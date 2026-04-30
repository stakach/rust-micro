// Codegen for the XML-driven enums.
//
// Reads:
//   - codegen/syscall.xml           -> `pub enum Syscall`
//   - codegen/object-api.xml        -> common invocation labels
//   - codegen/object-api-sel4-arch.xml -> sel4-arch (x86_64-mode) labels
//   - codegen/object-api-arch.xml   -> arch (x86) labels
//
// Together the three invocation files make a single contiguous numeric
// range, in the order: 0=InvalidInvocation, then common, then
// sel4_arch, then arch. We produce one `pub enum InvocationLabel`
// covering the whole range so kernel dispatchers can `match` on it.
//
// We do NOT pull in an XML crate. Both files are well-structured
// enough that a tiny tag scanner is fine; we look for `<method>`,
// `</method>`, and `<condition>...</condition>` (possibly multi-line).
// The DSL inside `<condition>` is just `<config var="X"/>`,
// `<and>...</and>`, `<or>...</or>`, `<not>...</not>`.

use std::collections::HashMap;
use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// Configuration knobs the XML conditions are evaluated against.
// Anything not listed here defaults to false. Mirror the `cfg` used
// by the .bf preprocessor where the names overlap.
// ---------------------------------------------------------------------------

pub fn default_config() -> HashMap<&'static str, bool> {
    [
        ("CONFIG_KERNEL_MCS", false),
        ("CONFIG_ENABLE_SMP_SUPPORT", false),
        ("CONFIG_HARDWARE_DEBUG_API", false),
        ("CONFIG_VTX", false),
        ("CONFIG_IOMMU", false),
        ("CONFIG_ENABLE_BENCHMARKS", false),
        ("CONFIG_BENCHMARK_TRACK_UTILISATION", false),
        ("CONFIG_DEBUG_BUILD", false),
        ("CONFIG_DANGEROUS_CODE_INJECTION", false),
        ("CONFIG_KERNEL_X86_DANGEROUS_MSR", false),
        ("CONFIG_SET_TLS_BASE_SELF", false),
        ("CONFIG_ARCH_IA32", false),
        ("CONFIG_ARCH_X86_64", true),
        ("CONFIG_X86_64", true),
        // CONFIG_PRINTING is not a kernel-side feature gate — we keep
        // it on so the SysDebugPutChar entry exists in the syscall
        // enum. The kernel decides at runtime whether to honour it.
        ("CONFIG_PRINTING", true),
    ]
    .into_iter()
    .collect()
}

// ---------------------------------------------------------------------------
// Generic XML helpers — *not* a full parser. Enough for these files.
// ---------------------------------------------------------------------------

/// Find every `<method ...` open tag, paired with the substring up to
/// the matching `</method>`. Returns `(attrs_str, body)` per method.
pub fn iter_methods(xml: &str) -> impl Iterator<Item = (String, String)> + '_ {
    let mut idx = 0usize;
    std::iter::from_fn(move || loop {
        let rest = &xml[idx..];
        let open = rest.find("<method")?;
        let after_open = idx + open + "<method".len();
        // Find the closing `>` of the open tag, *not* inside a quoted
        // attribute. Methods like:
        //   <method id="X" name="Y">
        //   <method id="X" name="Y"/>           <- self-closing (rare)
        let mut end = after_open;
        let mut in_quote = false;
        let mut quote = b'"';
        let bytes = xml.as_bytes();
        let close = loop {
            if end >= bytes.len() {
                return None;
            }
            let c = bytes[end];
            if in_quote {
                if c == quote {
                    in_quote = false;
                }
            } else if c == b'"' || c == b'\'' {
                in_quote = true;
                quote = c;
            } else if c == b'>' {
                break end;
            }
            end += 1;
        };
        let attrs = xml[after_open..close].trim().trim_end_matches('/').to_string();
        let self_closing = bytes[close - 1] == b'/';
        idx = close + 1;
        let body = if self_closing {
            String::new()
        } else {
            let body_end = match xml[idx..].find("</method>") {
                Some(p) => idx + p,
                None => return None,
            };
            let b = xml[idx..body_end].to_string();
            idx = body_end + "</method>".len();
            b
        };
        return Some((attrs, body));
    })
}

/// Extract `attr_name="..."` from a tag's attribute string.
pub fn attr<'a>(attrs: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("{name}=\"");
    let start = attrs.find(&key)? + key.len();
    let end = attrs[start..].find('"')? + start;
    Some(&attrs[start..end])
}

/// Extract the contents of `<condition>...</condition>` from a method
/// body. Returns `None` if no condition is declared (i.e. always-true).
fn extract_condition(body: &str) -> Option<&str> {
    let s = body.find("<condition>")? + "<condition>".len();
    let e = body[s..].find("</condition>")? + s;
    Some(&body[s..e])
}

// ---------------------------------------------------------------------------
// Condition evaluator. Walks the tag stream of an XML fragment.
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum CondTok<'a> {
    Open(&'a str, &'a str),  // tag name, attrs (without `<`/`>`)
    Close(&'a str),
    SelfClose(&'a str, &'a str),
}

fn cond_tokens(s: &str) -> Vec<CondTok<'_>> {
    let mut out = Vec::new();
    let mut i = 0;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        // skip whitespace and text content
        while i < bytes.len() && bytes[i] != b'<' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        // bytes[i] == '<'
        let start = i + 1;
        let end = match s[start..].find('>') {
            Some(p) => start + p,
            None => break,
        };
        let inner = &s[start..end];
        if let Some(stripped) = inner.strip_prefix('/') {
            out.push(CondTok::Close(stripped.trim()));
        } else if inner.ends_with('/') {
            let body = &inner[..inner.len() - 1];
            let (name, attrs) = split_tag(body);
            out.push(CondTok::SelfClose(name, attrs));
        } else {
            let (name, attrs) = split_tag(inner);
            out.push(CondTok::Open(name, attrs));
        }
        i = end + 1;
    }
    out
}

fn split_tag(inner: &str) -> (&str, &str) {
    let inner = inner.trim();
    match inner.find(char::is_whitespace) {
        Some(p) => (&inner[..p], inner[p..].trim()),
        None => (inner, ""),
    }
}

fn eval_cond(s: &str, cfg: &HashMap<&'static str, bool>) -> Result<bool, String> {
    let toks = cond_tokens(s);
    let mut pos = 0;
    let v = eval_one(&toks, &mut pos, cfg)?;
    Ok(v)
}

fn eval_one(
    toks: &[CondTok<'_>],
    pos: &mut usize,
    cfg: &HashMap<&'static str, bool>,
) -> Result<bool, String> {
    if *pos >= toks.len() {
        return Err("condition: unexpected end".into());
    }
    match &toks[*pos] {
        CondTok::SelfClose("config", attrs) => {
            *pos += 1;
            let var = attr(attrs, "var")
                .ok_or_else(|| format!("condition: <config> missing var: {attrs}"))?;
            Ok(*cfg.get(var).unwrap_or(&false))
        }
        CondTok::Open("not", _) => {
            *pos += 1;
            let v = eval_one(toks, pos, cfg)?;
            expect_close(toks, pos, "not")?;
            Ok(!v)
        }
        CondTok::Open("and", _) => {
            *pos += 1;
            let mut v = true;
            while !matches!(toks.get(*pos), Some(CondTok::Close("and"))) {
                v &= eval_one(toks, pos, cfg)?;
            }
            expect_close(toks, pos, "and")?;
            Ok(v)
        }
        CondTok::Open("or", _) => {
            *pos += 1;
            let mut v = false;
            while !matches!(toks.get(*pos), Some(CondTok::Close("or"))) {
                v |= eval_one(toks, pos, cfg)?;
            }
            expect_close(toks, pos, "or")?;
            Ok(v)
        }
        other => Err(format!("condition: unexpected token {:?}", other)),
    }
}

fn expect_close(toks: &[CondTok<'_>], pos: &mut usize, name: &str) -> Result<(), String> {
    match toks.get(*pos) {
        Some(CondTok::Close(n)) if *n == name => {
            *pos += 1;
            Ok(())
        }
        other => Err(format!("expected </{name}>, got {:?}", other)),
    }
}

// ---------------------------------------------------------------------------
// Syscall codegen.
//
// Numbers descend from -1: first listed is -1, second is -2, ... The
// generator filters by the active <api-master|api-mcs> tag (we use
// api-master) and applies <condition> gates on debug syscalls.
// ---------------------------------------------------------------------------

pub fn render_syscalls(xml: &str, cfg: &HashMap<&'static str, bool>) -> Result<String, String> {
    // Slurp the api-master block.
    let api_block = pick_block(xml, "api-master")
        .ok_or_else(|| "syscall.xml: <api-master> missing".to_string())?;
    let api_syscalls: Vec<(String, Option<String>)> = parse_syscall_configs(api_block)?;

    let debug_block = pick_block(xml, "debug").unwrap_or("");
    let debug_syscalls: Vec<(String, Option<String>)> = parse_syscall_configs(debug_block)?;

    let mut s = String::new();
    s.push_str(
        "// AUTO-GENERATED by build.rs from codegen/syscall.xml.\n\
         // DO NOT EDIT BY HAND.\n\n\
         /// seL4 syscall numbers. Encoded as i32 because they are\n\
         /// negative on the wire (architecture trap entry decodes\n\
         /// the signed register value).\n\
         #[repr(i32)]\n\
         #[derive(Copy, Clone, Eq, PartialEq, Debug)]\n\
         pub enum Syscall {\n",
    );
    let mut next: i32 = -1;
    let mut all: Vec<(String, i32)> = Vec::new();
    for (name, cond) in api_syscalls.iter().chain(debug_syscalls.iter()) {
        // Always allocate a number — seL4 numbers them whether or not
        // the condition is satisfied — so cross-config compatibility
        // holds.
        let n = next;
        next -= 1;
        let included = match cond {
            Some(c) => eval_cond(c, cfg)?,
            None => true,
        };
        if included {
            writeln!(s, "    Sys{name} = {n},").unwrap();
            all.push((name.clone(), n));
        }
    }
    s.push_str("}\n\n");

    // Helpful constants the kernel and tests both want.
    let api_count = api_syscalls.len() as i32;
    writeln!(s, "/// Lowest (most negative) API syscall number.").unwrap();
    writeln!(s, "pub const SYSCALL_API_MIN: i32 = {};", -api_count).unwrap();
    writeln!(s, "/// Highest API syscall number (always -1).").unwrap();
    writeln!(s, "pub const SYSCALL_API_MAX: i32 = -1;").unwrap();
    writeln!(s).unwrap();

    // Emit a from_i32 mapper.
    s.push_str("impl Syscall {\n");
    s.push_str("    /// Decode a syscall number coming in from a trap.\n");
    s.push_str("    pub const fn from_i32(n: i32) -> Option<Self> {\n");
    s.push_str("        match n {\n");
    for (name, n) in &all {
        writeln!(s, "            {n} => Some(Syscall::Sys{name}),").unwrap();
    }
    s.push_str("            _ => None,\n");
    s.push_str("        }\n");
    s.push_str("    }\n");
    s.push_str("}\n");

    Ok(s)
}

/// Find the contents of a top-level `<tag-name>...</tag-name>` block.
fn pick_block<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let s = xml.find(&open)? + open.len();
    let e = xml[s..].find(&close)? + s;
    Some(&xml[s..e])
}

/// Parse a sequence of `<config>...<syscall name="X"/></config>` blocks.
fn parse_syscall_configs(xml: &str) -> Result<Vec<(String, Option<String>)>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(start) = xml[i..].find("<config>") {
        let s = i + start + "<config>".len();
        let e = xml[s..]
            .find("</config>")
            .ok_or_else(|| "syscall xml: unterminated <config>".to_string())?
            + s;
        let block = &xml[s..e];
        let condition = extract_condition_inline(block);
        for cap in find_self_closing(block, "syscall") {
            let name = attr(cap, "name")
                .ok_or_else(|| format!("syscall: missing name in {cap}"))?;
            out.push((name.to_string(), condition.clone()));
        }
        i = e + "</config>".len();
    }
    Ok(out)
}

fn extract_condition_inline(s: &str) -> Option<String> {
    let s_idx = s.find("<condition>")? + "<condition>".len();
    let e_idx = s[s_idx..].find("</condition>")? + s_idx;
    Some(s[s_idx..e_idx].to_string())
}

/// Find every `<tag .../>` self-closing tag. Returns the attribute
/// substring per match.
fn find_self_closing<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let pat = format!("<{tag}");
    let mut i = 0;
    while let Some(p) = xml[i..].find(&pat) {
        let start = i + p + pat.len();
        let end = match xml[start..].find('>') {
            Some(e) => start + e,
            None => break,
        };
        let inner = xml[start..end].trim();
        // Only count self-closing forms.
        if inner.ends_with('/') {
            let attrs = inner[..inner.len() - 1].trim();
            out.push(attrs);
        }
        i = end + 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Invocation-label codegen.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct InvocLabel {
    pub id: String,
    pub included: bool,
}

pub fn parse_methods(xml: &str, cfg: &HashMap<&'static str, bool>) -> Result<Vec<InvocLabel>, String> {
    let mut out = Vec::new();
    for (attrs, body) in iter_methods(xml) {
        let id = attr(&attrs, "id")
            .ok_or_else(|| format!("<method> missing id: {attrs}"))?
            .to_string();
        let included = match extract_condition(&body) {
            Some(c) => eval_cond(c, cfg)?,
            None => true,
        };
        out.push(InvocLabel { id, included });
    }
    Ok(out)
}

pub fn render_invocations(
    common_xml: &str,
    sel4_arch_xml: &str,
    arch_xml: &str,
    cfg: &HashMap<&'static str, bool>,
) -> Result<String, String> {
    let common = parse_methods(common_xml, cfg)?;
    let sel4_arch = parse_methods(sel4_arch_xml, cfg)?;
    let arch = parse_methods(arch_xml, cfg)?;

    let mut s = String::new();
    s.push_str(
        "// AUTO-GENERATED by build.rs from codegen/object-api*.xml.\n\
         // DO NOT EDIT BY HAND.\n\n\
         /// Object-invocation labels, in seL4's contiguous numeric range.\n\
         /// Order: InvalidInvocation, then common, then sel4_arch (x86_64),\n\
         /// then arch (x86).\n\
         #[repr(u32)]\n\
         #[derive(Copy, Clone, Eq, PartialEq, Debug)]\n\
         pub enum InvocationLabel {\n\
         \x20   InvalidInvocation = 0,\n",
    );

    let mut next: u32 = 1;
    let mut all = Vec::new();
    for inv in common.iter().chain(sel4_arch.iter()).chain(arch.iter()) {
        // Match seL4's behaviour: skipped methods do NOT consume a
        // number (Jinja `{%- if condition %}` only emits when included
        // for our cfg, and the C enum auto-numbers from there). We
        // therefore only allocate when `included`.
        if inv.included {
            writeln!(s, "    {} = {},", inv.id, next).unwrap();
            all.push((inv.id.clone(), next));
            next += 1;
        }
    }
    writeln!(s, "    nInvocationLabels = {},", next).unwrap();
    s.push_str("}\n\n");

    s.push_str("impl InvocationLabel {\n");
    s.push_str("    pub const fn from_u64(n: u64) -> Option<Self> {\n");
    s.push_str("        match n {\n");
    s.push_str("            0 => Some(InvocationLabel::InvalidInvocation),\n");
    for (id, n) in &all {
        writeln!(s, "            {n} => Some(InvocationLabel::{id}),").unwrap();
    }
    s.push_str("            _ => None,\n");
    s.push_str("        }\n");
    s.push_str("    }\n");
    s.push_str("}\n");
    Ok(s)
}

// ---------------------------------------------------------------------------
// Driver: glue the two enums into a single OUT_DIR file.
// ---------------------------------------------------------------------------

pub fn generate_syscalls(syscall_xml: &str) -> Result<String, String> {
    render_syscalls(syscall_xml, &default_config())
}

pub fn generate_invocations(
    common_xml: &str,
    sel4_arch_xml: &str,
    arch_xml: &str,
) -> Result<String, String> {
    render_invocations(common_xml, sel4_arch_xml, arch_xml, &default_config())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_numbering() {
        // Minimal fixture: just two API syscalls and one debug,
        // without the wrapping XML doctype.
        let xml = "<syscalls>\
                   <api-master><config>\
                   <syscall name=\"Call\"/>\
                   <syscall name=\"Send\"/>\
                   </config></api-master>\
                   <debug>\
                   <config>\
                   <condition><config var=\"CONFIG_PRINTING\"/></condition>\
                   <syscall name=\"DebugPutChar\"/>\
                   </config>\
                   </debug>\
                   </syscalls>";
        let mut cfg = default_config();
        cfg.insert("CONFIG_PRINTING", true);
        let rust = render_syscalls(xml, &cfg).unwrap();
        assert!(rust.contains("SysCall = -1,"));
        assert!(rust.contains("SysSend = -2,"));
        assert!(rust.contains("SysDebugPutChar = -3,"));
    }

    #[test]
    fn condition_evaluator() {
        let mut cfg = HashMap::new();
        cfg.insert("A", true);
        cfg.insert("B", false);
        assert!(eval_cond("<config var=\"A\"/>", &cfg).unwrap());
        assert!(!eval_cond("<config var=\"B\"/>", &cfg).unwrap());
        assert!(eval_cond("<not><config var=\"B\"/></not>", &cfg).unwrap());
        assert!(eval_cond(
            "<and><config var=\"A\"/><not><config var=\"B\"/></not></and>",
            &cfg
        )
        .unwrap());
        assert!(eval_cond(
            "<or><config var=\"B\"/><config var=\"A\"/></or>",
            &cfg
        )
        .unwrap());
    }

    #[test]
    fn methods_are_extracted() {
        let xml = "<api>\
                   <interface name=\"X\">\
                   <method id=\"Foo\" name=\"foo\"></method>\
                   <method id=\"Bar\" name=\"bar\">\
                   <condition><config var=\"OFF\"/></condition>\
                   </method>\
                   </interface>\
                   </api>";
        let cfg = default_config();
        let ms = parse_methods(xml, &cfg).unwrap();
        assert_eq!(ms.len(), 2);
        assert_eq!(ms[0].id, "Foo");
        assert!(ms[0].included);
        assert_eq!(ms[1].id, "Bar");
        assert!(!ms[1].included);
    }
}
