// Parser and Rust-codegen for the seL4 `.bf` DSL.
//
// We support exactly the constructs that appear in
// codegen/structures_64.bf:
//
//   - line comments starting with `--`
//   - `#ifdef IDENT` / `#else` / `#endif` (substitution against a fixed
//     config map)
//   - `block <name>[(<vis-list>)] { <fields> }`
//   - `tagged_union <name> <tagname> { tag <block> <value> ... }`
//   - inside a block:
//         field <name> <expr>
//         field_high <name> <expr>
//         field_ptr <name> <expr>
//         field_ptr(<expr>) <name> <expr>
//         padding <expr>
//   - integer expressions over `word_size`, `canonical_size`, integer
//     literals, with `+`, `-`, `*`.
//
// The output is a small in-memory model (`Module` / `BlockDecl` /
// `FieldDecl`) plus a `render()` that emits Rust source.
//
// Layout convention (matches `bitfield_gen.py`'s `Block.checks()`):
// fields are declared from the HIGH bit position toward the LOW bit
// position. The first declared field occupies the most-significant
// bits of the block; each subsequent field packs downward. The total
// size must be a multiple of `word_size` and no field may straddle a
// word boundary.

use std::collections::HashMap;
use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// Configuration knobs evaluated by the preprocessor and the expression
// evaluator. These match a non-MCS, non-SMP, non-debug pc99 build.
// ---------------------------------------------------------------------------

pub const WORD_SIZE: u64 = 64;
pub const CANONICAL_SIZE: u64 = 48;

pub fn default_config() -> HashMap<String, bool> {
    [
        ("CONFIG_KERNEL_MCS", false),
        ("ENABLE_SMP_SUPPORT", false),
        ("CONFIG_HARDWARE_DEBUG_API", false),
        ("CONFIG_SET_TLS_BASE_SELF", false),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

// ---------------------------------------------------------------------------
// Pass 1 — preprocessor.
// ---------------------------------------------------------------------------

pub fn preprocess(src: &str, cfg: &HashMap<String, bool>) -> String {
    let mut out = String::with_capacity(src.len());
    // Stack of "currently emitting?" booleans; the conditional is the
    // AND of every entry on the stack.
    let mut emit_stack: Vec<bool> = vec![true];
    // Independent stack of original conditions, so `#else` flips
    // correctly even when nested inside a disabled branch.
    let mut cond_stack: Vec<bool> = vec![true];

    for raw_line in src.lines() {
        let line_no_comment = match raw_line.find("--") {
            Some(idx) => &raw_line[..idx],
            None => raw_line,
        };
        let trimmed = line_no_comment.trim();

        if let Some(rest) = trimmed.strip_prefix("#ifdef") {
            let ident = rest.trim();
            let cond = *cfg.get(ident).unwrap_or(&false);
            cond_stack.push(cond);
            let parent_emit = *emit_stack.last().unwrap();
            emit_stack.push(parent_emit && cond);
            continue;
        }
        if trimmed == "#else" {
            let cond = cond_stack.last().copied().unwrap_or(true);
            emit_stack.pop();
            let parent_emit = *emit_stack.last().unwrap();
            emit_stack.push(parent_emit && !cond);
            continue;
        }
        if trimmed == "#endif" {
            emit_stack.pop();
            cond_stack.pop();
            continue;
        }

        if *emit_stack.last().unwrap() {
            out.push_str(line_no_comment);
            out.push('\n');
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Pass 2 — tokenizer.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tok {
    Ident(String),
    Number(u64),
    LBrace,
    RBrace,
    LParen,
    RParen,
    Comma,
    Plus,
    Minus,
    Star,
}

pub fn tokenize(src: &str) -> Result<Vec<Tok>, String> {
    let bytes = src.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '{' => { out.push(Tok::LBrace); i += 1; }
            '}' => { out.push(Tok::RBrace); i += 1; }
            '(' => { out.push(Tok::LParen); i += 1; }
            ')' => { out.push(Tok::RParen); i += 1; }
            ',' => { out.push(Tok::Comma); i += 1; }
            '+' => { out.push(Tok::Plus); i += 1; }
            '-' => { out.push(Tok::Minus); i += 1; }
            '*' => { out.push(Tok::Star); i += 1; }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < bytes.len() && (bytes[i] as char).is_ascii_digit() {
                    i += 1;
                }
                let n: u64 = src[start..i]
                    .parse()
                    .map_err(|e| format!("bad number {:?}: {}", &src[start..i], e))?;
                out.push(Tok::Number(n));
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                while i < bytes.len() {
                    let ch = bytes[i] as char;
                    if ch.is_ascii_alphanumeric() || ch == '_' {
                        i += 1;
                    } else {
                        break;
                    }
                }
                out.push(Tok::Ident(src[start..i].to_string()));
            }
            _ => return Err(format!("unexpected character {:?} at byte {}", c, i)),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Pass 3 — AST and recursive-descent parser.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum Expr {
    Lit(u64),
    Symbol(String),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
}

#[derive(Clone, Debug)]
pub enum FieldKind {
    /// Plain field — zero-extend on read.
    Plain,
    /// Pointer-shaped — sign-extend bit `(size + shift - 1)` on read.
    High,
}

#[derive(Clone, Debug)]
pub struct FieldDecl {
    /// `None` for `padding`.
    pub name: Option<String>,
    pub size: Expr,
    pub kind: FieldKind,
    /// Left-shift on read (right-shift on write). For `field_ptr(N)
    /// foo M` this is `N`; otherwise zero. Used to recover the low
    /// bits of an aligned pointer.
    pub shift: Expr,
}

#[derive(Clone, Debug)]
pub struct BlockDecl {
    pub name: String,
    /// Optional explicit constructor parameter list (`block foo(a, b)
    /// { ... }`). When `Some`, `new(...)` takes those args, in that
    /// order, and skips fields not in the list.
    pub explicit_params: Option<Vec<String>>,
    pub fields: Vec<FieldDecl>,
}

#[derive(Clone, Debug)]
pub struct TaggedTag {
    pub block: String,
    pub value: u64,
}

#[derive(Clone, Debug)]
pub struct TaggedUnionDecl {
    pub name: String,
    pub tagname: String,
    pub tags: Vec<TaggedTag>,
}

#[derive(Clone, Debug, Default)]
pub struct Module {
    pub blocks: Vec<BlockDecl>,
    pub tagged_unions: Vec<TaggedUnionDecl>,
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn new(toks: Vec<Tok>) -> Self { Self { toks, pos: 0 } }
    fn peek(&self) -> Option<&Tok> { self.toks.get(self.pos) }
    fn bump(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() { self.pos += 1; }
        t
    }
    fn expect(&mut self, want: &Tok) -> Result<(), String> {
        match self.bump() {
            Some(ref t) if t == want => Ok(()),
            other => Err(format!("expected {:?}, got {:?}", want, other)),
        }
    }
    fn expect_ident(&mut self) -> Result<String, String> {
        match self.bump() {
            Some(Tok::Ident(s)) => Ok(s),
            other => Err(format!("expected identifier, got {:?}", other)),
        }
    }
    fn eat_keyword(&mut self, kw: &str) -> bool {
        if let Some(Tok::Ident(s)) = self.peek() {
            if s == kw { self.pos += 1; return true; }
        }
        false
    }

    // expr   = term ((+|-) term)*
    // term   = factor (* factor)*
    // factor = number | ident | '(' expr ')'
    fn parse_expr(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_term()?;
        loop {
            match self.peek() {
                Some(Tok::Plus) => {
                    self.bump();
                    let r = self.parse_term()?;
                    left = Expr::Add(Box::new(left), Box::new(r));
                }
                Some(Tok::Minus) => {
                    self.bump();
                    let r = self.parse_term()?;
                    left = Expr::Sub(Box::new(left), Box::new(r));
                }
                _ => break,
            }
        }
        Ok(left)
    }
    fn parse_term(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_factor()?;
        while let Some(Tok::Star) = self.peek() {
            self.bump();
            let r = self.parse_factor()?;
            left = Expr::Mul(Box::new(left), Box::new(r));
        }
        Ok(left)
    }
    fn parse_factor(&mut self) -> Result<Expr, String> {
        match self.bump() {
            Some(Tok::Number(n)) => Ok(Expr::Lit(n)),
            Some(Tok::Ident(s)) => Ok(Expr::Symbol(s)),
            Some(Tok::LParen) => {
                let e = self.parse_expr()?;
                self.expect(&Tok::RParen)?;
                Ok(e)
            }
            other => Err(format!("expected expression atom, got {:?}", other)),
        }
    }

    fn parse_module(&mut self) -> Result<Module, String> {
        let mut module = Module::default();
        while self.peek().is_some() {
            if self.eat_keyword("block") {
                module.blocks.push(self.parse_block()?);
            } else if self.eat_keyword("tagged_union") {
                module.tagged_unions.push(self.parse_tagged_union()?);
            } else {
                return Err(format!("unexpected top-level token {:?}", self.peek()));
            }
        }
        Ok(module)
    }

    fn parse_block(&mut self) -> Result<BlockDecl, String> {
        let name = self.expect_ident()?;
        let explicit_params = if matches!(self.peek(), Some(Tok::LParen)) {
            self.bump();
            let mut ps = Vec::new();
            if !matches!(self.peek(), Some(Tok::RParen)) {
                loop {
                    ps.push(self.expect_ident()?);
                    if matches!(self.peek(), Some(Tok::Comma)) {
                        self.bump();
                    } else {
                        break;
                    }
                }
            }
            self.expect(&Tok::RParen)?;
            Some(ps)
        } else {
            None
        };

        self.expect(&Tok::LBrace)?;
        let mut fields = Vec::new();
        while !matches!(self.peek(), Some(Tok::RBrace)) {
            fields.extend(self.parse_field_decls()?);
        }
        self.expect(&Tok::RBrace)?;
        Ok(BlockDecl { name, explicit_params, fields })
    }

    /// Returns one or two field declarations (`field_ptr` expands into
    /// padding + actual storage).
    fn parse_field_decls(&mut self) -> Result<Vec<FieldDecl>, String> {
        let head = self.expect_ident()?;
        match head.as_str() {
            "padding" => {
                let size = self.parse_expr()?;
                Ok(vec![FieldDecl {
                    name: None,
                    size,
                    kind: FieldKind::Plain,
                    shift: Expr::Lit(0),
                }])
            }
            "field" => {
                let name = self.expect_ident()?;
                let size = self.parse_expr()?;
                Ok(vec![FieldDecl {
                    name: Some(name),
                    size,
                    kind: FieldKind::Plain,
                    shift: Expr::Lit(0),
                }])
            }
            "field_high" => {
                let name = self.expect_ident()?;
                let size = self.parse_expr()?;
                Ok(vec![FieldDecl {
                    name: Some(name),
                    size,
                    kind: FieldKind::High,
                    shift: Expr::Lit(0),
                }])
            }
            "field_ptr" => {
                let align = if matches!(self.peek(), Some(Tok::LParen)) {
                    self.bump();
                    let e = self.parse_expr()?;
                    self.expect(&Tok::RParen)?;
                    e
                } else {
                    Expr::Lit(0)
                };
                let name = self.expect_ident()?;
                let total = self.parse_expr()?;
                // pad := (total - canonical_size) + align
                let pad_size = Expr::Add(
                    Box::new(Expr::Sub(
                        Box::new(total),
                        Box::new(Expr::Symbol("canonical_size".into())),
                    )),
                    Box::new(align.clone()),
                );
                // field := canonical_size - align
                let field_size = Expr::Sub(
                    Box::new(Expr::Symbol("canonical_size".into())),
                    Box::new(align.clone()),
                );
                Ok(vec![
                    FieldDecl {
                        name: None,
                        size: pad_size,
                        kind: FieldKind::Plain,
                        shift: Expr::Lit(0),
                    },
                    FieldDecl {
                        name: Some(name),
                        size: field_size,
                        kind: FieldKind::High,
                        shift: align,
                    },
                ])
            }
            other => Err(format!("unknown field head {:?}", other)),
        }
    }

    fn parse_tagged_union(&mut self) -> Result<TaggedUnionDecl, String> {
        let name = self.expect_ident()?;
        let tagname = self.expect_ident()?;
        self.expect(&Tok::LBrace)?;
        let mut tags = Vec::new();
        while !matches!(self.peek(), Some(Tok::RBrace)) {
            if !self.eat_keyword("tag") {
                return Err(format!("expected `tag`, got {:?}", self.peek()));
            }
            let block = self.expect_ident()?;
            let value = match self.bump() {
                Some(Tok::Number(n)) => n,
                other => return Err(format!("expected tag number, got {:?}", other)),
            };
            tags.push(TaggedTag { block, value });
        }
        self.expect(&Tok::RBrace)?;
        Ok(TaggedUnionDecl { name, tagname, tags })
    }
}

pub fn parse(src: &str) -> Result<Module, String> {
    let toks = tokenize(src)?;
    Parser::new(toks).parse_module()
}

// ---------------------------------------------------------------------------
// Pass 4 — lowering. Evaluate all `Expr`s and assign bit offsets per
// the high-to-low convention. Also runs the same well-formedness
// checks as bitfield_gen.py: positive sizes for fields, total a
// multiple of word_size, no field straddles a word boundary.
// ---------------------------------------------------------------------------

pub fn eval_expr(e: &Expr, syms: &HashMap<&'static str, u64>) -> Result<i64, String> {
    fn go(e: &Expr, syms: &HashMap<&'static str, u64>) -> Result<i64, String> {
        Ok(match e {
            Expr::Lit(n) => *n as i64,
            Expr::Symbol(s) => *syms
                .get(s.as_str())
                .ok_or_else(|| format!("unknown symbol `{}`", s))? as i64,
            Expr::Add(a, b) => go(a, syms)? + go(b, syms)?,
            Expr::Sub(a, b) => go(a, syms)? - go(b, syms)?,
            Expr::Mul(a, b) => go(a, syms)? * go(b, syms)?,
        })
    }
    go(e, syms)
}

#[derive(Clone, Debug)]
pub struct LoweredField {
    pub name: Option<String>,
    pub size: u64,
    /// Bit offset within the block (0 = LSB of word 0).
    pub offset: u64,
    pub sign_extend: bool,
    pub shift: u64,
}

#[derive(Clone, Debug)]
pub struct LoweredBlock {
    pub name: String,
    pub explicit_params: Option<Vec<String>>,
    pub size: u64,
    pub fields: Vec<LoweredField>,
}

pub fn lower(module: &Module) -> Result<Vec<LoweredBlock>, String> {
    let syms: HashMap<&'static str, u64> = [
        ("word_size", WORD_SIZE),
        ("canonical_size", CANONICAL_SIZE),
    ]
    .into_iter()
    .collect();

    let mut out = Vec::new();
    for b in &module.blocks {
        let mut sized: Vec<(Option<String>, i64, bool, i64)> = Vec::new();
        let mut total: i64 = 0;
        for f in &b.fields {
            let size = eval_expr(&f.size, &syms)
                .map_err(|e| format!("block {}: field size: {}", b.name, e))?;
            let shift = eval_expr(&f.shift, &syms)
                .map_err(|e| format!("block {}: field shift: {}", b.name, e))?;
            if let Some(n) = &f.name {
                if size <= 0 {
                    return Err(format!("block {}: field {} has size {}", b.name, n, size));
                }
            } else if size < 0 {
                return Err(format!("block {}: padding has negative size {}", b.name, size));
            }
            let sign_extend = matches!(f.kind, FieldKind::High);
            sized.push((f.name.clone(), size, sign_extend, shift));
            total += size;
        }
        if total <= 0 || total % WORD_SIZE as i64 != 0 {
            return Err(format!(
                "block {}: total size {} not a positive multiple of word_size",
                b.name, total
            ));
        }

        // Assign offsets HIGH-to-LOW in declaration order.
        let mut offset = total;
        let mut fields_lowered = Vec::with_capacity(sized.len());
        for (name, size, sign_extend, shift) in sized {
            offset -= size;
            if size > 0 {
                let lo_word = offset / WORD_SIZE as i64;
                let hi_word = (offset + size - 1) / WORD_SIZE as i64;
                if lo_word != hi_word {
                    return Err(format!(
                        "block {}: field {:?} (size {}, offset {}) straddles a word boundary",
                        b.name, name, size, offset
                    ));
                }
            }
            fields_lowered.push(LoweredField {
                name,
                size: size as u64,
                offset: offset as u64,
                sign_extend,
                shift: shift as u64,
            });
        }

        out.push(LoweredBlock {
            name: b.name.clone(),
            explicit_params: b.explicit_params.clone(),
            size: total as u64,
            fields: fields_lowered,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Pass 5 — emit Rust.
// ---------------------------------------------------------------------------

pub fn render(blocks: &[LoweredBlock]) -> String {
    // We do *not* emit inner attributes here — the file is intended
    // to be `include!()`d into a module, and `#![...]` is illegal
    // inside an `include!`. The wrapper module in src/structures.rs
    // applies the necessary lint allows.
    let mut s = String::new();
    s.push_str(
        "// AUTO-GENERATED by build.rs from codegen/structures_64.bf.\n\
         // DO NOT EDIT BY HAND.\n\n",
    );
    for b in blocks {
        render_block(&mut s, b);
    }
    s
}

fn render_block(s: &mut String, b: &LoweredBlock) {
    let words = b.size / WORD_SIZE;
    let struct_name = type_name(&b.name);
    writeln!(s, "/// `{}` — {} bits ({} words)", b.name, b.size, words).unwrap();
    writeln!(s, "#[repr(C)]").unwrap();
    writeln!(s, "#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]").unwrap();
    writeln!(s, "pub struct {} {{", struct_name).unwrap();
    writeln!(s, "    pub words: [u64; {}],", words).unwrap();
    writeln!(s, "}}\n").unwrap();

    writeln!(s, "impl {} {{", struct_name).unwrap();
    writeln!(s, "    pub const SIZE_BITS: usize = {};", b.size).unwrap();
    writeln!(s, "    pub const SIZE_BYTES: usize = {};", b.size / 8).unwrap();
    writeln!(s, "    pub const WORDS: usize = {};", words).unwrap();
    writeln!(
        s,
        "    pub const fn zeroed() -> Self {{ Self {{ words: [0; {}] }} }}",
        words
    )
    .unwrap();

    for f in &b.fields {
        let Some(name) = &f.name else { continue };
        emit_getter(s, f, name);
        emit_setter(s, f, name);
    }

    // Constructor.
    let visible: Vec<&LoweredField> =
        b.fields.iter().filter(|f| f.name.is_some()).collect();
    let arg_names: Vec<String> = if let Some(ep) = &b.explicit_params {
        ep.clone()
    } else {
        visible.iter().map(|f| f.name.clone().unwrap()).collect()
    };

    write!(s, "    pub const fn new(").unwrap();
    let mut first = true;
    for arg in &arg_names {
        if !first {
            s.push_str(", ");
        }
        first = false;
        write!(s, "{}: u64", arg).unwrap();
    }
    s.push_str(") -> Self {\n");
    writeln!(s, "        let mut this = Self::zeroed();").unwrap();
    for arg in &arg_names {
        writeln!(s, "        this = this.with_{name}({name});", name = arg).unwrap();
    }
    writeln!(s, "        this").unwrap();
    writeln!(s, "    }}").unwrap();
    writeln!(s, "}}\n").unwrap();
}

fn emit_getter(s: &mut String, f: &LoweredField, name: &str) {
    let word = f.offset / WORD_SIZE;
    let bit_in_word = f.offset % WORD_SIZE;
    let mask: u64 = if f.size >= 64 {
        u64::MAX
    } else {
        (1u64 << f.size) - 1
    };
    writeln!(
        s,
        "    /// bit-range [{}..{}) (offset {}, size {}{}{})",
        f.offset,
        f.offset + f.size,
        f.offset,
        f.size,
        if f.sign_extend { ", sign-extend" } else { "" },
        if f.shift != 0 {
            format!(", shift +{}", f.shift)
        } else {
            String::new()
        },
    )
    .unwrap();
    writeln!(s, "    pub const fn {}(self) -> u64 {{", name).unwrap();
    writeln!(
        s,
        "        let raw = (self.words[{}] >> {}) & 0x{:x}u64;",
        word, bit_in_word, mask
    )
    .unwrap();
    if f.shift != 0 {
        writeln!(s, "        let raw = raw << {};", f.shift).unwrap();
    }
    if f.sign_extend && (f.size + f.shift) < 64 {
        let sign_bit = f.size + f.shift - 1;
        writeln!(
            s,
            "        if (raw & (1u64 << {sign_bit})) != 0 {{ raw | !((1u64 << {top}) - 1) }} else {{ raw }}",
            sign_bit = sign_bit,
            top = sign_bit + 1,
        )
        .unwrap();
    } else {
        writeln!(s, "        raw").unwrap();
    }
    writeln!(s, "    }}").unwrap();
}

fn emit_setter(s: &mut String, f: &LoweredField, name: &str) {
    let word = f.offset / WORD_SIZE;
    let bit_in_word = f.offset % WORD_SIZE;
    let mask: u64 = if f.size >= 64 {
        u64::MAX
    } else {
        (1u64 << f.size) - 1
    };
    writeln!(
        s,
        "    pub const fn with_{}(mut self, value: u64) -> Self {{",
        name
    )
    .unwrap();
    if f.shift != 0 {
        writeln!(s, "        let value = value >> {};", f.shift).unwrap();
    }
    writeln!(s, "        let value = value & 0x{:x}u64;", mask).unwrap();
    writeln!(
        s,
        "        self.words[{w}] = (self.words[{w}] & !(0x{m:x}u64 << {b})) | (value << {b});",
        w = word,
        m = mask,
        b = bit_in_word
    )
    .unwrap();
    writeln!(s, "        self").unwrap();
    writeln!(s, "    }}").unwrap();
}

fn type_name(bf_name: &str) -> String {
    // `endpoint_cap` -> `EndpointCap`; `endpoint` -> `Endpoint`;
    // already-PascalCase names like `NullFault` pass through.
    let mut out = String::new();
    for part in bf_name.split('_') {
        let mut cs = part.chars();
        if let Some(c) = cs.next() {
            out.push(c.to_ascii_uppercase());
            out.extend(cs);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Driver.
// ---------------------------------------------------------------------------

pub fn generate(src: &str) -> Result<String, String> {
    let cfg = default_config();
    let preprocessed = preprocess(src, &cfg);
    let module = parse(&preprocessed)?;
    let blocks = lower(&module)?;
    Ok(render(&blocks))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup<'a>(b: &'a LoweredBlock, name: &str) -> &'a LoweredField {
        b.fields
            .iter()
            .find(|f| f.name.as_deref() == Some(name))
            .expect("field present")
    }

    #[test]
    #[allow(non_snake_case)]
    fn endpoint_cap_layout_matches_seL4() {
        // Mirror the real endpoint_cap entry from structures_64.bf.
        let src = "block endpoint_cap(capEPBadge, capCanGrantReply, capCanGrant, \
                       capCanSend, capCanReceive, capEPPtr, capType) {\n\
                   field capEPBadge        64\n\
                   field capType           5\n\
                   field capCanGrantReply  1\n\
                   field capCanGrant       1\n\
                   field capCanReceive     1\n\
                   field capCanSend        1\n\
                   field_ptr capEPPtr      word_size - 5 - 4\n\
                   }\n";
        let m = parse(&preprocess(src, &default_config())).unwrap();
        let b = &lower(&m).unwrap()[0];
        assert_eq!(b.size, 128, "endpoint_cap is two words");

        // word 1: badge in low 64 bits.
        let badge = lookup(b, "capEPBadge");
        assert_eq!(badge.offset, 64);
        assert_eq!(badge.size, 64);

        // word 0 high tag.
        assert_eq!(lookup(b, "capType").offset, 59);
        assert_eq!(lookup(b, "capType").size, 5);
        assert_eq!(lookup(b, "capCanGrantReply").offset, 58);
        assert_eq!(lookup(b, "capCanGrant").offset, 57);
        assert_eq!(lookup(b, "capCanReceive").offset, 56);
        assert_eq!(lookup(b, "capCanSend").offset, 55);

        // capEPPtr expanded: pad(7)+canonical(48). Stored bits 0..47.
        let ptr = lookup(b, "capEPPtr");
        assert_eq!(ptr.offset, 0);
        assert_eq!(ptr.size, 48);
        assert!(ptr.sign_extend);
        assert_eq!(ptr.shift, 0);
    }

    #[test]
    fn cnode_cap_aligned_pointer() {
        // field_ptr(1) capCNodePtr 47 -> pad(0)+canonical-1=47, shift=1
        let src = "block cnode_cap {\n\
                   field capCNodeGuard       64\n\
                   field capType             5\n\
                   field capCNodeGuardSize   6\n\
                   field capCNodeRadix       6\n\
                   field_ptr(1) capCNodePtr  47\n\
                   }\n";
        let m = parse(&preprocess(src, &default_config())).unwrap();
        let b = &lower(&m).unwrap()[0];
        let p = lookup(b, "capCNodePtr");
        assert_eq!(p.size, 47);
        assert_eq!(p.shift, 1);
        assert!(p.sign_extend);
        // word 0 layout: ptr at [0..47), pad(0), radix at 47..53, ...
        assert_eq!(p.offset, 0);
        assert_eq!(lookup(b, "capCNodeRadix").offset, 47);
    }

    #[test]
    fn ifdef_kernel_mcs_picks_else_branch() {
        let src = "#ifdef CONFIG_KERNEL_MCS\n\
                   block reply_cap_mcs {\n\
                       field a 64\n\
                       field capType 5\n\
                       padding 59\n\
                   }\n\
                   #else\n\
                   block reply_cap_classic {\n\
                       field a 64\n\
                       field capType 5\n\
                       padding 59\n\
                   }\n\
                   #endif\n";
        let m = parse(&preprocess(src, &default_config())).unwrap();
        assert_eq!(m.blocks.len(), 1);
        assert_eq!(m.blocks[0].name, "reply_cap_classic");
    }

    #[test]
    fn rendered_block_has_expected_shape() {
        // We can't easily compile-and-run generated code from inside
        // these unit tests, so we settle for checking the source
        // contains the expected getter/setter signatures. End-to-end
        // is covered by the kernel build itself (build.rs runs
        // generate() on the real bf, then rustc compiles it).
        let src = "block tiny_widget {\n\
                   field foo 16\n\
                   padding 48\n\
                   field bar 8\n\
                   padding 56\n\
                   }\n";
        let rust = generate(src).unwrap();
        assert!(rust.contains("pub struct TinyWidget"));
        assert!(rust.contains("pub const fn foo(self) -> u64"));
        assert!(rust.contains("pub const fn with_foo("));
        assert!(rust.contains("pub const fn bar(self) -> u64"));
    }
}
