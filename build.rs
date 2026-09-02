// Build script — emits Rust source from the seL4 codegen inputs
// pinned in codegen/. The kernel does not link any seL4 C code; we
// only consume the .bf and .xml files as the source of truth for the
// user-visible ABI.
//
// Outputs (under $OUT_DIR):
//   * structures.rs   — capability and kernel-object bitfield types
//                       (from codegen/structures_64.bf)
//   * syscalls.rs     — Syscall enum (from codegen/syscall.xml)
//   * invocations.rs  — InvocationLabel enum (from object-api*.xml)

#[path = "build_support/bf.rs"]
mod bf;

#[path = "build_support/xml.rs"]
mod xml;

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let codegen_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("codegen");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH not set");
    assert!(
        matches!(target_arch.as_str(), "x86_64" | "aarch64"),
        "unsupported codegen target architecture: {target_arch}"
    );

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support/bf.rs");
    println!("cargo:rerun-if-changed=build_support/xml.rs");
    for entry in fs::read_dir(&codegen_dir).expect("codegen/ missing") {
        let path = entry.expect("readdir failed").path();
        if matches!(
            path.file_name().and_then(|n| n.to_str()),
            Some("README.md") | Some("refresh.sh")
        ) {
            continue;
        }
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let read = |name: &str| -> String {
        fs::read_to_string(codegen_dir.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
    };

    // .bf -> structures.rs
    let bf_src = read("structures_64.bf");
    let rust = bf::generate(&bf_src).unwrap_or_else(|e| panic!("bf codegen: {e}"));
    fs::write(out_dir.join("structures.rs"), rust).expect("write structures.rs");

    // Architecture .bf -> structures_arch.rs. These are exact snapshots from
    // the pinned seL4 architecture directories; never use x86 definitions as
    // an AArch64 compatibility fallback.
    let bf_arch_name = match target_arch.as_str() {
        "x86_64" => "structures_x86_64.bf",
        "aarch64" => "structures_aarch64.bf",
        _ => unreachable!(),
    };
    let bf_arch = read(bf_arch_name);
    let rust = bf::generate_for_arch(&bf_arch, &target_arch)
        .unwrap_or_else(|e| panic!("arch bf codegen ({target_arch}): {e}"));
    fs::write(out_dir.join("structures_arch.rs"), rust).expect("write structures_arch.rs");

    // syscall.xml -> syscalls.rs
    let syscall_xml = read("syscall.xml");
    let rust =
        xml::generate_syscalls(&syscall_xml).unwrap_or_else(|e| panic!("syscall codegen: {e}"));
    fs::write(out_dir.join("syscalls.rs"), rust).expect("write syscalls.rs");

    // object-api*.xml -> invocations.rs
    let common = read("object-api.xml");
    let (sel4_arch_name, arch_name) = match target_arch.as_str() {
        "x86_64" => ("object-api-sel4-arch.xml", "object-api-arch.xml"),
        "aarch64" => ("object-api-aarch64.xml", "object-api-arm.xml"),
        _ => unreachable!(),
    };
    let sel4_arch = read(sel4_arch_name);
    let arch = read(arch_name);
    let extension = read("object-api-rust-micro.xml");
    let arch_and_extension = format!("{arch}\n{extension}");
    let rust = xml::generate_invocations(&common, &sel4_arch, &arch_and_extension)
        .unwrap_or_else(|e| panic!("invocation codegen: {e}"));
    fs::write(out_dir.join("invocations.rs"), rust).expect("write invocations.rs");
}
