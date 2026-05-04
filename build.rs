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
        fs::read_to_string(codegen_dir.join(name))
            .unwrap_or_else(|e| panic!("read {name}: {e}"))
    };

    // .bf -> structures.rs
    let bf_src = read("structures_64.bf");
    let rust = bf::generate(&bf_src).unwrap_or_else(|e| panic!("bf codegen: {e}"));
    fs::write(out_dir.join("structures.rs"), rust).expect("write structures.rs");

    // arch x86_64 .bf -> structures_arch.rs
    let bf_arch = read("structures_x86_64.bf");
    let rust = bf::generate(&bf_arch)
        .unwrap_or_else(|e| panic!("arch bf codegen: {e}"));
    fs::write(out_dir.join("structures_arch.rs"), rust).expect("write structures_arch.rs");

    // syscall.xml -> syscalls.rs
    let syscall_xml = read("syscall.xml");
    let rust = xml::generate_syscalls(&syscall_xml)
        .unwrap_or_else(|e| panic!("syscall codegen: {e}"));
    fs::write(out_dir.join("syscalls.rs"), rust).expect("write syscalls.rs");

    // object-api*.xml -> invocations.rs
    let common = read("object-api.xml");
    let sel4_arch = read("object-api-sel4-arch.xml");
    let arch = read("object-api-arch.xml");
    let rust = xml::generate_invocations(&common, &sel4_arch, &arch)
        .unwrap_or_else(|e| panic!("invocation codegen: {e}"));
    fs::write(out_dir.join("invocations.rs"), rust).expect("write invocations.rs");
}
