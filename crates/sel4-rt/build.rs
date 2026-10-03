#[path = "../../build_support/xml.rs"]
#[allow(dead_code)]
mod xml;

fn main() {
    let source = "../../codegen/syscall.xml";
    println!("cargo:rerun-if-changed={source}");
    println!("cargo:rerun-if-changed=../../build_support/xml.rs");
    let input = std::fs::read_to_string(source).expect("central syscall XML");
    let output = xml::generate_syscalls(&input).expect("central syscall generation");
    let path = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(path.join("syscalls.rs"), output).expect("generated syscall ABI");
}
