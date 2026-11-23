//! The preflight and live LAPIC map must use one physical MSR-page decoder.

use std::fs;
use std::process::Command;

#[test]
fn native_lapic_page_decoder_preserves_physical_identity() {
    let root = std::env::current_dir().unwrap();
    let source = fs::read_to_string(root.join("src/arch/x86_64/paging.rs")).unwrap();
    let start = source
        .find("fn lapic_physical_page()")
        .expect("one LAPIC physical-page decoder exists");
    let end = source[start..]
        .find("/// Public entry point")
        .expect("LAPIC decoder ends before paging installer");
    let fixture = format!("{SUPPORT}\n{}\n{CASES}", &source[start..start + end]);
    let directory =
        std::env::temp_dir().join(format!("rust-micro-lapic-preflight-{}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    fs::write(&input, fixture).unwrap();
    let built = Command::new("rustc")
        .args(["--edition=2021", "--test", "-Awarnings"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "production LAPIC decoder fixture compile:\n{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let ran = Command::new(&binary).output().unwrap();
    assert!(
        ran.status.success(),
        "production LAPIC decoder fixture:\n{}{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(
        source.contains("let lapic_paddr = lapic_physical_page()"),
        "the live page-table installer must map the preflight-decoded page"
    );
}

const SUPPORT: &str = r#"
use core::sync::atomic::{AtomicU64,Ordering};
const IA32_APIC_BASE_MSR:u32=0x1b;
static APIC_BASE:AtomicU64=AtomicU64::new(0);
unsafe fn rdmsr(_:u32)->u64 {APIC_BASE.load(Ordering::Relaxed)}
"#;

const CASES: &str = r#"
#[test]
fn high_physical_bits_and_page_alignment_are_preserved() {
    APIC_BASE.store(0x1_fec0_0800,Ordering::Relaxed);
    assert_eq!(lapic_physical_page(),Some(0x1_fec0_0000));
}
#[test]
fn zero_page_refuses_preflight() {
    APIC_BASE.store(0x800,Ordering::Relaxed);
    assert_eq!(lapic_physical_page(),None);
}
"#;
