//! Exercise the real boot map reader against a synthetic Simpleboot producer.
//!
//! The source function is compiled verbatim into a small host harness. This
//! checks its failure behavior without running the bare-metal kernel binary.

use std::fs;
use std::process::Command;

fn reader_source(source: &str) -> &str {
    let start = source
        .find("pub fn read_simpleboot_mmap(")
        .expect("native boot reader exists");
    let open = start + source[start..].find('{').expect("reader body");
    let mut depth = 0usize;
    for (offset, byte) in source[open..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..open + offset + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated native boot reader")
}

#[test]
fn native_reader_rejects_truncation_overflow_and_malformed_final_tag_atomically() {
    let root = std::env::current_dir().unwrap();
    let source = fs::read_to_string(root.join("src/boot.rs")).unwrap();
    let work = std::env::temp_dir().join(format!(
        "rust-micro-boot-mmap-source-{}",
        std::process::id()
    ));
    fs::create_dir_all(&work).unwrap();
    let harness = work.join("reader.rs");
    let binary = work.join("reader");

    let mut program = String::new();
    program.push_str("#[path = ");
    program.push_str(&format!("{:?}", root.join("src/boot/direct_map_policy.rs")));
    program.push_str("] mod direct_map_policy;\n#[path = ");
    program.push_str(&format!(
        "{:?}",
        root.join("src/boot/simpleboot_mmap_policy.rs")
    ));
    program.push_str("] mod simpleboot_mmap_policy;\n");
    program.push_str(r#"
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PRegion { start: u64, end: u64 }
impl PRegion { fn new(start: u64, end: u64) -> Self { Self { start, end } } }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemKind { Free, Used, Acpi, Mmio }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemEntry { region: PRegion, kind: MemKind }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BootError { InvalidMemoryMap }
const MAX_BOOT_MMAP_ENTRIES: usize = 240;

mod simpleboot {
    use std::sync::{atomic::{AtomicBool, Ordering}, Mutex};
    pub const MULTIBOOT_MEMORY_AVAILABLE: u32 = 1;
    pub const MULTIBOOT_MEMORY_ACPI_RECLAIMABLE: u32 = 3;
    pub const MULTIBOOT_MEMORY_NVS: u32 = 4;
    #[derive(Clone, Copy)]
    pub struct MMapEntry {
        pub base_addr: u64,
        pub length: u64,
        pub entry_type: u32,
        pub reserved: u32,
    }
    static ENTRIES: Mutex<Vec<MMapEntry>> = Mutex::new(Vec::new());
    static MALFORMED_FINAL_TAG: AtomicBool = AtomicBool::new(false);
    pub fn set(entries: Vec<MMapEntry>, malformed: bool) {
        *ENTRIES.lock().unwrap() = entries;
        MALFORMED_FINAL_TAG.store(malformed, Ordering::Relaxed);
    }
    pub fn for_each_mmap_entry(mut f: impl FnMut(MMapEntry)) {
        for entry in ENTRIES.lock().unwrap().iter().copied() { f(entry); }
    }
    pub fn try_for_each_mmap_entry(f: impl FnMut(MMapEntry)) -> Result<(), ()> {
        for_each_mmap_entry(f);
        if MALFORMED_FINAL_TAG.load(Ordering::Relaxed) { Err(()) } else { Ok(()) }
    }
}

trait Rejected { fn rejected(self) -> bool; }
impl Rejected for usize { fn rejected(self) -> bool { false } }
impl Rejected for Result<usize, BootError> { fn rejected(self) -> bool { self.is_err() } }

fn entry(base: u64, length: u64) -> simpleboot::MMapEntry {
    simpleboot::MMapEntry { base_addr: base, length, entry_type: 1, reserved: 0 }
}

fn check_case(name: &str, raw: Vec<simpleboot::MMapEntry>, malformed: bool) -> bool {
    simpleboot::set(raw, malformed);
    let sentinel = MemEntry { region: PRegion::new(u64::MAX, u64::MAX), kind: MemKind::Used };
    let mut output = [sentinel; MAX_BOOT_MMAP_ENTRIES];
    let rejected = read_simpleboot_mmap(&mut output).rejected();
    let untouched = output.iter().all(|entry| *entry == sentinel);
    println!("{name}: rejected={rejected} untouched={untouched}");
    rejected && untouched
}

fn main() {
    let oversized = (0..=240).map(|i| entry(i * 4096, 4096)).collect();
    let truncated = check_case("241 entries", oversized, false);
    let overflow = check_case("overflowing physical range", vec![entry(0, 4096), entry(u64::MAX - 8, 16)], false);
    let malformed = check_case("malformed final tag", vec![entry(0, 4096)], true);
    if !(truncated && overflow && malformed) { std::process::exit(1); }
}
"#);
    program.push_str(reader_source(&source));
    fs::write(&harness, program).unwrap();
    let compiled = Command::new("rustc")
        .arg("--edition=2021")
        .arg("-A")
        .arg("dead_code")
        .arg("-A")
        .arg("private_interfaces")
        .arg(&harness)
        .arg("-o")
        .arg(&binary)
        .status()
        .unwrap();
    assert!(compiled.success(), "native reader harness must compile");
    let ran = Command::new(&binary).output().unwrap();
    print!("{}", String::from_utf8_lossy(&ran.stdout));
    assert!(
        ran.status.success(),
        "native reader accepted a corrupt source map"
    );
}
