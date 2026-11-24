//! Compile the production no-MMIO IOAPIC discovery path with synthetic MADTs.

use std::fs;
use std::process::Command;

#[test]
fn early_ioapic_apertures_use_the_validated_initializer_topology() {
    let root = std::env::current_dir().unwrap();
    let source = fs::read_to_string(root.join("src/arch/x86_64/ioapic.rs")).unwrap();
    assert!(
        source.contains("let (mut staged, count) = discover_topology(sdt_addr)?"),
        "live IOAPIC initialization must use the preflight topology validator"
    );
    let start = source
        .find("fn discover_topology(")
        .expect("production IOAPIC topology discovery is shared");
    let end = source[start..]
        .find("/// Discover every MADT IOAPIC")
        .expect("no-MMIO discovery ends before hardware initialization");
    let source = source[start..start + end].replace("super::acpi::", "acpi::");
    let fixture = format!("{SUPPORT}\n{source}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "rust-micro-ioapic-preflight-{}",
        std::process::id()
    ));
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
        "production discovery fixture compile:\n{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let ran = Command::new(&binary).output().unwrap();
    assert!(
        ran.status.success(),
        "production discovery fixture:\n{}{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
}

const SUPPORT: &str = r#"
use acpi::MadtEntry;
const IOAPIC_PAGE_SIZE: u64 = 0x1000;
const MAX_IOAPICS: usize = 16;
const KERNEL_IOAPIC_VBASE: u64 = 0xffff_ffff_f800_2000;
#[derive(Copy,Clone,Debug,Eq,PartialEq)]
enum IoApicError {NoTopology,MalformedMadt,TooManyControllers,InvalidAddress,DuplicateControllerId,
    DuplicateAddress,DuplicateGsiRange,InvalidHardware}
#[derive(Copy,Clone,Debug)]
struct IoApicController {madt_id:u8,paddr:u64,vaddr:u64,gsi_base:u32,redirection_entries:u16}
const EMPTY_CONTROLLER:IoApicController=IoApicController{madt_id:0,paddr:0,vaddr:0,gsi_base:0,redirection_entries:0};
mod acpi {
    #[derive(Copy,Clone)]
    pub enum MadtEntry {IoApic {ioapic_id:u8,address:u32,gsi_base:u32},Other}
    pub struct MadtHeader { pub case: u64 }
    static VALID:MadtHeader=MadtHeader{case:0}; static DUP_ADDR:MadtHeader=MadtHeader{case:1};
    static INVALID:MadtHeader=MadtHeader{case:2}; static EMPTY:MadtHeader=MadtHeader{case:3};
    static TOO_MANY:MadtHeader=MadtHeader{case:5}; static DUP_GSI:MadtHeader=MadtHeader{case:6};
    static DUP_ID:MadtHeader=MadtHeader{case:7};
    pub fn find_madt(case:u64)->Result<&'static MadtHeader,()> {
        match case {0=>Ok(&VALID),1=>Ok(&DUP_ADDR),2=>Ok(&INVALID),3=>Ok(&EMPTY),
            5=>Ok(&TOO_MANY),6=>Ok(&DUP_GSI),7=>Ok(&DUP_ID),_=>Err(())}
    }
    pub fn iter_madt_entries(madt:&MadtHeader,mut f:impl FnMut(MadtEntry))->Result<usize,()> {
        if madt.case==5 {
            for i in 0..17 {f(MadtEntry::IoApic{ioapic_id:i,address:0xfec0_0000+(i as u32)*0x1000,gsi_base:(i as u32)*24});}
            return Ok(17);
        }
        let entries:&[MadtEntry]=match madt.case {
            0=>&[MadtEntry::Other,MadtEntry::IoApic{ioapic_id:1,address:0xfec0_0000,gsi_base:0},
                MadtEntry::IoApic{ioapic_id:2,address:0xfec0_1000,gsi_base:24}],
            1=>&[MadtEntry::IoApic{ioapic_id:1,address:0xfec0_0000,gsi_base:0},
                MadtEntry::IoApic{ioapic_id:2,address:0xfec0_0000,gsi_base:24}],
            2=>&[MadtEntry::IoApic{ioapic_id:1,address:0xfec0_0001,gsi_base:0}],
            3=>&[],
            6=>&[MadtEntry::IoApic{ioapic_id:1,address:0xfec0_0000,gsi_base:0},
                MadtEntry::IoApic{ioapic_id:2,address:0xfec0_1000,gsi_base:0}],
            7=>&[MadtEntry::IoApic{ioapic_id:1,address:0xfec0_0000,gsi_base:0},
                MadtEntry::IoApic{ioapic_id:1,address:0xfec0_1000,gsi_base:24}],
            _=>&[],
        };
        for entry in entries {f(*entry);}
        Ok(entries.len())
    }
}
"#;

const CASES: &str = r#"
#[test]
fn exact_apertures_are_discovered_without_hardware_mapping() {
    let mut pages=[u64::MAX;3];
    assert_eq!(preflight_apertures(0,&mut pages),Ok(2));
    assert_eq!(pages,[0xfec0_0000,0xfec0_1000,u64::MAX]);
    let (topology,count)=discover_topology(0).unwrap();
    assert_eq!(count,2);
    assert_eq!(topology[0].paddr,pages[0]);
    assert_eq!(topology[1].paddr,pages[1]);
}
#[test]
fn malformed_or_ambiguous_topology_does_not_publish_a_partial_aperture() {
    for (case,error) in [(1,IoApicError::DuplicateAddress),(2,IoApicError::InvalidAddress),
        (3,IoApicError::NoTopology),(4,IoApicError::MalformedMadt),
        (5,IoApicError::TooManyControllers),(6,IoApicError::DuplicateGsiRange),
        (7,IoApicError::DuplicateControllerId)] {
        let mut pages=[u64::MAX;16];
        assert_eq!(preflight_apertures(case,&mut pages),Err(error));
        assert_eq!(pages,[u64::MAX;16]);
    }
    let mut small=[u64::MAX;1];
    assert_eq!(preflight_apertures(0,&mut small),Err(IoApicError::TooManyControllers));
    assert_eq!(small,[u64::MAX]);
}
"#;
