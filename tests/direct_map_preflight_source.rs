//! Compile native boot preflight with fixed Simpleboot owners and firmware.

use std::fs;
use std::process::Command;

#[test]
fn first_install_counts_exact_boot_owners_before_page_table_mutation() {
    let root = std::env::current_dir().unwrap();
    let boot = fs::read_to_string(root.join("src/boot.rs")).unwrap();
    assert!(boot.contains("preflight_direct_map, DirectMapPlan"));
    let preflight = fs::read_to_string(root.join("src/boot/direct_map_preflight.rs")).unwrap();
    let start = preflight
        .find("fn push_boot_owner(")
        .expect("native preflight has a bounded boot-owner collector");
    let paging = fs::read_to_string(root.join("src/arch/x86_64/paging.rs")).unwrap();
    let first = paging
        .find("boot::preflight_direct_map(")
        .expect("first native paging install invokes preflight");
    for mutation in [
        "KERNEL_VIRT_TO_PHYS_OFFSET =",
        "install_linear_map(pml4)",
        "map_4k_into(\n            pml4,\n            KERNEL_LAPIC_VBASE",
    ] {
        assert!(
            first < paging.find(mutation).unwrap(),
            "preflight must precede {mutation}"
        );
    }
    let source = preflight[start..].replace("#[cfg(target_arch = \"x86_64\")]\n", "");
    let support = SUPPORT
        .replace(
            "{policy}",
            &root
                .join("src/boot/direct_map_policy.rs")
                .display()
                .to_string(),
        )
        .replace(
            "{owners}",
            &root
                .join("src/boot/direct_map_owners.rs")
                .display()
                .to_string(),
        );
    let fixture = format!("{support}\n{source}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "rust-micro-direct-preflight-{}",
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
        "native preflight fixture compile:\n{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let ran = Command::new(&binary).output().unwrap();
    assert!(
        ran.status.success(),
        "native preflight fixture:\n{}{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
}

const SUPPORT: &str = r#"
#[path = "{policy}"] mod direct_map_policy;
#[path = "{owners}"] mod direct_map_owners;
use direct_map_policy::{FirmwareKind,FirmwareRange,PhysicalRange,PlanError,TableDemand,TablePool};
#[derive(Clone,Copy,Debug,Eq,PartialEq)] enum BootError {InvalidMemoryMap,TooManyRegions}
const MAX_BOOT_MMAP_ENTRIES:usize=240;
const MAX_RESERVED_REGIONS:usize=128;
mod arch {pub mod x86_64 {pub mod ioapic {pub const MAX_IOAPICS:usize=16;}}}
fn read_simpleboot_firmware_map(out:&mut[FirmwareRange])->Result<usize,BootError> {
    let entries=[
        FirmwareRange{range:PhysicalRange{start:0,end:0x20_0000},kind:FirmwareKind::Ram},
        FirmwareRange{range:PhysicalRange{start:0x20_0000,end:0x40_0000},kind:FirmwareKind::Reserved},
        FirmwareRange{range:PhysicalRange{start:0x40_0000,end:0x60_0000},kind:FirmwareKind::Mmio},
        FirmwareRange{range:PhysicalRange{start:0x60_0000,end:0x80_0000},kind:FirmwareKind::Ram},
    ];
    out[..entries.len()].copy_from_slice(&entries);
    Ok(entries.len())
}
mod simpleboot {
    pub fn mbi_region()->Option<(u64,u64)> {Some((0x20_0000,0x20_0900))}
    pub fn for_each_module_region(mut f:impl FnMut(u64,u64)) {f(0x20_1000,0x20_1800);}
    pub fn for_each_kernel_region(mut f:impl FnMut(u64,u64)) {f(0x20_2000,0x20_2800);}
}
fn visit_live_page_tables(mut f:impl FnMut(u64,u64)->Result<(),BootError>)->Result<(),BootError> {
    f(0x20_3000,0x20_4000)
}
"#;

const CASES: &str = r#"
#[test]
fn all_boot_owners_and_both_controller_apertures_fit() {
    let mut owners=[PhysicalRange{start:0,end:0};MAX_RESERVED_REGIONS];
    let count=collect_boot_owner_ranges(&mut owners).unwrap();
    assert_eq!(count,4);
    assert_eq!(&owners[..count],&[
        PhysicalRange{start:0x20_0000,end:0x20_1000},
        PhysicalRange{start:0x20_1000,end:0x20_2000},
        PhysicalRange{start:0x20_2000,end:0x20_3000},
        PhysicalRange{start:0x20_3000,end:0x20_4000},
    ]);
    let pool=TablePool{used:0,reserved:3,capacity:64};
    let mut plan=DirectMapPlan::new();
    let budget=preflight_direct_map(0x40_0000,&[0x40_1000],0x80_0000,pool,&mut plan).unwrap();
    assert_eq!(budget,TableDemand{pdpt_pages:1,pd_pages:1,pt_pages:1});
    assert!(plan.checked());
    assert!(plan.contains(0x1000));
    assert!(plan.contains(0x20_1000));
    assert!(!plan.contains(0x40_0000));
    assert!(!plan.contains(0x40_1000));
}
#[test]
fn a_controller_in_ram_or_insufficient_pool_refuses() {
    let pool=TablePool{used:0,reserved:3,capacity:64};
    let mut plan=DirectMapPlan::new();
    assert_eq!(preflight_direct_map(0,&[0x40_1000],0x80_0000,pool,&mut plan),Err(PreflightError::InvalidAperture));
    assert!(!plan.checked());
    assert_eq!(preflight_direct_map(0x1000,&[0x40_1000],0x80_0000,pool,&mut plan),
        Err(PreflightError::Policy(PlanError::AmbiguousOverlap)));
    assert!(!plan.checked());
    assert_eq!(preflight_direct_map(0x40_0000,&[0x40_1000],0x80_0000,
        TablePool{used:0,reserved:3,capacity:5},&mut plan),Err(PreflightError::Policy(PlanError::PoolExhausted)));
    assert!(!plan.checked());
}
"#;
