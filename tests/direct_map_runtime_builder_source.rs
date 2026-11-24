//! Exercise the native first-install direct-map builder against checked firmware ownership.
//! The pure range planner can pass while the runtime still installs a blanket WB leaf.

use std::fs;
use std::process::Command;

#[test]
fn native_direct_map_builder_excludes_device_holes_after_preflight() {
    let root = std::env::current_dir().unwrap();
    let paging = fs::read_to_string(root.join("src/arch/x86_64/paging.rs")).unwrap();
    let preflight = paging
        .find("boot::preflight_direct_map(")
        .expect("first native paging install must preflight firmware ownership");
    let install = paging
        .find("install_linear_map(pml4);")
        .expect("first native paging install must use the checked map");
    assert!(preflight < install, "preflight must precede native PML4 mutation");

    // Execute the production builder with fake page-table storage. Only the privileged TLB
    // flush is omitted; the native PML4/PDPT writes and leaf flags are unchanged.
    let start = paging
        .find("unsafe fn install_linear_map(")
        .expect("native direct-map builder");
    let tail = &paging[start..];
    let flush = tail.find("    // TLB flush.").expect("native TLB flush boundary");
    let after_flush = tail.find("    Some((idx, base))")
        .expect("native builder returns an unpublished slot and base");
    let builder_end = tail.find("\n/// Map `vaddr -> paddr`")
        .expect("native builder end");
    let builder = format!("{}    // Host fixture omits only the privileged TLB flush.\n{}",
        &tail[..flush], &tail[after_flush..builder_end]);
    let ensure_start = paging.find("unsafe fn ensure_table_into(")
        .expect("native intermediate-table constructor");
    let ensure_tail = &paging[ensure_start..];
    let ensure_end = ensure_tail.find("// ---------------------------------------------------------------------------\n// Specs")
        .expect("native intermediate-table end");
    let fixture = SUPPORT
        .replace("{policy}", &root.join("src/boot/direct_map_policy.rs").display().to_string())
        .replace("{builder}", &builder)
        .replace("{ensure}", &ensure_tail[..ensure_end]);

    let directory = std::env::temp_dir().join(format!(
        "rust-micro-runtime-direct-map-{}",
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
    assert!(built.status.success(),
        "native builder fixture compile:\n{}", String::from_utf8_lossy(&built.stderr));
    let ran = Command::new(&binary).output().unwrap();
    assert!(ran.status.success(),
        "native builder mapped a device hole or lost admitted RAM:\n{}{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr));
}

const SUPPORT: &str = r#"
mod boot { #[path = "{policy}"] pub mod direct_map_policy; }
mod arch {
    pub mod x86_64 {
        pub mod vspace {
            pub const KUSER_SHARED_DATA_VADDR: u64 = 0;
            pub struct Parts { pub pml4: u16 }
            pub fn decompose_vaddr(_: u64) -> Parts { Parts { pml4: 0 } }
        }
        pub mod paging {
            use std::ptr;
            use crate::boot::direct_map_policy::{
                count_direct_map_tables, FirmwareKind, FirmwareRange, PhysicalRange,
                PlanError, TableDemand, TablePool,
            };

            const PTE_PRESENT: u64 = 1;
            const PTE_RW: u64 = 1 << 1;
            const PTE_PS: u64 = 1 << 7;
            const PTE_NX: u64 = 1 << 63;
            const LINEAR_MAP_GIB: u64 = 8;
            static mut LINEAR_MAP_BASE: u64 = 0;
            static mut LINEAR_MAP_PML4_IDX: usize = 0;

            struct DirectMapPlan {
                firmware: [FirmwareRange; 5],
                reserved_ram: [PhysicalRange; 1],
                devices: [PhysicalRange; 1],
            }
            impl DirectMapPlan {
                fn checked(&self) -> bool { true }
                fn firmware(&self) -> &[FirmwareRange] { &self.firmware }
                fn reserved_ram(&self) -> &[PhysicalRange] { &self.reserved_ram }
                fn devices(&self) -> &[PhysicalRange] { &self.devices }
                fn limit(&self) -> u64 { 8 << 30 }
            }
            static DIRECT_MAP_PLAN: DirectMapPlan = DirectMapPlan {
                firmware: [
                    FirmwareRange { range: PhysicalRange { start: 0, end: 0x20_0000 }, kind: FirmwareKind::Ram },
                    FirmwareRange { range: PhysicalRange { start: 0x20_0000, end: 0x40_0000 }, kind: FirmwareKind::Reserved },
                    FirmwareRange { range: PhysicalRange { start: 0x40_0000, end: 0x60_0000 }, kind: FirmwareKind::Mmio },
                    FirmwareRange { range: PhysicalRange { start: 0x60_0000, end: 0x80_0000 }, kind: FirmwareKind::Ram },
                    FirmwareRange { range: PhysicalRange { start: 5 << 30, end: 6 << 30 }, kind: FirmwareKind::Ram },
                ],
                reserved_ram: [PhysicalRange { start: 0x20_0000, end: 0x30_0000 }],
                devices: [PhysicalRange { start: 0x40_0000, end: 0x60_0000 }],
            };

            #[derive(Clone, Copy)]
            #[repr(align(4096))]
            struct PageTable([u64; 512]);
            static mut TABLES: [PageTable; 64] = [PageTable([0; 512]); 64];
            static mut TABLE_USED: usize = 0;

            unsafe fn alloc_table_va() -> *mut u64 {
                assert!(TABLE_USED < 64, "native builder exceeded fixture table pool");
                let next = ptr::addr_of_mut!(TABLES).cast::<PageTable>().add(TABLE_USED);
                TABLE_USED += 1;
                ptr::addr_of_mut!((*next).0).cast::<u64>()
            }
            fn kernel_virt_to_phys(address: u64) -> u64 { address }

            {builder}
            {ensure}

            unsafe fn mapped(pml4: &[u64; 512], physical: u64) -> bool {
                const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
                let root = pml4[LINEAR_MAP_PML4_IDX];
                if root & PTE_PRESENT == 0 { return false; }
                let pdpt = (root & ADDRESS) as *const u64;
                let one_gib = ptr::read_volatile(pdpt.add((physical >> 30) as usize));
                if one_gib & PTE_PRESENT == 0 { return false; }
                if one_gib & PTE_PS != 0 { return true; }
                let pd = (one_gib & ADDRESS) as *const u64;
                let two_mib = ptr::read_volatile(pd.add(((physical >> 21) & 511) as usize));
                if two_mib & PTE_PRESENT == 0 { return false; }
                if two_mib & PTE_PS != 0 { return true; }
                let pt = (two_mib & ADDRESS) as *const u64;
                ptr::read_volatile(pt.add(((physical >> 12) & 511) as usize)) & PTE_PRESENT != 0
            }

            #[test]
            fn checked_firmware_hole_is_absent_from_native_page_tables() {
                let firmware = DIRECT_MAP_PLAN.firmware();
                let boot_owned = DIRECT_MAP_PLAN.reserved_ram();
                let devices = DIRECT_MAP_PLAN.devices();
                let mut demand = TableDemand { pdpt_pages: 0, pd_pages: 0, pt_pages: 0 };
                let mut pml4 = [0u64; 512];

                assert_eq!(count_direct_map_tables(firmware, boot_owned, devices,
                    8 << 30, TablePool { used: 0, reserved: 3, capacity: 5 }, &mut demand),
                    Err(PlanError::PoolExhausted));
                assert!(pml4.iter().all(|entry| *entry == 0));
                assert_eq!(unsafe { LINEAR_MAP_BASE }, 0);

                count_direct_map_tables(firmware, boot_owned, devices,
                    8 << 30, TablePool { used: 0, reserved: 3, capacity: 64 }, &mut demand)
                    .unwrap();
                let (slot, base) = unsafe { install_linear_map(pml4.as_mut_ptr()) }
                    .expect("first checked native map");
                unsafe { LINEAR_MAP_PML4_IDX = slot; LINEAR_MAP_BASE = base; }
                assert!(unsafe { mapped(&pml4, 0x1000) }, "ordinary RAM must remain mapped");
                assert!(unsafe { mapped(&pml4, 0x20_1000) }, "proven boot-owned RAM must remain mapped");
                assert!(!unsafe { mapped(&pml4, 0x40_1000) }, "BAR/MMIO must have no WB direct alias");
                assert!(!unsafe { mapped(&pml4, 0x50_1000) }, "controller aperture must have no WB direct alias");
                assert!(unsafe { mapped(&pml4, 0x60_1000) }, "later ordinary RAM must remain mapped");
                assert!(!unsafe { mapped(&pml4, (4 << 30) + 0x1000) }, "unknown high memory stays absent");
                assert!(unsafe { mapped(&pml4, (5 << 30) + 0x1000) }, "admitted RAM above 4 GiB remains mapped");
            }
        }
    }
}
"#;
