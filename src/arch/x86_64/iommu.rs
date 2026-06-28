//! Intel VT-d IOMMU (CONFIG_IOMMU). Mirrors seL4
//! `src/plat/pc99/machine/intel-vtd.c` + `src/arch/x86/object/iospace.c`.
//!
//! Current status: VIABILITY PROBE only — confirms QEMU TCG (launched
//! with `-machine q35 -device intel-iommu`) presents a parseable DMAR
//! ACPI table and a responding VT-d register file before the full
//! root/context/IO-page-table implementation is built.

use super::acpi;
use super::paging::{self, KERNEL_IOMMU_VBASE};

// VT-d register offsets (intel-vtd.c:21-88).
const VER_REG: u64 = 0x00;
const CAP_REG: u64 = 0x08;
const ECAP_REG: u64 = 0x10;

fn log_hex(v: u64) {
    let mut buf = [b'0'; 16];
    for i in 0..16 {
        let nyb = ((v >> ((15 - i) * 4)) & 0xF) as u8;
        buf[i] = if nyb < 10 { b'0' + nyb } else { b'a' + (nyb - 10) };
    }
    if let Ok(s) = core::str::from_utf8(&buf) {
        crate::arch::log(s);
    }
}

/// One-shot boot probe. Logs the verdict and leaves the IOMMU
/// untouched (no translation enabled).
pub fn viability_probe() {
    let bootboot = unsafe { &*(crate::bootboot::BOOTBOOT_INFO as *const crate::bootboot::BOOTBOOT) };
    let sdt_addr = unsafe { bootboot.arch.x86_64 }.acpi_ptr;

    let dmar = match acpi::find_dmar(sdt_addr) {
        Ok(d) => d,
        Err(_) => {
            crate::arch::log("IOMMU probe: no DMAR table (need -device intel-iommu)\n");
            return;
        }
    };
    let base = match acpi::dmar_first_drhd_base(dmar) {
        Some(b) => b,
        None => {
            crate::arch::log("IOMMU probe: DMAR has no DRHD unit\n");
            return;
        }
    };
    crate::arch::log("IOMMU probe: DMAR ok, DRHD reg base=0x");
    log_hex(base);
    crate::arch::log("\n");

    unsafe { paging::map_kernel_mmio_page(KERNEL_IOMMU_VBASE, base); }
    let off = base & 0xFFF; // page offset of the register block
    let regs = KERNEL_IOMMU_VBASE + off;
    let ver = unsafe { core::ptr::read_volatile((regs + VER_REG) as *const u32) };
    let cap = unsafe { core::ptr::read_volatile((regs + CAP_REG) as *const u64) };
    let ecap = unsafe { core::ptr::read_volatile((regs + ECAP_REG) as *const u64) };

    crate::arch::log("IOMMU VER=0x");
    log_hex(ver as u64);
    crate::arch::log(" CAP=0x");
    log_hex(cap);
    crate::arch::log(" ECAP=0x");
    log_hex(ecap);
    crate::arch::log("\n");

    // SAGAW (Supported Adjusted Guest Address Widths) = CAP[12:8];
    // ND (number of domains) = CAP[2:0]. Both non-zero => a real,
    // responding VT-d unit (not an unmapped 0xFFFF.. or dead 0 read).
    let sagaw = (cap >> 8) & 0x1F;
    let nd = cap & 0x7;
    if ver != 0 && ver != 0xFFFF_FFFF && cap != u64::MAX && sagaw != 0 {
        crate::arch::log("IOMMU: VIABLE — VT-d registers respond; SAGAW=0x");
        log_hex(sagaw);
        crate::arch::log(" ND=0x");
        log_hex(nd);
        crate::arch::log("\n");
    } else {
        crate::arch::log("IOMMU: NO — VT-d register file dead under TCG\n");
    }
}
