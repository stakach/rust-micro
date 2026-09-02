//! ARM GICv2 support for QEMU's `virt` platform.
//!
//! The register policy follows seL4's pinned `gic_v2.c`: all sources begin
//! disabled and non-pending, SPIs target this CPU, and the CPU interface uses
//! priority mask 0xf0 with binary point 3.

use core::ptr::{read_volatile, write_volatile};

pub const DISTRIBUTOR_BASE: usize = 0x0800_0000;
pub const CPU_INTERFACE_BASE: usize = 0x0801_0000;
pub const SPURIOUS_IRQ: u32 = 1023;

const GICD_CTLR: usize = 0x000;
const GICD_TYPER: usize = 0x004;
const GICD_IGROUPR: usize = 0x080;
const GICD_ISENABLER: usize = 0x100;
const GICD_ICENABLER: usize = 0x180;
const GICD_ICPENDR: usize = 0x280;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_ITARGETSR: usize = 0x800;
const GICD_ICFGR: usize = 0xc00;
const GICD_SGIR: usize = 0xf00;
const GICD_CPENDSGIR: usize = 0xf10;

const GICC_CTLR: usize = 0x000;
const GICC_PMR: usize = 0x004;
const GICC_BPR: usize = 0x008;
const GICC_IAR: usize = 0x00c;
const GICC_EOIR: usize = 0x010;
const GICC_IIDR: usize = 0x0fc;

#[inline]
unsafe fn dist_read(offset: usize) -> u32 {
    read_volatile((DISTRIBUTOR_BASE + offset) as *const u32)
}

#[inline]
unsafe fn dist_write(offset: usize, value: u32) {
    write_volatile((DISTRIBUTOR_BASE + offset) as *mut u32, value);
}

#[inline]
unsafe fn cpu_read(offset: usize) -> u32 {
    read_volatile((CPU_INTERFACE_BASE + offset) as *const u32)
}

#[inline]
unsafe fn cpu_write(offset: usize, value: u32) {
    write_volatile((CPU_INTERFACE_BASE + offset) as *mut u32, value);
}

pub fn interrupt_count() -> u32 {
    unsafe { 32 * ((dist_read(GICD_TYPER) & 0x1f) + 1) }
}

fn infer_cpu_target(nirqs: u32) -> u8 {
    let mut irq = 0;
    while irq < nirqs {
        let mut target = unsafe { dist_read(GICD_ITARGETSR + irq as usize) };
        target |= target >> 16;
        target |= target >> 8;
        if target != 0 {
            return target as u8;
        }
        irq += 4;
    }
    1
}

pub fn init() {
    unsafe {
        dist_write(GICD_CTLR, 0);
        let nirqs = interrupt_count().min(1020);
        let mut irq = 0;
        while irq < nirqs {
            dist_write(GICD_ICENABLER + (irq as usize / 8), u32::MAX);
            dist_write(GICD_ICPENDR + (irq as usize / 8), u32::MAX);
            dist_write(GICD_IGROUPR + (irq as usize / 8), 0);
            irq += 32;
        }

        let target = infer_cpu_target(nirqs);
        let targets = u32::from(target) * 0x0101_0101;
        irq = 32;
        while irq < nirqs {
            dist_write(GICD_IPRIORITYR + irq as usize, 0);
            dist_write(GICD_ITARGETSR + irq as usize, targets);
            irq += 4;
        }
        irq = 64;
        while irq < nirqs {
            dist_write(GICD_ICFGR + (irq as usize / 4), 0x5555_5555);
            irq += 32;
        }
        dist_write(GICD_CTLR, 1);

        init_cpu_interface();
    }
}

/// Initialize the banked SGI/PPI state and GIC CPU interface on one CPU.
/// The distributor-wide SPI setup is BSP-only, while every AP must execute
/// this portion before enabling IRQs.
pub unsafe fn init_cpu_interface() {
    unsafe {
        dist_write(GICD_ICENABLER, u32::MAX);
        dist_write(GICD_ICPENDR, u32::MAX);
        dist_write(GICD_IGROUPR, 0);
        dist_write(GICD_IPRIORITYR, 0);
        for offset in (0..16).step_by(4) {
            dist_write(GICD_CPENDSGIR + offset, u32::MAX);
        }

        // SGI 1 is the kernel reschedule/remote-call interrupt.
        dist_write(GICD_ISENABLER, 1 << super::interrupts::IPI_IRQ);

        cpu_write(GICC_CTLR, 0);
        cpu_write(GICC_PMR, 0xf0);
        cpu_write(GICC_BPR, 3);
        let mut active = cpu_read(GICC_IAR);
        while (active & 0x3ff) != SPURIOUS_IRQ {
            cpu_write(GICC_EOIR, active);
            active = cpu_read(GICC_IAR);
        }
        cpu_write(GICC_CTLR, 1);
        core::arch::asm!("dsb sy", "isb", options(nostack));
    }
}

/// Send an SGI to one GICv2 CPU target. QEMU virt exposes CPU interface bits
/// in the same dense order as MPIDR affinity level 0.
pub fn send_sgi(target_cpu: u32, irq: u32) {
    assert!(target_cpu < 8);
    assert!(irq < 16);
    unsafe {
        core::arch::asm!("dsb ishst", options(nostack));
        dist_write(GICD_SGIR, (1 << (16 + target_cpu)) | irq);
        core::arch::asm!("isb", options(nostack));
    }
}

pub fn mask(irq: u32) {
    assert!(irq < interrupt_count());
    unsafe {
        dist_write(
            GICD_ICENABLER + ((irq as usize / 32) * core::mem::size_of::<u32>()),
            1 << (irq % 32),
        );
        core::arch::asm!("dsb sy", options(nostack));
    }
}

pub fn unmask(irq: u32) {
    assert!(irq < interrupt_count());
    unsafe {
        dist_write(
            GICD_ISENABLER + ((irq as usize / 32) * core::mem::size_of::<u32>()),
            1 << (irq % 32),
        );
        core::arch::asm!("dsb sy", "isb", options(nostack));
    }
}

pub fn acknowledge() -> u32 {
    unsafe { cpu_read(GICC_IAR) }
}

pub fn end_interrupt(acknowledge: u32) {
    unsafe {
        cpu_write(GICC_EOIR, acknowledge);
        core::arch::asm!("dsb sy", "isb", options(nostack));
    }
}

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_gic() {
        arch::log("  aarch64 GICv2 registers...");
        assert_eq!(DISTRIBUTOR_BASE, 0x0800_0000);
        assert_eq!(CPU_INTERFACE_BASE, 0x0801_0000);
        assert!(interrupt_count() >= 160);
        unsafe {
            assert_eq!(dist_read(GICD_CTLR) & 1, 1);
            assert_eq!(cpu_read(GICC_CTLR) & 1, 1);
            assert_eq!(cpu_read(GICC_PMR), 0xf0);
            assert_eq!(cpu_read(GICC_BPR) & 7, 3);
            assert_ne!(cpu_read(GICC_IIDR), 0);
        }
        arch::log(" ok\n");
    }
}
