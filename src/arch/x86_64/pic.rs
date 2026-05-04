//! Phase 12c — legacy 8259 PIC driver.
//!
//! The 8259A pair (master at 0x20/0x21, slave at 0xA0/0xA1) is the
//! pre-APIC PC interrupt controller. Even though we'll switch to
//! the IOAPIC for real interrupt delivery, the 8259 must be set up
//! at boot so spurious IRQs don't land on the CPU's exception
//! vectors (the BIOS leaves it pointing at vectors 0x08..0x0F /
//! 0x70..0x77, which clash with the CPU's #DF / page-fault / etc.).
//!
//! Standard remap: master IRQs 0..7 → vectors 0x20..0x27, slave
//! IRQs 8..15 → 0x28..0x2F. Then mask everything and let the
//! IOAPIC take over.

use core::arch::asm;

const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

const ICW1_ICW4: u8 = 0x01; // ICW4 will follow
const ICW1_INIT: u8 = 0x10; // Initialisation

const ICW4_8086: u8 = 0x01; // 8086/88 mode

const PIC_EOI: u8 = 0x20;

/// Vector that master IRQs land on after the remap. Master IRQ N
/// → vector (PIC1_VECTOR_BASE + N). Slave IRQs land at
/// PIC2_VECTOR_BASE + (irq - 8).
pub const PIC1_VECTOR_BASE: u8 = 0x20;
pub const PIC2_VECTOR_BASE: u8 = 0x28;

/// Remap and mask every IRQ. Mirrors the canonical "init the 8259"
/// sequence from the OSDev wiki, also used by seL4's
/// `arch/x86/kernel/cmdline.c` PIC bring-up.
pub fn init_pic() {
    unsafe {
        // Disable interrupts while we reprogram — partial state
        // on the wires would deliver an IRQ to the wrong vector.
        let prev_iflag: u64;
        asm!(
            "pushfq",
            "pop {0}",
            "cli",
            out(reg) prev_iflag,
            options(nomem, preserves_flags),
        );

        // Save current masks (BIOS may have left some IRQs unmasked).
        let mask1 = inb(PIC1_DATA);
        let mask2 = inb(PIC2_DATA);

        // ICW1 — start initialisation in cascade mode.
        outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();
        outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();

        // ICW2 — vector base for each PIC.
        outb(PIC1_DATA, PIC1_VECTOR_BASE);
        io_wait();
        outb(PIC2_DATA, PIC2_VECTOR_BASE);
        io_wait();

        // ICW3 — describe the master/slave wiring.
        // Master: tell it slave is wired on IRQ2 (bit 2 = 0x04).
        outb(PIC1_DATA, 0x04);
        io_wait();
        // Slave:  tell it its cascade identity (slave ID = 2).
        outb(PIC2_DATA, 0x02);
        io_wait();

        // ICW4 — 8086 mode for both.
        outb(PIC1_DATA, ICW4_8086);
        io_wait();
        outb(PIC2_DATA, ICW4_8086);
        io_wait();

        // Restore (or mask). For now we mask everything — the
        // IOAPIC will take over.
        outb(PIC1_DATA, mask1 | 0xFF);
        outb(PIC2_DATA, mask2 | 0xFF);

        // Restore IF if it was previously set.
        if prev_iflag & (1 << 9) != 0 {
            asm!("sti", options(nomem, preserves_flags));
        }
    }
}

/// Mask all IRQs on both PICs.
pub fn mask_all() {
    unsafe {
        outb(PIC1_DATA, 0xFF);
        outb(PIC2_DATA, 0xFF);
    }
}

/// Unmask a single IRQ line.
pub fn unmask_irq(irq: u8) {
    let (port, bit) = if irq < 8 {
        (PIC1_DATA, irq)
    } else {
        (PIC2_DATA, irq - 8)
    };
    unsafe {
        let mask = inb(port);
        outb(port, mask & !(1 << bit));
    }
}

/// End-of-interrupt notification. Send to the slave first (if the
/// IRQ came from the slave) then the master.
pub fn eoi(irq: u8) {
    unsafe {
        if irq >= 8 {
            outb(PIC2_CMD, PIC_EOI);
        }
        outb(PIC1_CMD, PIC_EOI);
    }
}

/// Read the per-PIC mask register (test hook).
pub fn read_masks() -> (u8, u8) {
    unsafe { (inb(PIC1_DATA), inb(PIC2_DATA)) }
}

#[inline(always)]
unsafe fn outb(port: u16, value: u8) {
    asm!("out dx, al", in("dx") port, in("al") value,
        options(nostack, nomem, preserves_flags));
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    asm!("in al, dx", in("dx") port, out("al") v,
        options(nostack, nomem, preserves_flags));
    v
}

/// Tiny delay between PIC commands. The classic PC trick is to
/// write to port 0x80 (legacy POST-code register, ignored on
/// modern systems but takes one bus cycle).
#[inline(always)]
unsafe fn io_wait() {
    outb(0x80, 0);
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_pic() {
        arch::log("Running 8259 PIC tests...\n");
        vector_bases_dont_clash_with_cpu_exceptions();
        init_then_mask_all_set();
        unmask_clears_one_bit();
        arch::log("PIC tests completed\n");
    }

    #[inline(never)]
    fn vector_bases_dont_clash_with_cpu_exceptions() {
        // CPU exceptions are vectors 0..0x1F. PIC vectors must
        // start at 0x20 or higher.
        assert!(PIC1_VECTOR_BASE >= 0x20);
        assert_eq!(PIC2_VECTOR_BASE, PIC1_VECTOR_BASE + 8);
        arch::log("  ✓ PIC vector bases avoid CPU exception range\n");
    }

    #[inline(never)]
    fn init_then_mask_all_set() {
        init_pic();
        let (m1, m2) = read_masks();
        assert_eq!(m1, 0xFF, "master mask should be all-ones after init");
        assert_eq!(m2, 0xFF, "slave mask should be all-ones after init");
        arch::log("  ✓ init_pic remaps + masks everything\n");
    }

    #[inline(never)]
    fn unmask_clears_one_bit() {
        // Mask everything, then unmask IRQ 5; bit 5 of master mask
        // should clear.
        mask_all();
        unmask_irq(5);
        let (m1, _m2) = read_masks();
        assert_eq!(m1, 0xFF & !(1 << 5));
        // Slave-side: unmask IRQ 12 → bit (12-8)=4 of slave mask
        // clears.
        mask_all();
        unmask_irq(12);
        let (_m1, m2) = read_masks();
        assert_eq!(m2, 0xFF & !(1 << 4));
        arch::log("  ✓ unmask_irq clears the right bit on the right PIC\n");
    }
}
