//! Phase 12b — legacy 8253/8254 Programmable Interval Timer.
//!
//! The PIT lives behind four I/O ports (0x40..0x43) and predates the
//! LAPIC by decades — every PC and PC emulator implements it. Even
//! though we'll prefer the LAPIC timer for production, the PIT is
//! handy for early bring-up because it's reachable through I/O
//! instructions (no MMIO mapping needed).
//!
//! Channels:
//!   ch0 (port 0x40) — usually wired to IRQ 0 via the 8259 / IOAPIC
//!   ch1 (port 0x41) — historically DRAM refresh; ignore
//!   ch2 (port 0x42) — PC speaker; we don't use it
//!
//! Modes used here:
//!   mode 0 — one-shot. Counter counts down once, then stops.
//!   mode 2 — rate generator. Counter wraps at zero, generates a
//!            periodic IRQ each time it crosses.
//!
//! All ports take 8-bit data. Counters are 16-bit and we write/read
//! them as low-byte then high-byte (lobyte/hibyte access mode).

use core::arch::asm;

/// PIT input frequency in Hz. Standardised at the original 8253's
/// 1.193 MHz (1.193182 MHz to be precise — derived from the original
/// PC's 14.31818 MHz clock divided by 12).
pub const PIT_INPUT_HZ: u32 = 1_193_182;

const PORT_CH0_DATA: u16 = 0x40;
const PORT_CH2_DATA: u16 = 0x42;
const PORT_COMMAND: u16 = 0x43;

/// PIT command-register layout:
///   bits 7..6 = channel (0=ch0, 1=ch1, 2=ch2, 3=read-back)
///   bits 5..4 = access mode (0=latch, 1=lobyte, 2=hibyte, 3=lo+hi)
///   bits 3..1 = mode (0..5 — we use 0 and 2)
///   bit  0    = BCD (0=binary, 1=BCD; we always pick binary)
const fn cmd_byte(channel: u8, access: u8, mode: u8) -> u8 {
    ((channel & 3) << 6) | ((access & 3) << 4) | ((mode & 7) << 1)
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Channel {
    Ch0,
    Ch2,
}

impl Channel {
    const fn data_port(self) -> u16 {
        match self {
            Channel::Ch0 => PORT_CH0_DATA,
            Channel::Ch2 => PORT_CH2_DATA,
        }
    }
    const fn cmd_index(self) -> u8 {
        match self {
            Channel::Ch0 => 0,
            Channel::Ch2 => 2,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Mode {
    /// Mode 0 — interrupt on terminal count.
    OneShot,
    /// Mode 2 — rate generator; periodic.
    Periodic,
}

impl Mode {
    const fn bits(self) -> u8 {
        match self {
            Mode::OneShot => 0,
            Mode::Periodic => 2,
        }
    }
}

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

/// Program a channel for a given count value. The IRQ fires (or
/// counter wraps) when the count hits zero.
pub fn program(channel: Channel, mode: Mode, initial_count: u16) {
    unsafe {
        outb(PORT_COMMAND, cmd_byte(channel.cmd_index(), 3, mode.bits()));
        outb(channel.data_port(), (initial_count & 0xFF) as u8);
        outb(channel.data_port(), (initial_count >> 8) as u8);
    }
}

/// Convenience wrapper: program ch0 for periodic IRQ 0 at `hz`
/// frequency. Returns the chosen divisor so the caller can tell
/// what they actually got (PIT counts at PIT_INPUT_HZ; the divisor
/// is `PIT_INPUT_HZ / hz`).
pub fn program_periodic_hz(hz: u32) -> u16 {
    let divisor = (PIT_INPUT_HZ / hz.max(1)).clamp(1, u16::MAX as u32) as u16;
    program(Channel::Ch0, Mode::Periodic, divisor);
    divisor
}

/// Latch and read back the current count of `channel`. The latch
/// command (top two bits 00 of the command byte) freezes the count
/// at its current value so we can read both bytes consistently.
pub fn read_count(channel: Channel) -> u16 {
    unsafe {
        // Issue a latch command for the channel.
        outb(PORT_COMMAND, (channel.cmd_index() & 3) << 6);
        let lo = inb(channel.data_port()) as u16;
        let hi = inb(channel.data_port()) as u16;
        (hi << 8) | lo
    }
}

// ---------------------------------------------------------------------------
// I/O helpers.
// ---------------------------------------------------------------------------

#[inline(always)]
unsafe fn outb(port: u16, value: u8) {
    asm!("out dx, al", in("dx") port, in("al") value,
        options(nostack, nomem, preserves_flags));
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    asm!("in al, dx", in("dx") port, out("al") value,
        options(nostack, nomem, preserves_flags));
    value
}

// ---------------------------------------------------------------------------
// Tick counter + IRQ 0 handler. The handler increments
// `TICK_COUNT` and EOIs the PIC. Userspace will eventually drive
// preemption from this; for now it's a smoke test that the PIT →
// PIC → IDT path actually delivers interrupts.
// ---------------------------------------------------------------------------

use core::sync::atomic::{AtomicU64, Ordering};

#[no_mangle]
pub static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Naked entry — pushes a dummy error code so the iretq frame is
/// consistent with `interrupt!`-shaped exception handlers, calls
/// the Rust ISR, EOIs the PIC, returns.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn pit_irq_entry() {
    core::arch::naked_asm!(
        "push 0",
        "push 0",
        "call {handler}",
        "add rsp, 16",
        "iretq",
        handler = sym pit_isr,
    );
}

extern "C" fn pit_isr() {
    TICK_COUNT.fetch_add(1, Ordering::Relaxed);
    super::pic::eoi(0);
}

/// Wire the PIT IRQ end-to-end:
///   1. install pit_irq_entry at IDT vector PIC1_VECTOR_BASE+0
///   2. program the PIT for `hz` rate-generator
///   3. unmask IRQ 0 on the master PIC
pub fn enable_periodic_irq(hz: u32) {
    use super::interrupts::{IdtEntry, IDT};
    use super::pic;
    let vector = pic::PIC1_VECTOR_BASE as usize;
    unsafe {
        IDT[vector] = IdtEntry::new(pit_irq_entry as u64, 0x08, 0, 0x8E);
    }
    program_periodic_hz(hz);
    pic::unmask_irq(0);
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_pit() {
        arch::log("Running PIT tests...\n");
        cmd_byte_layout();
        oneshot_count_decrements();
        periodic_divisor_picks_sane_value();
        live_irq_increments_tick_count();
        arch::log("PIT tests completed\n");
    }

    #[inline(never)]
    fn cmd_byte_layout() {
        // Channel 0, lo+hi access (3), mode 2 (periodic), binary.
        // Expected bits: 00 11 010 0 = 0011_0100 = 0x34.
        assert_eq!(cmd_byte(0, 3, 2), 0x34);
        // Channel 0, lo+hi access (3), mode 0 (one-shot), binary.
        // Expected bits: 00 11 000 0 = 0011_0000 = 0x30.
        assert_eq!(cmd_byte(0, 3, 0), 0x30);
        // Channel 2 latch: top bits 10, rest zero → 0x80.
        // (We use 'channel.cmd_index() << 6' with access=0, mode=0.)
        assert_eq!(cmd_byte(2, 0, 0), 0x80);
        arch::log("  ✓ PIT command-byte encoding matches manual\n");
    }

    #[inline(never)]
    fn oneshot_count_decrements() {
        // Park ch2 in one-shot mode with a generous count.
        // We use ch2 (PC speaker) instead of ch0 so we don't fight
        // the OS for IRQ 0 delivery on hardware that has the
        // legacy PIT routed there.
        program(Channel::Ch2, Mode::OneShot, 0xFFFF);
        let a = read_count(Channel::Ch2);
        // Burn cycles. PIT runs at ~1.19 MHz so a few thousand
        // spin-loop iterations are plenty.
        for _ in 0..10_000 {
            core::hint::spin_loop();
        }
        let b = read_count(Channel::Ch2);
        assert!(
            b < a,
            "PIT count should have decremented (a={a}, b={b})",
        );
        arch::log("  ✓ PIT one-shot count decrements over a busy wait\n");
    }

    #[inline(never)]
    fn live_irq_increments_tick_count() {
        // PIC must be initialised first; init_pic is idempotent so
        // we call it again here to be safe.
        super::super::pic::init_pic();

        let before = TICK_COUNT.load(Ordering::Relaxed);
        // 1000 Hz → 1ms per tick. Burn ~10ms.
        enable_periodic_irq(1000);
        // Spin long enough for several ticks. The qemu boot is fast
        // and our spinloop steps are cheap, so allow a generous
        // count.
        for _ in 0..50_000_000 {
            core::hint::spin_loop();
            // Bail early once we see ticks.
            if TICK_COUNT.load(Ordering::Relaxed) > before + 5 {
                break;
            }
        }
        // Mask IRQ 0 again so subsequent specs aren't perturbed.
        super::super::pic::mask_all();
        let after = TICK_COUNT.load(Ordering::Relaxed);
        assert!(
            after > before,
            "PIT IRQ should have fired at least once (before={before}, after={after})",
        );
        arch::log("  ✓ PIT IRQ delivers via PIC → IDT → ISR\n");
    }

    #[inline(never)]
    fn periodic_divisor_picks_sane_value() {
        // 100 Hz tick → divisor ≈ 11932. Within u16 range, > 1.
        let d = program_periodic_hz(100);
        // PIT_INPUT_HZ / 100 = 11_931 (rounded down).
        assert_eq!(d, 11_931);
        // Pathological inputs clamp.
        let d = program_periodic_hz(0); // would be /0; we treat as max
        assert!(d == u16::MAX);
        let d = program_periodic_hz(20_000_000); // tiny divisor
        assert_eq!(d, 1);
        arch::log("  ✓ program_periodic_hz clamps & rounds sanely\n");
    }
}
