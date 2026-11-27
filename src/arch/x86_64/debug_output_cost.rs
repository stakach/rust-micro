//! Sparse accounting for the two synchronous user diagnostic output paths.
//!
//! These counters are kernel-owned: an isolated service may map its image read-only. They
//! observe output while the caller already holds the BKL and never affect the output decision.

use core::sync::atomic::{AtomicU64, Ordering};

pub(super) enum Channel {
    Record,
    DebugService,
}

struct Cost {
    records: AtomicU64,
    bytes: AtomicU64,
    ticks: AtomicU64,
    max_ticks: AtomicU64,
}

impl Cost {
    const fn new() -> Self {
        Self {
            records: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
            max_ticks: AtomicU64::new(0),
        }
    }
}

static RECORD: Cost = Cost::new();
static DEBUG_SERVICE: Cost = Cost::new();

#[inline]
pub(super) fn start() -> u64 {
    let low: u32;
    let high: u32;
    // The two reads enclose synchronous output on one CPU with local interrupts disabled.
    unsafe {
        core::arch::asm!(
            "lfence",
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags),
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

fn print_u64(mut value: u64) {
    let mut digits = [0u8; 20];
    let mut first = digits.len();
    loop {
        first -= 1;
        digits[first] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    if let Ok(text) = core::str::from_utf8(&digits[first..]) {
        crate::arch::log(text);
    }
}

pub(super) fn finish(channel: Channel, started: u64, bytes: usize) {
    let elapsed = start().saturating_sub(started);
    let (name, cost, first_report) = match channel {
        Channel::Record => ("record", &RECORD, 1024),
        Channel::DebugService => ("debug-service", &DEBUG_SERVICE, 128),
    };
    cost.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    cost.ticks.fetch_add(elapsed, Ordering::Relaxed);
    cost.max_ticks.fetch_max(elapsed, Ordering::Relaxed);
    let records = cost.records.fetch_add(1, Ordering::Relaxed) + 1;
    if records < first_report || !records.is_power_of_two() {
        return;
    }
    // Direct kernel output cannot reenter either measured path. Sparse reports exclude their own
    // serial cost and keep the measurement from becoming another high-frequency trace.
    crate::arch::log("[debug-output-cost] path=");
    crate::arch::log(name);
    crate::arch::log(" records=");
    print_u64(records);
    crate::arch::log(" bytes=");
    print_u64(cost.bytes.load(Ordering::Relaxed));
    crate::arch::log(" ticks=");
    print_u64(cost.ticks.load(Ordering::Relaxed));
    crate::arch::log(" max-ticks=");
    print_u64(cost.max_ticks.load(Ordering::Relaxed));
    crate::arch::log("\n");
}
