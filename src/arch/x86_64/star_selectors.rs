//! IA32_STAR selector encoding shared by native setup and host regressions.

pub const fn star_value(kernel_cs: u16, user32_cs: u16) -> u64 {
    // Hardware carries the low RPL bits from STAR into the SYSRET SS/CS
    // selectors. With a bare 0x18 base KVM returns SS=0x20; a subsequent
    // LAPIC interrupt then #GPs when IRET tries to reload that ring-0 SS
    // while returning to user CS=0x2b.
    ((kernel_cs as u64) << 32) | (((user32_cs | 3) as u64) << 48)
}
