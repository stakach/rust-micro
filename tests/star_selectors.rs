#[path = "../src/arch/x86_64/star_selectors.rs"]
mod star_selectors;

#[test]
fn sysret_user_base_preserves_ring_three_in_both_selectors() {
    // KVM exposed the hardware selector values: STAR user base 0x18
    // produced SS=0x20, and the LAPIC IRQ's IRET then #GP'd on 0x20.
    let star = star_selectors::star_value(0x08, 0x18);
    let base = (star >> 48) as u16;
    assert_eq!(base.wrapping_add(8), 0x23, "SYSRET user SS");
    assert_eq!(base.wrapping_add(16), 0x2b, "SYSRET user CS");
}
