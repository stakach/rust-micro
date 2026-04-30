//! Phase 11a — Global Descriptor Table + Task State Segment.
//!
//! Sets up the GDT layout that user-mode + SYSCALL/SYSRET expects:
//!
//!   index   selector  description
//!   0       0x00      NULL (required by ISA)
//!   1       0x08      KERNEL_CS  64-bit code, DPL=0
//!   2       0x10      KERNEL_DS  data,        DPL=0
//!   3       0x18      USER32_CS  placeholder; SYSRET expects it
//!   4       0x20      USER_DS    data,        DPL=3
//!   5       0x28      USER_CS    64-bit code, DPL=3
//!   6-7     0x30      TSS        16-byte system descriptor
//!
//! The user-DS / user-CS pair sits adjacent to USER32_CS so the
//! IA32_STAR MSR's user base of 0x18 lands on USER_DS for SS and
//! USER32_CS+0x10 for CS — exactly what SYSRET decodes.
//!
//! The TSS holds `rsp0`, the kernel stack the CPU loads when a user
//! thread enters the kernel via SYSCALL or an exception. It's
//! allocated in BSS; production multi-CPU would have one TSS per
//! core.

use core::arch::asm;

// ---------------------------------------------------------------------------
// Selector constants. RPL bits (low 2) are the requested privilege
// level the *caller* asks for; we OR them in at use sites.
// ---------------------------------------------------------------------------

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
pub const USER32_CS: u16 = 0x18; // legacy, kept for SYSRET
pub const USER_DS: u16 = 0x20 | 3;
pub const USER_CS: u16 = 0x28 | 3;
pub const TSS_SEL: u16 = 0x30;

// ---------------------------------------------------------------------------
// GDT and TSS storage. Both live in BSS.
//
// GDT: 8 entries × 8 bytes = 64 bytes. Slot 6/7 hold the upper half
// of the TSS system descriptor.
// ---------------------------------------------------------------------------

const GDT_ENTRIES: usize = 8;

#[repr(C, align(16))]
struct GdtTable {
    entries: [u64; GDT_ENTRIES],
}

static mut GDT: GdtTable = GdtTable { entries: [0; GDT_ENTRIES] };

/// Minimal x86_64 TSS layout (104 bytes). Only `rsp0` is meaningful
/// for syscall entry; the IST entries and iomap base sit at zero
/// for now.
#[repr(C, packed)]
struct Tss {
    _reserved0: u32,
    pub rsp0: u64,
    pub rsp1: u64,
    pub rsp2: u64,
    _reserved1: u64,
    pub ist1: u64,
    pub ist2: u64,
    pub ist3: u64,
    pub ist4: u64,
    pub ist5: u64,
    pub ist6: u64,
    pub ist7: u64,
    _reserved2: u64,
    _reserved3: u16,
    pub iomap_base: u16,
}

static mut TSS: Tss = Tss {
    _reserved0: 0,
    rsp0: 0,
    rsp1: 0,
    rsp2: 0,
    _reserved1: 0,
    ist1: 0,
    ist2: 0,
    ist3: 0,
    ist4: 0,
    ist5: 0,
    ist6: 0,
    ist7: 0,
    _reserved2: 0,
    _reserved3: 0,
    iomap_base: 0,
};

// Descriptor used by `lgdt`. 10 bytes packed: 2-byte limit + 8-byte
// base.
#[repr(C, packed)]
struct GdtPointer {
    limit: u16,
    base: u64,
}

// ---------------------------------------------------------------------------
// Hand-rolled descriptor encoders. We could route through the
// auto-generated `GdtCode` / `GdtData` / `GdtTss` bitfields, but the
// fields are scattered across 13 named slots which makes a
// hand-encoded constant clearer for a one-time setup.
// ---------------------------------------------------------------------------

const fn segment_descriptor(
    limit: u32,
    base: u32,
    access: u8,
    flags: u8,
) -> u64 {
    let mut d: u64 = 0;
    d |= (limit as u64) & 0xFFFF;
    d |= ((base as u64) & 0xFFFF) << 16;
    d |= (((base as u64) >> 16) & 0xFF) << 32;
    d |= (access as u64) << 40;
    d |= (((limit as u64) >> 16) & 0x0F) << 48;
    d |= (flags as u64) << 52;
    d |= (((base as u64) >> 24) & 0xFF) << 56;
    d
}

// access byte:
//   bit 7: present (P)
//   bit 6-5: DPL
//   bit 4: descriptor type (1 = code/data, 0 = system)
//   bit 3-0: type
// flags nybble (in bits 52..55 of the descriptor):
//   bit 3: G (granularity)
//   bit 2: D/B
//   bit 1: L (long mode)
//   bit 0: AVL
//
// Kernel CS: P=1, DPL=0, S=1, type=1010 (exec/read) → 0x9A
// Kernel DS: P=1, DPL=0, S=1, type=0010 (read/write) → 0x92
// User CS  : P=1, DPL=3, S=1, type=1010                → 0xFA
// User DS  : P=1, DPL=3, S=1, type=0010                → 0xF2
//
// Flags for 64-bit code: G=1, D=0, L=1 → 0xA0
// Flags for data:        G=1, D=1, L=0 → 0xC0  (D=1 is a no-op in
//                                              long mode for data)
const ACCESS_KERN_CS: u8 = 0x9A;
const ACCESS_KERN_DS: u8 = 0x92;
const ACCESS_USER_CS: u8 = 0xFA;
const ACCESS_USER_DS: u8 = 0xF2;
const FLAGS_CODE64: u8 = 0xA;
const FLAGS_DATA: u8 = 0xC;

const KERNEL_CS_DESC: u64 =
    segment_descriptor(0xFFFFF, 0, ACCESS_KERN_CS, FLAGS_CODE64);
const KERNEL_DS_DESC: u64 =
    segment_descriptor(0xFFFFF, 0, ACCESS_KERN_DS, FLAGS_DATA);
const USER32_CS_DESC: u64 =
    // 32-bit user code segment placeholder. SYSRET's CS=STAR_USER+16
    // logic gates off the L bit, but if it's mistakenly used we want
    // a sensible 32-bit code segment. Flags: G=1, D=1, L=0 → 0xC0.
    segment_descriptor(0xFFFFF, 0, ACCESS_USER_CS, 0xC);
const USER_DS_DESC: u64 =
    segment_descriptor(0xFFFFF, 0, ACCESS_USER_DS, FLAGS_DATA);
const USER_CS_DESC: u64 =
    segment_descriptor(0xFFFFF, 0, ACCESS_USER_CS, FLAGS_CODE64);

// 16-byte TSS system descriptor. Two consecutive 8-byte slots: low
// half encodes the limit + low 32 bits of base + access + flags,
// high half holds bits 32..63 of base.
const fn tss_descriptor_low(base: u64, limit: u32) -> u64 {
    // Access byte: P=1, DPL=0, S=0, type=1001 (available 64-bit
    // TSS) → 0x89. Flags: G=0, D=0, L=0 → 0x0.
    let access: u8 = 0x89;
    let flags: u8 = 0x0;
    let mut d: u64 = 0;
    d |= (limit as u64) & 0xFFFF;
    d |= (base & 0xFFFF) << 16;
    d |= ((base >> 16) & 0xFF) << 32;
    d |= (access as u64) << 40;
    d |= (((limit as u64) >> 16) & 0x0F) << 48;
    d |= (flags as u64) << 52;
    d |= ((base >> 24) & 0xFF) << 56;
    d
}

// ---------------------------------------------------------------------------
// init_gdt — populate the GDT, load it, set the TSS, point
// kernel-side `rsp0` at the current stack.
// ---------------------------------------------------------------------------

pub fn init_gdt() {
    // Capture the current stack as the kernel rsp0. When a user
    // thread enters via SYSCALL or an interrupt, this is the rsp
    // the CPU loads. For now we use the boot stack; per-thread
    // kernel stacks land with thread switching.
    let rsp0 = current_rsp();

    unsafe {
        // SAFETY: We're the only writer pre-init. After this point
        // the GDT becomes a read-mostly structure; subsequent
        // changes (e.g. updating TSS rsp0 on context switch) only
        // touch fields that don't affect the descriptor layout.
        TSS.rsp0 = rsp0;
        TSS.iomap_base = core::mem::size_of::<Tss>() as u16;

        let tss_base = &raw const TSS as u64;
        let tss_limit = (core::mem::size_of::<Tss>() - 1) as u32;

        GDT.entries[0] = 0;
        GDT.entries[1] = KERNEL_CS_DESC;
        GDT.entries[2] = KERNEL_DS_DESC;
        GDT.entries[3] = USER32_CS_DESC;
        GDT.entries[4] = USER_DS_DESC;
        GDT.entries[5] = USER_CS_DESC;
        GDT.entries[6] = tss_descriptor_low(tss_base, tss_limit);
        GDT.entries[7] = tss_base >> 32;

        load_gdt(&raw const GDT as u64, (core::mem::size_of::<GdtTable>() - 1) as u16);
        load_tss(TSS_SEL);
    }
}

/// Update the kernel-mode rsp the CPU loads on user→kernel
/// transition. Called by the scheduler whenever the current thread
/// changes — each thread has its own kernel stack.
pub fn set_kernel_rsp(rsp: u64) {
    unsafe {
        TSS.rsp0 = rsp;
    }
}

/// Read the GDT entry at `index` for spec assertions.
#[cfg(feature = "spec")]
pub fn gdt_entry(index: usize) -> u64 {
    unsafe { GDT.entries[index] }
}

#[cfg(feature = "spec")]
pub fn tss_rsp0() -> u64 {
    unsafe { TSS.rsp0 }
}

// ---------------------------------------------------------------------------
// Low-level helpers.
// ---------------------------------------------------------------------------

#[inline(always)]
fn current_rsp() -> u64 {
    let rsp: u64;
    unsafe {
        asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem, preserves_flags));
    }
    rsp
}

unsafe fn load_gdt(base: u64, limit: u16) {
    let ptr = GdtPointer { limit, base };
    asm!(
        "lgdt [{p}]",
        // Far-return into the new code segment so CS gets reloaded.
        "push {cs}",
        "lea {tmp}, [rip + 2f]",
        "push {tmp}",
        "retfq",
        "2:",
        // Reload data-segment registers via a fixed AX. The const
        // immediate goes through `mov ax, imm16` so we don't need
        // a template modifier.
        "mov ax, {ds}",
        "mov ds, ax",
        "mov es, ax",
        "mov ss, ax",
        "mov fs, ax",
        "mov gs, ax",
        p = in(reg) &ptr,
        cs = const KERNEL_CS as u64,
        ds = const KERNEL_DS as u64,
        tmp = lateout(reg) _,
        out("ax") _,
        options(nostack, preserves_flags),
    );
}

unsafe fn load_tss(sel: u16) {
    asm!("ltr {0:x}", in(reg) sel, options(nostack, nomem, preserves_flags));
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_gdt() {
        arch::log("Running GDT/TSS tests...\n");
        layout_matches_seL4_convention();
        tss_rsp0_set();
        descriptor_bits_check_out();
        arch::log("GDT/TSS tests completed\n");
    }

    #[inline(never)]
    fn layout_matches_seL4_convention() {
        // Selectors at the documented offsets.
        assert_eq!(KERNEL_CS, 0x08);
        assert_eq!(KERNEL_DS, 0x10);
        assert_eq!(USER32_CS, 0x18);
        assert_eq!(USER_DS, 0x23);
        assert_eq!(USER_CS, 0x2B);
        assert_eq!(TSS_SEL, 0x30);
        // Slot 0 must be the null descriptor.
        assert_eq!(gdt_entry(0), 0);
        // Kernel CS / DS non-zero, TSS pair non-zero.
        assert_ne!(gdt_entry(1), 0);
        assert_ne!(gdt_entry(2), 0);
        assert_ne!(gdt_entry(6), 0);
        arch::log("  ✓ GDT layout matches seL4 selector convention\n");
    }

    #[inline(never)]
    fn tss_rsp0_set() {
        // After init_gdt(), rsp0 is the stack we were running on.
        // Just check it's non-zero and looks like a kernel-half
        // address.
        let rsp = tss_rsp0();
        assert!(rsp != 0, "TSS.rsp0 should be set");
        assert!(rsp > 0xFFFF_FFFF_0000_0000, "rsp0 should be kernel-half");
        arch::log("  ✓ TSS.rsp0 holds the boot kernel stack\n");
    }

    #[inline(never)]
    fn descriptor_bits_check_out() {
        // The CPU sets the "accessed" bit (bit 0 of the access byte)
        // automatically when a selector is loaded into a segment
        // register. Mask it off before comparing — what we care
        // about is the rest of the access byte plus the DPL/L
        // bits.
        const ACCESS_MASK: u64 = 0xFE;

        // Kernel CS: access byte = 0x9A, L bit set.
        let kcs = gdt_entry(1);
        assert_eq!((kcs >> 40) & ACCESS_MASK, 0x9A);
        assert_eq!((kcs >> 53) & 1, 1, "kernel CS must have L=1");

        // Kernel DS: access byte = 0x92 (might read 0x93 post-load).
        let kds = gdt_entry(2);
        assert_eq!((kds >> 40) & ACCESS_MASK, 0x92);

        // User CS: access byte = 0xFA, DPL=3 at bits 45..46.
        let ucs = gdt_entry(5);
        assert_eq!((ucs >> 40) & ACCESS_MASK, 0xFA);
        assert_eq!((ucs >> 45) & 3, 3, "user CS must have DPL=3");

        // User DS: access byte = 0xF2, DPL=3.
        let uds = gdt_entry(4);
        assert_eq!((uds >> 40) & ACCESS_MASK, 0xF2);
        assert_eq!((uds >> 45) & 3, 3, "user DS must have DPL=3");

        arch::log("  ✓ descriptor bits encode access + flags correctly\n");
    }
}
