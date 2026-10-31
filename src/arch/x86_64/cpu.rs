use crate::arch::CpuId;
use core::arch::asm;
#[cfg(feature = "spec")]
use core::sync::atomic::{AtomicU64, Ordering};

// Count the existing hardware identity lookup per physical CPU in spec builds.
// Every sample below reads both IA32_APIC_BASE and the local APIC ID MMIO register.
#[cfg(feature = "spec")]
static APIC_IDENTITY_SAMPLES: [AtomicU64; crate::smp::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::smp::MAX_CPUS];

#[cfg(feature = "spec")]
pub(crate) fn apic_identity_samples(cpu: CpuId) -> u64 {
    APIC_IDENTITY_SAMPLES[cpu as usize].load(Ordering::Relaxed)
}

/// After `ltr`, the live Task Register names this CPU's TSS in the shared
/// GDT. It remains valid across address spaces and user/kernel transitions.
#[inline(always)]
pub fn get_cpu_id() -> CpuId {
    let selector: u16;
    unsafe {
        asm!(
            "str {selector:x}",
            selector = out(reg) selector,
            options(nomem, nostack, preserves_flags),
        );
    }
    decode_tss_selector(selector).expect("current Task Register must name a per-CPU TSS")
}

#[inline(always)]
fn decode_tss_selector(selector: u16) -> Option<CpuId> {
    let base = super::gdt::TSS_SEL_BASE;
    // Reject the LDT bit and any non-zero requested privilege level, then
    // require an aligned TSS descriptor inside our per-CPU GDT range.
    if selector & 0x7 != 0 || selector < base {
        return None;
    }
    let offset = selector - base;
    if offset & 0xF != 0 {
        return None;
    }
    let cpu = (offset / 0x10) as CpuId;
    ((cpu as usize) < crate::smp::MAX_CPUS).then_some(cpu)
}

/// The bootloader enters each CPU before its GDT/TSS is installed. Only the
/// entry path and Simpleboot's missing-SMP-tag fallback use this hardware ID.
pub fn get_hardware_cpu_id() -> CpuId {
    // Read the APIC ID register. Two regimes coexist:
    //   * Pre-`install_kernel_page_tables` (very-early boot, before
    //     we have the kernel-half linear map): use the loader's
    //     initial low-memory/MMIO mappings.
    //   * After `install_kernel_page_tables`: the linear map is up
    //     and `phys_to_lin` returns a kernel-half vaddr that's
    //     reachable from any vspace (including user vspaces that
    //     strip PML4[0] for sel4test).
    // `phys_to_lin` returns the bare paddr when `LINEAR_MAP_BASE`
    // is still zero, so a single call covers both regimes.
    let apic_base = get_apic_base();
    const APIC_ID_OFFSET: u64 = 0x20;
    let apic_id_reg = unsafe {
        let kva = super::paging::phys_to_lin(apic_base + APIC_ID_OFFSET);
        core::ptr::read_volatile(kva as *const u32)
    };
    let cpu = (apic_id_reg >> 24) & 0xFF;
    #[cfg(feature = "spec")]
    if let Some(samples) = APIC_IDENTITY_SAMPLES.get(cpu as usize) {
        samples.fetch_add(1, Ordering::Relaxed);
    }
    cpu
}

#[cfg(feature = "spec")]
pub(crate) fn test_tss_selector_decode() {
    let base = super::gdt::TSS_SEL_BASE;
    for cpu in 0..crate::smp::MAX_CPUS {
        assert_eq!(
            decode_tss_selector(super::gdt::tss_selector(cpu as u32)),
            Some(cpu as CpuId)
        );
    }
    for invalid in [
        0,
        base - 8,
        base + 1,
        base + 2,
        base + 4,
        base + 8,
        super::gdt::tss_selector(crate::smp::MAX_CPUS as u32),
    ] {
        assert_eq!(decode_tss_selector(invalid), None);
    }
}

fn get_apic_base() -> u64 {
    // Read APIC base address from MSR 0x1B (IA32_APIC_BASE)
    let apic_base_msr = unsafe {
        let mut low: u32;
        let mut high: u32;
        asm!(
            "rdmsr",
            in("ecx") 0x1Bu32,
            out("eax") low,
            out("edx") high,
        );
        ((high as u64) << 32) | (low as u64)
    };

    // APIC base address is in bits 63:12, but we mask to get the base address
    apic_base_msr & 0xFFFFF000
}

pub fn halt_cpu() {
    unsafe {
        asm!("hlt");
    }
}

pub fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let mut eax: u32;
    let mut ebx: u32;
    let mut ecx: u32;
    let mut edx: u32;

    unsafe {
        asm!(
            "push rbx",
            "mov eax, {0:e}",
            "cpuid",
            "mov {1:e}, ebx",
            "pop rbx",
            in(reg) leaf,
            out(reg) ebx,
            out("ecx") ecx,
            out("edx") edx,
            out("eax") eax,
        );
    }

    (eax, ebx, ecx, edx)
}

pub fn check_cpu_features() {
    let (_, _, _ecx, edx) = cpuid(0x1);

    if (edx & (1 << 5)) == 0 {
        panic!("MSR support required but not available");
    }

    if (edx & (1 << 9)) == 0 {
        panic!("APIC support required but not available");
    }

    if (edx & (1 << 25)) == 0 {
        panic!("SSE support required but not available");
    }
}
