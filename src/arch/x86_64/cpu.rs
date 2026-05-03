use crate::arch::CpuId;
use core::arch::asm;

pub fn get_cpu_id() -> CpuId {
    // Read the APIC ID register. Two regimes coexist:
    //   * Pre-`install_kernel_page_tables` (very-early boot, before
    //     we have the kernel-half linear map): BOOTBOOT identity-
    //     maps low memory + MMIO at PML4[0], so dereferencing the
    //     raw paddr from IA32_APIC_BASE just works.
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
    (apic_id_reg >> 24) & 0xFF
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