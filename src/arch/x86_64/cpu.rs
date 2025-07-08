use crate::arch::CpuId;
use core::arch::asm;

pub fn get_cpu_id() -> CpuId {
    // Read the APIC ID from the APIC ID register (not x2APIC mode)
    let apic_base = get_apic_base();
    const APIC_ID_OFFSET: u64 = 0x20;
    
    let apic_id_reg = unsafe {
        let apic_id_addr = (apic_base + APIC_ID_OFFSET) as *const u32;
        core::ptr::read_volatile(apic_id_addr)
    };
    
    // In standard APIC mode, APIC ID is in bits 31:24 of the ID register
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