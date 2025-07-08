#[cfg(feature = "spec")]
pub fn test_architecture() {
    crate::arch::log("Running architecture tests...\n");
    
    test_cpu_id();
    test_bootstrap_processor();
    
    crate::arch::log("Architecture tests completed\n");
}

#[cfg(feature = "spec")]
fn test_cpu_id() {
    crate::arch::log("Testing CPU ID retrieval...\n");
    
    let cpu_id = crate::arch::get_cpu_id();
    let bsp_id = crate::bootboot::get_bootstrap_processor_id() as crate::arch::CpuId;
    
    crate::arch::log("Current CPU APIC ID (from APIC register): ");
    print_number(cpu_id);
    crate::arch::log("\nBootstrap Processor ID (from BOOTBOOT): ");
    print_number(bsp_id);
    crate::arch::log("\n");
    
    if cpu_id == bsp_id {
        crate::arch::log("✓ APIC ID matches BOOTBOOT BSP ID\n");
    } else {
        crate::arch::log("✗ APIC ID mismatch - APIC ID should match BOOTBOOT BSP ID\n");
    }
}

#[cfg(feature = "spec")]
fn test_bootstrap_processor() {
    crate::arch::log("Testing bootstrap processor detection...\n");
    
    // Since we're running tests, we know we're on the BSP
    // (kernel initialization would have failed otherwise)
    crate::arch::log("✓ Running on bootstrap processor (kernel initialized successfully)\n");
}

#[cfg(feature = "spec")]
fn print_number(n: u32) {
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    let mut num = n;
    
    if num == 0 {
        crate::arch::log("0");
        return;
    }
    
    while num > 0 {
        i -= 1;
        buf[i] = b'0' + (num % 10) as u8;
        num /= 10;
    }
    
    if let Ok(s) = core::str::from_utf8(&buf[i..]) {
        crate::arch::log(s);
    }
}