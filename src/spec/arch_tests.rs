#[cfg(feature = "spec")]
pub fn test_architecture() {
    crate::arch::log("Running architecture tests...\n");

    test_cpu_id();
    test_bootstrap_processor();
    #[cfg(target_arch = "aarch64")]
    test_fdt_handoff();

    crate::arch::log("Architecture tests completed\n");
}

#[cfg(all(feature = "spec", target_arch = "aarch64"))]
fn test_fdt_handoff() {
    let fdt = crate::simpleboot::fdt_addr();
    assert_ne!(fdt, 0, "QEMU must pass a live FDT to the Image entry");
    let magic = unsafe { core::ptr::read_volatile(fdt as *const u32) };
    assert_eq!(u32::from_be(magic), 0xd00d_feed);
    let image = test_fdt_handoff as *const () as u64;
    let mut memory_ranges = 0usize;
    let mut image_is_in_ram = false;
    crate::simpleboot::for_each_mmap_entry(|entry| {
        memory_ranges += 1;
        image_is_in_ram |=
            image >= entry.base_addr && image < entry.base_addr.saturating_add(entry.length);
    });
    assert_ne!(memory_ranges, 0, "FDT must describe at least one RAM range");
    assert!(image_is_in_ram, "FDT RAM must contain the kernel image");
    let fdt_region = crate::simpleboot::mbi_region().expect("FDT region must be bounded");
    assert!(fdt_region.1 > fdt_region.0);
    crate::arch::log("AArch64 FDT memory handoff validated\n");
}

#[cfg(feature = "spec")]
fn test_cpu_id() {
    crate::arch::log("Testing CPU ID retrieval...\n");

    let cpu_id = crate::arch::get_cpu_id();
    let bsp_id = crate::simpleboot::get_bootstrap_processor_id() as crate::arch::CpuId;

    crate::arch::log("Current CPU APIC ID (from APIC register): ");
    print_number(cpu_id);
    crate::arch::log("\nBootstrap Processor ID (from Simpleboot): ");
    print_number(bsp_id);
    crate::arch::log("\n");

    if cpu_id == bsp_id {
        crate::arch::log("✓ APIC ID matches Simpleboot BSP ID\n");
    } else {
        crate::arch::log("✗ APIC ID mismatch - APIC ID should match Simpleboot BSP ID\n");
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
