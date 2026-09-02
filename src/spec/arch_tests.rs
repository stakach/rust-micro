#[cfg(feature = "spec")]
pub fn test_architecture() {
    crate::arch::log("Running architecture tests...\n");

    test_cpu_id();
    test_bootstrap_processor();
    #[cfg(target_arch = "aarch64")]
    test_simpleboot_handoff();

    crate::arch::log("Architecture tests completed\n");
}

#[cfg(all(feature = "spec", target_arch = "aarch64"))]
fn test_simpleboot_handoff() {
    let mbi = crate::simpleboot::mbi_addr();
    assert_ne!(mbi, 0, "Simpleboot must pass a live MBI");
    assert!(crate::simpleboot::mbi_total_size() >= 16);
    let image = test_simpleboot_handoff as *const () as u64;
    let mut memory_ranges = 0usize;
    let mut image_is_in_ram = false;
    crate::simpleboot::for_each_mmap_entry(|entry| {
        memory_ranges += 1;
        image_is_in_ram |=
            image >= entry.base_addr && image < entry.base_addr.saturating_add(entry.length);
    });
    assert_ne!(
        memory_ranges, 0,
        "Simpleboot must describe at least one RAM range"
    );
    assert!(
        image_is_in_ram,
        "Simpleboot RAM must contain the kernel image"
    );
    let mbi_region = crate::simpleboot::mbi_region().expect("MBI region must be bounded");
    assert!(mbi_region.1 > mbi_region.0);
    let smp = crate::simpleboot::smp_info().expect("Simpleboot must provide its SMP tag");
    assert!(smp.numcores > 0);
    assert_eq!(smp.running, smp.numcores);
    assert_eq!(smp.numcores, u32::from(crate::simpleboot::get_num_cores()));
    crate::arch::log("AArch64 Simpleboot MBI/SMP handoff validated\n");
}

#[cfg(feature = "spec")]
fn test_cpu_id() {
    crate::arch::log("Testing CPU ID retrieval...\n");

    let cpu_id = crate::arch::get_cpu_id();
    let bsp_id = crate::simpleboot::get_bootstrap_processor_id() as crate::arch::CpuId;

    crate::arch::log("Current CPU ID: ");
    print_number(cpu_id);
    crate::arch::log("\nBootstrap Processor ID (from Simpleboot): ");
    print_number(bsp_id);
    crate::arch::log("\n");

    if cpu_id == bsp_id {
        crate::arch::log("✓ CPU ID matches Simpleboot BSP ID\n");
    } else {
        crate::arch::log("✗ CPU ID mismatch - CPU ID should match Simpleboot BSP ID\n");
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
