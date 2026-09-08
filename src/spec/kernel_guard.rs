//! Exclusive access for hardware-free kernel fixtures while AP idle loops remain live.

pub(crate) struct KernelGuard {
    interrupt_state: u64,
    cpu: u32,
}

impl KernelGuard {
    pub(crate) fn run(test: fn()) {
        let _guard = Self::acquire();
        test();
    }

    pub(crate) fn acquire() -> Self {
        let interrupt_state: u64;
        unsafe {
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("pushfq", "pop {}", "cli", out(reg) interrupt_state);
            #[cfg(target_arch = "aarch64")]
            core::arch::asm!(
                "mrs {}, daif", "msr daifset, #2", "isb",
                out(reg) interrupt_state, options(nostack),
            );
        }
        let cpu = crate::arch::get_cpu_id();
        assert_ne!(crate::smp::bkl_holder(), cpu + 1, "nested spec KernelGuard");
        crate::smp::bkl_acquire();
        Self { interrupt_state, cpu }
    }
}

impl Drop for KernelGuard {
    fn drop(&mut self) {
        assert_eq!(crate::arch::get_cpu_id(), self.cpu);
        assert_eq!(crate::smp::bkl_holder(), self.cpu + 1);
        crate::smp::bkl_release();
        unsafe {
            #[cfg(target_arch = "x86_64")]
            if self.interrupt_state & (1 << 9) != 0 {
                core::arch::asm!("sti", options(nostack));
            }
            #[cfg(target_arch = "aarch64")]
            core::arch::asm!(
                "msr daif, {}", "isb", in(reg) self.interrupt_state, options(nostack),
            );
        }
    }
}
