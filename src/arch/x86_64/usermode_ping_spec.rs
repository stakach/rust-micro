//! Live ring-3 SMP probe with actual assigned VSpace ownership.

use super::map_user_4k_into_pml4;
use crate::arch::x86_64::paging::{install_kernel_page_tables, kernel_virt_to_phys};
use crate::arch::x86_64::syscall_entry::UserContext;
use crate::asid::spec::RootOwners;
use crate::kernel::KERNEL;
use crate::tcb::{Tcb, ThreadStateType};

#[repr(C, align(4096))]
struct UserPage([u8; 4096]);

#[rustfmt::skip]
const PING_PAYLOAD: &[u8] = &[
    0x48, 0xC7, 0xC2, 0xF5, 0xFF, 0xFF, 0xFF, // mov rdx, -11
    0x0F, 0x05,                               // syscall
    0xEB, 0xF5,                               // jmp -11
];

static mut PING_CODE_PAGE: UserPage = UserPage([0; 4096]);
static mut PING_STACK_PAGE: UserPage = UserPage([0; 4096]);

const PING_CODE_VBASE: u64 = 0x0000_0100_0010_0000;
const PING_STACK_VBASE: u64 = 0x0000_0100_0011_0000;

/// Caller holds BKL and retains the returned owners until the thread is stopped and detached.
pub unsafe fn launch_smp_ping_thread() -> (crate::tcb::TcbId, RootOwners) {
    install_kernel_page_tables();
    copy_payload(&raw const PING_CODE_PAGE, PING_PAYLOAD);

    let pml4 = crate::arch::x86_64::paging::make_user_pml4();
    map_user_4k_into_pml4(
        pml4,
        PING_CODE_VBASE,
        kernel_virt_to_phys((&raw const PING_CODE_PAGE) as u64),
        false,
        false,
    );
    map_user_4k_into_pml4(
        pml4,
        PING_STACK_VBASE,
        kernel_virt_to_phys((&raw const PING_STACK_PAGE) as u64),
        true,
        true,
    );

    let mut owners = RootOwners::new();
    let root = owners.root(pml4);
    let s = KERNEL.get();
    let mut t = Tcb::default();
    t.priority = 100;
    t.state = ThreadStateType::Running;
    t.affinity = 1; // pin to CPU 1 (AP1)
    t.user_context = UserContext::for_entry(
        PING_CODE_VBASE,
        PING_STACK_VBASE + 0x1000 - 8,
        /* arg0 */ 0,
    );
    assert!(t.set_vspace_root(root));
    let id = s.scheduler.admit(t);

    // Reschedule IPI tells AP1 to run choose_thread. After the ISR
    // returns, AP1's `ap_scheduler_loop` body sees `current=Some(id)`
    // and dispatches.
    crate::smp::kick_cpu(1);
    (id, owners)
}

unsafe fn copy_payload(page: *const UserPage, source: &[u8]) {
    core::ptr::copy_nonoverlapping(source.as_ptr(), page as *mut u8, source.len());
}
