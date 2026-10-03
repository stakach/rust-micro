//! Exercise the real syscall capture against owned page tables, without user-pointer reads.

use crate::syscall_handler::{handle_debug_write, DebugSink, SyscallArgs};

#[repr(C, align(4096))]
struct Page([u64; 512]);
static mut PAGES: [Page; 5] = [const { Page([0; 512]) }; 5];

struct Sink { bytes: [u8; 16], length: usize, records: usize }
impl DebugSink for Sink {
    fn put_byte(&mut self, _: u8) { panic!("record must use one sink operation"); }
    fn put_record(&mut self, bytes: &[u8]) {
        self.records += 1;
        self.bytes[..bytes.len()].copy_from_slice(bytes);
        self.length = bytes.len();
    }
}

pub fn test_debug_record_capture() {
    use crate::kernel::KERNEL;
    use crate::cte::TcbSlot;
    use crate::tcb::{Tcb, ThreadStateType};
    let (saved_current, saved_active_user, saved_handoff) = unsafe {
        let scheduler = &KERNEL.get().scheduler;
        (scheduler.current(), scheduler.active_user(),
            scheduler.nodes[crate::arch::get_cpu_id() as usize].direct_handoff)
    };
    let mut owners = crate::asid::spec::RootOwners::new();
    let physical = |index: usize| unsafe {
        crate::arch::virt_to_phys(core::ptr::addr_of!(PAGES[index]) as u64)
    };
    let root = owners.root(physical(0));
    let source = owners.root_source(physical(0));
    let thread = unsafe {
        let pages = &mut *core::ptr::addr_of_mut!(PAGES);
        for page in pages.iter_mut() { page.0.fill(0); }
        pages[0].0[0] = physical(1) | 5;
        pages[1].0[0] = physical(2) | 5;
        pages[2].0[2] = physical(3) | 5;
        pages[3].0[0] = physical(4) | 5;
        let bytes = core::slice::from_raw_parts_mut(pages[4].0.as_mut_ptr() as *mut u8, 4096);
        bytes[4092..].copy_from_slice(b"head");
        bytes[..4].copy_from_slice(b"tail");
        let state = KERNEL.get();
        let mut tcb = Tcb::default();
        tcb.state = ThreadStateType::Running;
        tcb.msg_regs.fill(77);
        tcb.msg_regs[..4].copy_from_slice(&[11, 22, 33, 44]);
        tcb.ipc_badge = 55;
        tcb.ipc_label = 66;
        tcb.ipc_length = 4;
        let thread = state.scheduler.admit(tcb);
        crate::invocation::derive_tcb_cap(state, thread, TcbSlot::VSpace, Some(source), 0).unwrap();
        assert_eq!(state.scheduler.slab.get(thread).vspace_root(), root);
        state.scheduler.set_current(None);
        thread
    };
    let args = SyscallArgs { a0: 0x400ffc, a1: 8, ..SyscallArgs::default() };
    let mut sink = Sink { bytes: [0; 16], length: 0, records: 0 };
    assert!(handle_debug_write(&args, Some(thread), &mut sink).is_err());
    assert_eq!(sink.records, 0, "late missing page cannot emit a prefix");
    assert!(handle_debug_write(&args, None, &mut sink).is_err());
    unsafe { (*core::ptr::addr_of_mut!(PAGES))[3].0[1] = physical(4) | 5; }
    handle_debug_write(&args, Some(thread), &mut sink).unwrap();
    assert_eq!(&sink.bytes[..sink.length], b"headtail");
    assert_eq!(sink.records, 1);
    unsafe {
        let state = KERNEL.get();
        let tcb = state.scheduler.slab.get(thread);
        assert_eq!(&tcb.msg_regs[..4], &[11, 22, 33, 44]);
        assert!(tcb.msg_regs[4..].iter().all(|word| *word == 77));
        assert_eq!((tcb.ipc_badge, tcb.ipc_label, tcb.ipc_length), (55, 66, 4));
        assert_eq!(tcb.call_reply, None);
        assert_eq!(state.scheduler.current(), None, "capture cannot invent or replace an invoker");
        state.scheduler.block(thread, ThreadStateType::Inactive);
    }
    unsafe { crate::invocation::retire_tcb(KERNEL.get(), thread); }
    drop(owners);
    unsafe {
        let scheduler = &mut KERNEL.get().scheduler;
        assert_eq!(scheduler.active_user(), saved_active_user);
        assert_eq!(scheduler.nodes[crate::arch::get_cpu_id() as usize].direct_handoff,
            saved_handoff);
        scheduler.set_current(saved_current);
        scheduler.set_active_user(saved_active_user);
    }
    crate::arch::log("  checked debug record uses exact owned VSpace and preserves IPC\n");
}
