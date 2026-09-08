use crate::asid::spec::RootOwners;
use crate::cap::{Cap, FrameMapType, FrameRights, FrameSize, PAddr};
use crate::cte::{MdbId, TcbSlot};
use crate::kernel::KERNEL;
use crate::tcb::{Tcb, TcbId, ThreadStateType};

const FRAME_BYTES: usize = 1 << 21;
const BUFFER_VA: u64 = 0x0040_0000 + 0x0001_2400;

#[repr(C, align(2097152))]
struct FrameBacking([u8; FRAME_BYTES * 2]);

static mut BACKING: FrameBacking = FrameBacking([0; FRAME_BYTES * 2]);

struct Fixture {
    thread: TcbId,
    sources: RootOwners,
    physical: u64,
    linked: *mut u8,
}

impl Fixture {
    unsafe fn new() -> Self {
        let sources = RootOwners::new();
        let mut thread = Tcb::default();
        thread.state = ThreadStateType::Inactive;
        let thread = KERNEL
            .get()
            .scheduler
            .try_admit_cap(thread)
            .expect("IPC fixture TCB");
        let start = core::ptr::addr_of_mut!(BACKING) as *mut u8;
        let start_physical = crate::arch::virt_to_phys(start as u64);
        // ELF virtual alignment does not require the loader to choose aligned physical backing.
        let physical = (start_physical + FRAME_BYTES as u64 - 1) & !(FRAME_BYTES as u64 - 1);
        let offset = (physical - start_physical) as usize;
        assert!(offset + FRAME_BYTES <= core::mem::size_of::<FrameBacking>());
        assert_eq!(physical & (FRAME_BYTES as u64 - 1), 0);
        Self {
            thread,
            sources,
            physical,
            linked: start.add(offset),
        }
    }

    unsafe fn source(&mut self, rights: FrameRights, is_device: bool) -> MdbId {
        self.sources.cap_source_in(
            KERNEL.get(),
            Cap::Frame {
                ptr: PAddr::new(self.physical),
                size: FrameSize::Large,
                rights,
                mapped: None,
                asid: 0,
                is_device,
                map_type: FrameMapType::None,
            },
        )
    }

    unsafe fn bind(&self, source: Option<MdbId>, address: u64) -> crate::error::KResult<()> {
        crate::invocation::derive_tcb_cap(
            KERNEL.get(),
            self.thread,
            TcbSlot::IpcBuffer,
            source,
            address,
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        unsafe {
            crate::invocation::retire_tcb(KERNEL.get(), self.thread);
        }
    }
}

pub(super) fn run() {
    unsafe {
        large_frame_offset_and_directional_rights();
        rejected_bindings_preserve_prior_authority();
        zero_address_and_deletion_withdraw_access();
    }
    crate::arch::log("  IPC buffers use retained Frame rights and full large-frame offsets\n");
}

#[inline(never)]
unsafe fn large_frame_offset_and_directional_rights() {
    let mut fixture = Fixture::new();
    let initial = KERNEL.get().scheduler.slab.get(fixture.thread);
    assert_eq!(initial.ipc_buffer_send_paddr(), 0);
    assert_eq!(initial.ipc_buffer_receive_paddr(), 0);
    let offset = BUFFER_VA & (FRAME_BYTES as u64 - 1);
    assert!(offset > 4096);
    let expected = fixture.physical + offset;
    let linked = fixture.linked.add(offset as usize);
    let linear = crate::arch::phys_to_virt(expected) as *mut u8;
    linked.write_volatile(0x5a);
    assert_eq!(linear.read_volatile(), 0x5a);
    linear.write_volatile(0xa5);
    assert_eq!(linked.read_volatile(), 0xa5);

    let read_only = fixture.source(FrameRights::ReadOnly, false);
    fixture.bind(Some(read_only), BUFFER_VA).unwrap();
    let tcb = KERNEL.get().scheduler.slab.get(fixture.thread);
    assert_eq!(tcb.ipc_buffer_send_paddr(), expected);
    assert_eq!(tcb.ipc_buffer_receive_paddr(), 0);
    assert_eq!(KERNEL.get().cte(read_only).unwrap().child_count(), 1);

    let read_write = fixture.source(FrameRights::ReadWrite, false);
    fixture.bind(Some(read_write), BUFFER_VA).unwrap();
    let tcb = KERNEL.get().scheduler.slab.get(fixture.thread);
    assert_eq!(tcb.ipc_buffer_send_paddr(), expected);
    assert_eq!(tcb.ipc_buffer_receive_paddr(), expected);
    assert!(matches!(
        tcb.ipc_buffer_cap(),
        Cap::Frame {
            size: FrameSize::Large,
            rights: FrameRights::ReadWrite,
            mapped: None,
            asid: 0,
            map_type: FrameMapType::None,
            ..
        }
    ));
    assert_eq!(KERNEL.get().cte(read_only).unwrap().child_count(), 0);
    assert_eq!(KERNEL.get().cte(read_write).unwrap().child_count(), 1);

    let kernel_only = fixture.source(FrameRights::KernelOnly, false);
    fixture.bind(Some(kernel_only), BUFFER_VA).unwrap();
    let tcb = KERNEL.get().scheduler.slab.get(fixture.thread);
    assert_eq!(tcb.ipc_buffer_send_paddr(), 0);
    assert_eq!(tcb.ipc_buffer_receive_paddr(), 0);
    assert_eq!(KERNEL.get().cte(read_write).unwrap().child_count(), 0);
    assert_eq!(KERNEL.get().cte(kernel_only).unwrap().child_count(), 1);
}

#[inline(never)]
unsafe fn rejected_bindings_preserve_prior_authority() {
    let mut fixture = Fixture::new();
    let source = fixture.source(FrameRights::ReadWrite, false);
    fixture.bind(Some(source), BUFFER_VA).unwrap();
    let held = KERNEL
        .get()
        .scheduler
        .slab
        .get(fixture.thread)
        .ipc_buffer_cap();
    let expected = fixture.physical + (BUFFER_VA & (FRAME_BYTES as u64 - 1));

    let device = fixture.source(FrameRights::ReadWrite, true);
    assert!(fixture.bind(Some(device), BUFFER_VA).is_err());
    assert!(fixture.bind(Some(source), BUFFER_VA + 8).is_err());
    assert!(fixture.bind(Some(source), BUFFER_VA + 512).is_err());
    let state = KERNEL.get();
    let tcb = state.scheduler.slab.get(fixture.thread);
    assert_eq!(tcb.ipc_buffer_cap(), held);
    assert_eq!(tcb.ipc_buffer, BUFFER_VA);
    assert_eq!(tcb.ipc_buffer_send_paddr(), expected);
    assert_eq!(tcb.ipc_buffer_receive_paddr(), expected);
    assert_eq!(
        state
            .cte(MdbId::tcb(fixture.thread, TcbSlot::IpcBuffer))
            .unwrap()
            .parent(),
        Some(source)
    );
    assert_eq!(state.cte(source).unwrap().child_count(), 1);
    assert_eq!(state.cte(device).unwrap().child_count(), 0);
}

#[inline(never)]
unsafe fn zero_address_and_deletion_withdraw_access() {
    let mut fixture = Fixture::new();
    let source = fixture.source(FrameRights::ReadWrite, false);
    let last_buffer = 0x0040_0000 + FRAME_BYTES as u64 - crate::ipc_buffer::SIZE_BYTES as u64;
    fixture.bind(Some(source), last_buffer).unwrap();
    assert_eq!(
        KERNEL
            .get()
            .scheduler
            .slab
            .get(fixture.thread)
            .ipc_buffer_receive_paddr(),
        fixture.physical + FRAME_BYTES as u64 - crate::ipc_buffer::SIZE_BYTES as u64
    );

    fixture.bind(Some(source), 0).unwrap();
    let tcb = KERNEL.get().scheduler.slab.get(fixture.thread);
    assert!(tcb.ipc_buffer_cap().is_null());
    assert_eq!(tcb.ipc_buffer_send_paddr(), 0);
    assert_eq!(tcb.ipc_buffer_receive_paddr(), 0);
    assert_eq!(KERNEL.get().cte(source).unwrap().child_count(), 0);

    fixture.bind(Some(source), BUFFER_VA).unwrap();
    crate::invocation::delete_cap_slot(
        KERNEL.get(),
        MdbId::tcb(fixture.thread, TcbSlot::IpcBuffer),
    )
    .unwrap();
    let tcb = KERNEL.get().scheduler.slab.get(fixture.thread);
    assert_eq!(tcb.ipc_buffer, 0);
    assert_eq!(tcb.ipc_buffer_send_paddr(), 0);
    assert_eq!(tcb.ipc_buffer_receive_paddr(), 0);
    assert_eq!(KERNEL.get().cte(source).unwrap().child_count(), 0);
}
