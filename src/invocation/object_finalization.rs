#[derive(Clone, Copy)]
enum FinalizationObject {
    CNode(usize),
    Thread(TcbId),
}

const FINALIZATION_CAPACITY: usize = KernelState::cnode_pool_count() + crate::tcb::MAX_TCBS;
const _: () = assert!(FINALIZATION_CAPACITY <= u16::MAX as usize);

struct FinalizationQueue {
    entries: [u16; FINALIZATION_CAPACITY],
    scheduled: [bool; FINALIZATION_CAPACITY],
    head: usize,
    tail: usize,
    active: bool,
}

impl FinalizationQueue {
    const fn new() -> Self {
        Self { entries: [0; FINALIZATION_CAPACITY], scheduled: [false; FINALIZATION_CAPACITY],
            head: 0, tail: 0, active: false }
    }

    fn push(&mut self, object: FinalizationObject) {
        let index = match object {
            FinalizationObject::CNode(index) => {
                assert!(index < KernelState::cnode_pool_count());
                index
            }
            FinalizationObject::Thread(id) => {
                assert!((id.0 as usize) < crate::tcb::MAX_TCBS);
                KernelState::cnode_pool_count() + id.0 as usize
            }
        };
        if self.scheduled[index] {
            return;
        }
        assert!(self.tail < self.entries.len(), "distinct finalizers fit the object registry");
        self.scheduled[index] = true;
        self.entries[self.tail] = index as u16;
        self.tail += 1;
    }

    fn pop(&mut self) -> Option<FinalizationObject> {
        if self.head == self.tail {
            return None;
        }
        let index = self.entries[self.head] as usize;
        self.head += 1;
        Some(if index < KernelState::cnode_pool_count() {
            FinalizationObject::CNode(index)
        } else {
            FinalizationObject::Thread(TcbId((index - KernelState::cnode_pool_count()) as u16))
        })
    }
}

struct FinalizationCell(core::cell::UnsafeCell<FinalizationQueue>);
unsafe impl Sync for FinalizationCell {}
static FINALIZATIONS: FinalizationCell = FinalizationCell(
    core::cell::UnsafeCell::new(FinalizationQueue::new()));

/// Nested object finalizers only enqueue. No queue borrow crosses a destructor, and the running
/// object's scheduled marker remains set until the entire BKL-owned drain finishes.
unsafe fn finalize_object(s: &mut KernelState, object: FinalizationObject) {
    let queue = FINALIZATIONS.0.get();
    if !(*queue).active {
        (*queue).head = 0;
        (*queue).tail = 0;
        (*queue).scheduled.fill(false);
    }
    (*queue).push(object);
    if (*queue).active {
        return;
    }
    (*queue).active = true;
    while let Some(object) = (*queue).pop() {
        match object {
            FinalizationObject::CNode(index) => destroy_cnode(s, index),
            FinalizationObject::Thread(id) => destroy_tcb(s, id),
        }
    }
    (*queue).active = false;
}

unsafe fn destroy_cnode(s: &mut KernelState, index: usize) {
    let slots = s.cnode_slots_at(index).expect("queued CNode remains registered under BKL");
    let count = slots.len();
    let cap = Cap::CNode { ptr: KernelState::cnode_ptr(index),
        radix: count.trailing_zeros() as u8, guard_size: 0, guard: 0 };
    assert!(cnode_has_only_self_refs(s, &cap), "queued CNode gained an external reference");
    for slot in 0..count {
        delete_cap_slot(s, MdbId::pack(index as u32, slot as u32))
            .expect("owned CNode slots remain finalizable under BKL");
    }
    assert_cnode_release_invariants(s, index);
    s.free_cnode_virt(index);
}

/// Trusted kernel retirement, also used by fixtures with an admitted but unpublished TCB.
pub(crate) unsafe fn retire_tcb(s: &mut KernelState, id: TcbId) {
    assert_eq!(crate::kernel::thread_cap_refcount(id), 0, "retired TCB retains caller capabilities");
    finalize_object(s, FinalizationObject::Thread(id));
}
