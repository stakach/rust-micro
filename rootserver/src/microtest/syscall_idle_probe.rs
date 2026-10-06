//! Exercise the live syscall idle backedge with a blocked AP receiver.
use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

const POLL_LIMIT: usize = 20_000;
const OBSERVATION_CALLS: usize = 20_000;
const RETIREMENT_ROUNDS: usize = 64;
const WAKE_PAUSES: usize = 4096;
// PML4[1] is empty in a freshly retyped VSpace; never map into the root's VSpace.
const RETIREMENT_VADDR: u64 = 1 << 39;
const TCB_SUSPEND: u64 = 12;
const CNODE_DELETE: u64 = 23;
const BLOCKED_ON_RECEIVE: u64 = 3;
const DEBUG_NONE: u64 = u64::MAX;

#[repr(C, align(4096))]
struct Stack([u8; 8192]);
static mut STACK: Stack = Stack([0; 8192]);
static CONTROL: AtomicU64 = AtomicU64::new(0);
static CORE: AtomicU64 = AtomicU64::new(0);
static ENDPOINT: AtomicU64 = AtomicU64::new(0);
static REPLY: AtomicU64 = AtomicU64::new(0);
static COMPLETED: AtomicU64 = AtomicU64::new(0);
// Failed cleanup retains exact capabilities and prevents shared storage reuse.
static mut OWNED: [u64; 9] = [0; 9]; // TCB, SC, endpoint, Reply, PML4, PDPT, PD, PT, Frame.

pub(super) fn configure(bootinfo: &sel4_rt::BootInfo) {
    if bootinfo.num_nodes < 4 {
        return;
    }
    let core = (bootinfo.node_id + 1) % bootinfo.num_nodes;
    if core < bootinfo.schedcontrol.end - bootinfo.schedcontrol.start {
        CONTROL.store(bootinfo.schedcontrol.start + core, Ordering::Relaxed);
        CORE.store(core, Ordering::Relaxed);
    }
}

unsafe fn invoke(cap: u64, info: u64, words: [u64; 4]) -> (u64, u64) {
    let result_info: u64;
    let result_word: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") cap => _, inout("rsi") info => result_info,
        inout("r10") words[0] => result_word,
        inout("r8") words[1] => _, inout("r9") words[2] => _,
        inout("r15") words[3] => _, inout("r12") 0u64 => _,
        inout("r13") 0u64 => _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    (result_info, result_word)
}

unsafe fn checked(cap: u64, label: u64, words: [u64; 4]) -> TestResult {
    if invoke(cap, label << 12, words).0 != 0 {
        return Err("idle probe capability invocation rejected");
    }
    Ok(())
}

unsafe fn create(index: usize, kind: u64, size: u32) -> Result<u64, &'static str> {
    let slot = alloc_slot();
    checked(
        CAP_INIT_UNTYPED,
        LBL_UNTYPED_RETYPE,
        [kind, (u64::from(size) << 32) | 1, slot, 0],
    )?;
    OWNED[index] = slot;
    Ok(slot)
}

unsafe fn blocked(tcb: u64) -> Result<bool, &'static str> {
    if invoke(tcb, LBL_TCB_READ_DEBUG_STATE << 12, [0; 4]).0 != 29 {
        return Err("idle probe debug snapshot framing");
    }
    let words = (ipcbuf_vaddr() as *const u64).add(1);
    if words.add(24).read_volatile() != CORE.load(Ordering::Relaxed) {
        return Err("idle probe child affinity mismatch");
    }
    Ok(words.read_volatile() == BLOCKED_ON_RECEIVE
        && words.add(1).read_volatile() == 0
        && words.add(2).read_volatile() == 0
        && words.add(27).read_volatile() == DEBUG_NONE
        && words.add(28).read_volatile() == DEBUG_NONE)
}

unsafe fn wait_blocked(tcb: u64, completed: u64) -> TestResult {
    for _ in 0..POLL_LIMIT {
        if COMPLETED.load(Ordering::Acquire) == completed && blocked(tcb)? {
            return Ok(());
        }
        syscall0(SYS_YIELD);
    }
    Err("idle probe receiver did not block on an otherwise idle AP")
}

unsafe extern "C" fn child() -> ! {
    let endpoint = ENDPOINT.load(Ordering::Relaxed);
    let reply = REPLY.load(Ordering::Relaxed);
    loop {
        let payload: u64;
        core::arch::asm!(
            "syscall",
            in("rdx") SYS_RECV as u64, inout("rdi") endpoint => _,
            inout("r12") reply => _, lateout("r10") payload,
            lateout("rax") _, lateout("rsi") _, lateout("r8") _,
            lateout("r9") _, lateout("r15") _,
            lateout("rcx") _, lateout("r11") _, options(nostack),
        );
        COMPLETED.fetch_add(1, Ordering::Release);
        let _ = syscall5(SYS_SEND, reply, 1, payload.wrapping_add(1), 0, 0);
    }
}

unsafe fn exercise() -> TestResult {
    let control = CONTROL.load(Ordering::Relaxed);
    if control == 0 {
        return Err("idle probe requires at least four CPUs and AP scheduling authority");
    }
    let tcb = create(0, OBJ_TCB, 0)?;
    let sc = create(1, OBJ_SCHED_CONTEXT, SCHED_CONTEXT_BITS)?;
    let endpoint = create(2, OBJ_ENDPOINT, 0)?;
    let reply = create(3, OBJ_REPLY, 0)?;
    ENDPOINT.store(endpoint, Ordering::Relaxed);
    REPLY.store(reply, Ordering::Relaxed);
    checked(
        tcb,
        LBL_TCB_SET_SPACE,
        [0, CAP_INIT_THREAD_CNODE, CAP_INIT_THREAD_VSPACE, 0],
    )?;
    checked(tcb, LBL_TCB_SET_PRIORITY, [100, 0, 0, 0])?;
    checked(control, LBL_SCHED_CONTROL_CONFIGURE, [sc, 10, 10, 0])?;
    checked(sc, LBL_SCHED_CONTEXT_BIND, [tcb, 0, 0, 0])?;
    checked(
        tcb,
        LBL_TCB_WRITE_REGISTERS,
        [
            child as *const () as u64,
            (&raw const STACK as u64) + 8192 - 8,
            0,
            0,
        ],
    )?;
    sel4_rt::execution_hold::resume_initial(tcb)
        .map_err(|_| "idle probe initial Resume rejected")?;
    wait_blocked(tcb, 0)?;

    let vspace = create(4, OBJ_X86_PML4, PAGING_BITS)?;
    checked(
        CAP_INIT_THREAD_ASID_POOL,
        LBL_X86_ASID_POOL_ASSIGN,
        [vspace, 0, 0, 0],
    )?;
    let pdpt = create(5, OBJ_X86_PDPT, PAGING_BITS)?;
    let directory = create(6, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS)?;
    let table = create(7, OBJ_X86_PAGE_TABLE, PAGING_BITS)?;
    let frame = create(8, OBJ_X86_4K_PAGE, PAGING_BITS)?;
    for (cap, label) in [
        (pdpt, LBL_X86_PDPT_MAP),
        (directory, LBL_X86_PAGE_DIRECTORY_MAP),
        (table, LBL_X86_PAGE_TABLE_MAP),
    ] {
        checked(cap, label, [RETIREMENT_VADDR, vspace, 0, 0])?;
    }
    // AP timers are not armed. Normal frame withdrawal sends synchronous all-context
    // retirement IPIs, including to this blocked AP, without queuing a runnable thread.
    for _ in 0..RETIREMENT_ROUNDS {
        checked(
            frame,
            LBL_X86_PAGE_MAP,
            [RETIREMENT_VADDR, 3 | PAGE_EXECUTE_NEVER, vspace, 0],
        )?;
        checked(frame, LBL_X86_PAGE_UNMAP, [0; 4])?;
        // Stay in userspace with BKL released so the IRQ can return to the idle loop.
        for _ in 0..WAKE_PAUSES {
            core::hint::spin_loop();
        }
        if !blocked(tcb)? || COMPLETED.load(Ordering::Acquire) != 0 {
            return Err("idle probe receiver changed during translation retirement");
        }
    }
    // A finite observation window, not an invented elapsed-time or coverage assertion.
    for _ in 0..OBSERVATION_CALLS {
        if !blocked(tcb)? || COMPLETED.load(Ordering::Acquire) != 0 {
            return Err("idle probe receiver changed during no-thread observation");
        }
    }
    for round in 0..2 {
        let request = 0x2950 + round;
        let (info, response) = invoke(endpoint, 1, [request, 0, 0, 0]);
        if info != 1 || response != request + 1 {
            return Err("idle probe normal Call/Reply progress mismatch");
        }
        wait_blocked(tcb, round + 1)?;
    }
    print_str(b"[syscall-idle-probe] cpu=");
    print_u64(CORE.load(Ordering::Relaxed));
    print_str(b" retirement-rounds=");
    print_u64(RETIREMENT_ROUNDS as u64);
    print_str(b" observation-calls=");
    print_u64(OBSERVATION_CALLS as u64);
    print_str(b" replies=2 blocked=1\n");
    Ok(())
}

unsafe fn cleanup() -> TestResult {
    if OWNED[0] != 0 {
        checked(OWNED[0], TCB_SUSPEND, [0; 4])?;
    }
    // Withdraw leaf objects before their paging parents. No object is forgotten on error.
    for index in (0..OWNED.len()).rev() {
        if OWNED[index] != 0 {
            checked(CAP_INIT_THREAD_CNODE, CNODE_DELETE, [OWNED[index], 0, 0, 0])?;
            OWNED[index] = 0;
        }
    }
    Ok(())
}

pub(super) fn run() -> TestResult {
    unsafe {
        if core::ptr::read(&raw const OWNED)
            .iter()
            .any(|slot| *slot != 0)
        {
            return Err("previous idle probe retains cleanup ownership");
        }
        COMPLETED.store(0, Ordering::Release);
        let result = exercise();
        cleanup().and(result)
    }
}
