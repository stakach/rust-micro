//! A real user thread must stop modifying shared memory before hold ACK returns.
use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

const POLL_LIMIT: usize = 20_000;
const HOLD_SAMPLES: usize = 1024;
const TCB_SUSPEND: u64 = 12;
const CNODE_DELETE: u64 = 23;

#[repr(C, align(4096))]
struct Stack([u8; 8192]);
static mut STACK: Stack = Stack([0; 8192]);
#[repr(C, align(64))]
struct Counter(AtomicU64);
static COUNTER: Counter = Counter(AtomicU64::new(0));
static CONTROL: AtomicU64 = AtomicU64::new(0);
static CORE: AtomicU64 = AtomicU64::new(0);
// Failed cleanup retains its exact identities; shared storage is not reused.
static mut OWNED: [u64; 2] = [0; 2];

pub(super) fn configure(bootinfo: &sel4_rt::BootInfo) {
    let core = if bootinfo.num_nodes > 1 {
        (bootinfo.node_id + 1) % bootinfo.num_nodes
    } else {
        bootinfo.node_id
    };
    if core < bootinfo.schedcontrol.end - bootinfo.schedcontrol.start {
        CONTROL.store(bootinfo.schedcontrol.start + core, Ordering::Relaxed);
        CORE.store(core, Ordering::Relaxed);
    }
}

unsafe fn invoke(cap: u64, label: u64, words: [u64; 4]) -> u64 {
    let info: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") cap => _,
        inout("rsi") label << 12 => info,
        inout("r10") words[0] => _, inout("r8") words[1] => _,
        inout("r9") words[2] => _, inout("r15") words[3] => _,
        inout("r12") 0u64 => _, inout("r13") 0u64 => _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    info
}

unsafe fn checked(cap: u64, label: u64, words: [u64; 4]) -> TestResult {
    if invoke(cap, label, words) != 0 {
        return Err("hold probe capability invocation rejected");
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

unsafe fn cleanup() -> TestResult {
    if OWNED[0] != 0 {
        checked(OWNED[0], TCB_SUSPEND, [0; 4])?;
    }
    for index in 0..2 {
        if OWNED[index] != 0 {
            checked(CAP_INIT_THREAD_CNODE, CNODE_DELETE, [OWNED[index], 0, 0, 0])?;
            OWNED[index] = 0;
        }
    }
    Ok(())
}

unsafe fn progress(previous: u64) -> Result<u64, &'static str> {
    for _ in 0..POLL_LIMIT {
        let current = COUNTER.0.load(Ordering::SeqCst);
        if current > previous {
            return Ok(current);
        }
        syscall0(SYS_YIELD);
    }
    Err("held child did not make bounded forward progress")
}

unsafe extern "C" fn child() -> ! {
    loop {
        COUNTER.0.fetch_add(1, Ordering::SeqCst);
    }
}

unsafe fn exercise() -> TestResult {
    let control = CONTROL.load(Ordering::Relaxed);
    if control == 0 {
        return Err("bootinfo lacks target CPU scheduling authority");
    }
    let tcb = create(0, OBJ_TCB, 0)?;
    let sc = create(1, OBJ_SCHED_CONTEXT, SCHED_CONTEXT_BITS)?;
    checked(
        tcb,
        LBL_TCB_SET_SPACE,
        [0, CAP_INIT_THREAD_CNODE, CAP_INIT_THREAD_VSPACE, 0],
    )?;
    checked(tcb, LBL_TCB_SET_PRIORITY, [255, 0, 0, 0])?;
    checked(control, LBL_SCHED_CONTROL_CONFIGURE, [sc, 10, 10, 0])?;
    checked(sc, LBL_SCHED_CONTEXT_BIND, [tcb, 0, 0, 0])?;
    let stack = (&raw const STACK as u64) + 8192 - 8;
    checked(
        tcb,
        LBL_TCB_WRITE_REGISTERS,
        [child as *const () as u64, stack, 0, 0],
    )?;
    // Verify the configured SC actually placed the child on the requested core.
    if invoke(tcb, LBL_TCB_READ_DEBUG_STATE, [0; 4]) != 29 {
        return Err("hold probe debug snapshot framing");
    }
    let affinity = (ipcbuf_vaddr() as *const u64).add(1 + 24).read_volatile();
    if affinity != CORE.load(Ordering::Relaxed) {
        return Err("hold probe child affinity mismatch");
    }
    sel4_rt::execution_hold::resume_initial(tcb)
        .map_err(|_| "hold probe initial Resume rejected")?;
    let started = progress(0)?;
    let generation =
        sel4_rt::execution_hold::acquire(tcb).map_err(|_| "hold probe acquisition rejected")?;
    let stationary = COUNTER.0.load(Ordering::SeqCst);
    for _ in 0..HOLD_SAMPLES {
        syscall0(SYS_YIELD);
        if COUNTER.0.load(Ordering::SeqCst) != stationary {
            return Err("child executed after execution-hold ACK");
        }
    }
    sel4_rt::execution_hold::release(tcb, generation).map_err(|_| "hold probe release rejected")?;
    let resumed = progress(stationary)?;
    print_str(b"[execution-hold-probe] cpu=");
    print_u64(affinity);
    print_str(b" started=");
    print_u64(started);
    print_str(b" held=");
    print_u64(stationary);
    print_str(b" resumed=");
    print_u64(resumed);
    print_str(b" stationary-samples=");
    print_u64(HOLD_SAMPLES as u64);
    print_str(b"\n");
    Ok(())
}

pub(super) fn run() -> TestResult {
    unsafe {
        if core::ptr::read(&raw const OWNED)
            .iter()
            .any(|slot| *slot != 0)
        {
            return Err("previous hold probe retains cleanup ownership");
        }
        COUNTER.0.store(0, Ordering::SeqCst);
        let result = exercise();
        cleanup().and(result)
    }
}
