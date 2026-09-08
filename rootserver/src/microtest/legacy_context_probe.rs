//! Execute the edited continuation, rather than only inspecting a stopped TCB snapshot.
use super::*;
use sel4_rt::legacy_context::*;

// MCS syscall.xml and object-api.xml labels not yet exposed by sel4-rt helpers.
const SYS_NB_RECV: i64 = -8;
const TCB_SUSPEND: u64 = 12;
const CNODE_DELETE: u64 = 23;
const POLL_LIMIT: usize = 20_000;
const FIRST_SYSCALL: u64 = 0x7f00_1501;
const FINAL_SYSCALL: u64 = 0x7f00_1502;
const TERMINAL_STATUS: u64 = 0xc000_0001;
const DR7_WATCH: u64 = 0x0009_0401; // Local DR0, write-only, eight bytes.

#[repr(C, align(4096))]
struct Stack([u8; 8192]);
static mut ENTRY_STACK: Stack = Stack([0; 8192]);
static mut EDITED_STACK: Stack = Stack([0; 8192]);

#[repr(C, align(64))]
struct Observation {
    registers: [u64; 18],
    fx: [u8; FX_BYTES],
    marker: u64,
}
static mut OBSERVED: Observation = Observation {
    registers: [0; 18], fx: [0; FX_BYTES], marker: 0,
};
const _: () = {
    assert!(core::mem::offset_of!(Observation, fx) == 144);
    assert!(core::mem::offset_of!(Observation, marker) == 656);
    assert!(core::mem::align_of::<Observation>() >= 16);
};
#[repr(C, align(8))]
struct Watch(u64);
static mut WATCH: Watch = Watch(0);

// Keep failed cleanup identities reachable and refuse to reuse the shared observation storage.
// Each entry is cleared only after the corresponding CNodeDelete acknowledged success.
static mut OWNED_CAPS: [u64; 4] = [0; 4]; // TCB, SC, endpoint, Reply.

#[derive(Clone, Copy)]
struct Message {
    info: u64,
    words: [u64; 4],
}

unsafe fn invoke(cap: u64, info: u64, words: [u64; 4]) -> Message {
    let result_info: u64;
    let (a, b, c, d): (u64, u64, u64, u64);
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") cap => _,
        inout("rsi") info => result_info,
        inout("r10") words[0] => a,
        inout("r8") words[1] => b,
        inout("r9") words[2] => c,
        inout("r15") words[3] => d,
        inout("r12") 0u64 => _,
        inout("r13") 0u64 => _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    Message { info: result_info, words: [a, b, c, d] }
}

unsafe fn checked(cap: u64, label: u64, words: [u64; 4]) -> TestResult {
    if invoke(cap, label << 12, words).info != 0 {
        return Err("probe capability invocation rejected");
    }
    Ok(())
}

unsafe fn create(index: usize, kind: u64, size: u32) -> Result<u64, &'static str> {
    let slot = alloc_slot();
    checked(CAP_INIT_UNTYPED, LBL_UNTYPED_RETYPE,
        [kind, (u64::from(size) << 32) | 1, slot, 0])?;
    OWNED_CAPS[index] = slot;
    Ok(slot)
}

unsafe fn cleanup() -> TestResult {
    let tcb = OWNED_CAPS[0];
    if tcb != 0 {
        checked(tcb, TCB_SUSPEND, [0; 4])?;
    }
    for index in [0, 3, 1, 2] {
        let slot = OWNED_CAPS[index];
        if slot != 0 {
            checked(CAP_INIT_THREAD_CNODE, CNODE_DELETE, [slot, 0, 0, 0])?;
            OWNED_CAPS[index] = 0;
        }
    }
    Ok(())
}

unsafe fn poll(endpoint: u64, reply: u64) -> Message {
    let info: u64;
    let (a, b, c, d): (u64, u64, u64, u64);
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_NB_RECV as u64 => _,
        inout("rdi") endpoint => _,
        inout("rsi") 0u64 => info,
        inout("r12") reply => _,
        inout("r13") 0u64 => _,
        lateout("r10") a, lateout("r8") b, lateout("r9") c, lateout("r15") d,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    Message { info, words: [a, b, c, d] }
}

unsafe fn event(endpoint: u64, reply: u64, label: u64) -> Result<Message, &'static str> {
    for _ in 0..POLL_LIMIT {
        let message = poll(endpoint, reply);
        if message.info != 0 {
            if message.info >> 12 != label {
                print_str(b"[legacy-context-probe] expected fault ");
                print_u64(label);
                print_str(b", got info=");
                print_hex(message.info);
                for word in message.words {
                    print_str(b" ");
                    print_hex(word);
                }
                print_str(b"\n");
                return Err("unexpected child fault");
            }
            return Ok(message);
        }
        syscall0(SYS_YIELD);
    }
    Err("child event deadline exhausted")
}

unsafe fn buffer_word(index: usize) -> u64 {
    core::ptr::read_volatile((ipcbuf_vaddr() as *const u64).add(1 + index))
}

unsafe fn write_context(tcb: u64, payload: &[u64; WRITE_WORDS]) -> TestResult {
    let buffer = ipcbuf_vaddr() as *mut u64;
    for (index, word) in payload.iter().enumerate().skip(4) {
        core::ptr::write_volatile(buffer.add(1 + index), *word);
    }
    let message = invoke(tcb, (LBL_TCB_WRITE_LEGACY_CONTEXT << 12) | WRITE_WORDS as u64,
        payload[..4].try_into().unwrap());
    if message.info != 0 { return Err("private context write rejected"); }
    Ok(())
}

unsafe fn read_context(tcb: u64) -> Result<[u64; READ_WORDS], &'static str> {
    let message = invoke(tcb, LBL_TCB_READ_LEGACY_CONTEXT << 12, [0; 4]);
    if message.info != READ_WORDS as u64 {
        return Err("private context read framing");
    }
    let mut words = [0; READ_WORDS];
    words[..4].copy_from_slice(&message.words);
    for (index, word) in words.iter_mut().enumerate().skip(4) {
        *word = buffer_word(index);
    }
    Ok(words)
}

unsafe fn reply(reply: u64, status: u64, length: u64) -> TestResult {
    // Send-on-Reply consumes the supplied message. SysCall additionally acknowledges that
    // invocation with its retained message length; it does not perform another endpoint Call.
    if invoke(reply, length, [status, 0xdead, 0xbeef, 0xbad]).info != length {
        return Err("terminal reply rejected");
    }
    Ok(())
}

unsafe fn fault_binding(tcb: u64, reply: u64, fault: u64) -> Result<(u64, u64), &'static str> {
    let message = invoke(tcb, LBL_TCB_READ_DEBUG_STATE << 12, [reply, 0, 0, 0]);
    if message.info != 29 || message.words[0] != 5 || message.words[3] != 255
        || buffer_word(12) != fault
        || buffer_word(14) != buffer_word(16) || buffer_word(4) == u64::MAX
        || buffer_word(11) != u64::MAX {
        return Err("fault Reply or independent SC ownership changed");
    }
    Ok((buffer_word(16), buffer_word(4)))
}

unsafe fn marker() -> u64 {
    core::ptr::read_volatile(&raw const OBSERVED.marker)
}

pub(super) fn immediate() -> TestResult { run(false) }
pub(super) fn parked() -> TestResult { run(true) }

fn run(parked: bool) -> TestResult {
    unsafe {
        if core::ptr::read(&raw const OWNED_CAPS).iter().any(|slot| *slot != 0) {
            return Err("previous probe retains capability cleanup");
        }
        core::ptr::write_bytes(&raw mut OBSERVED, 0, 1);
        core::ptr::write_volatile(&raw mut WATCH.0, 0);
        let result = exercise(parked);
        // Even a missing/unexpected event takes the checked suspend/delete path, never waits.
        let retired = cleanup();
        retired.and(result)
    }
}

unsafe fn exercise(parked: bool) -> TestResult {
    let tcb = create(0, OBJ_TCB, 0)?;
    let sc = create(1, OBJ_SCHED_CONTEXT, SCHED_CONTEXT_BITS)?;
    let endpoint = create(2, OBJ_ENDPOINT, 0)?;
    let reply_cap = create(3, OBJ_REPLY, 0)?;
    checked(tcb, LBL_TCB_SET_SPACE,
        [endpoint, CAP_INIT_THREAD_CNODE, CAP_INIT_THREAD_VSPACE, 0])?;
    // The rootserver is priority 255 on CPU0. Equal priority makes bounded yields fair;
    // the ordinary helper's priority 100 would starve during nonblocking parent polling.
    checked(tcb, LBL_TCB_SET_PRIORITY, [255, 0, 0, 0])?;
    checked(SLOT_SCHED_CONTROL, LBL_SCHED_CONTROL_CONFIGURE, [sc, 10, 10, 0])?;
    checked(sc, LBL_SCHED_CONTEXT_BIND, [tcb, 0, 0, 0])?;
    let initial_sp = (&raw const ENTRY_STACK as u64) + 8192 - 8;
    checked(tcb, LBL_TCB_WRITE_REGISTERS, [entry as *const () as u64, initial_sp, 0, 0])?;
    checked(tcb, LBL_TCB_RESUME, [0; 4])?;
    let first = event(endpoint, reply_cap, 2)?;
    if first.info & 0xfff != 19 || buffer_word(18) != FIRST_SYSCALL || marker() != 0 {
        return Err("first UnknownSyscall framing/progress");
    }
    let original_binding = fault_binding(tcb, reply_cap, 2)?;
    print_str(b"[legacy-context-probe] initial fault captured\n");

    let mut payload = [0; WRITE_WORDS];
    payload[0] = REGISTER_MASK | FX_MASK | DEBUG_MASK;
    for index in 0..18 { payload[index + 1] = 0x1234_0000 + index as u64; }
    payload[1] = observe as *const () as u64;
    payload[2] = (&raw const EDITED_STACK as u64) + 8192 - 40;
    payload[3] = 0x246;
    let mut fx = [0u8; FX_BYTES];
    fx[..2].copy_from_slice(&0x037fu16.to_le_bytes());
    fx[4] = 1; // ST0 = 1.0, remaining x87 registers empty.
    fx[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
    fx[39] = 0x80;
    fx[40] = 0xff;
    fx[41] = 0x3f;
    for (index, value) in fx[160..416].iter_mut().enumerate() {
        *value = (index as u8).wrapping_mul(17).wrapping_add(3);
    }
    for (word, bytes) in payload[1 + REGISTER_WORDS..1 + DEBUG_OFFSET]
        .iter_mut().zip(fx.chunks_exact(8)) {
        *word = u64::from_le_bytes(bytes.try_into().unwrap());
    }
    let watch = &raw const WATCH as u64;
    payload[1 + DEBUG_OFFSET..].copy_from_slice(&[watch, 0, 0, 0, 0, DR7_WATCH]);
    write_context(tcb, &payload)?;
    print_str(b"[legacy-context-probe] context installed without restart\n");
    let installed = read_context(tcb)?;
    if installed[..18] != payload[1..19] || installed[18..20] != [0, 0] {
        return Err("stopped context edit mismatch");
    }
    if fault_binding(tcb, reply_cap, 2)? != original_binding {
        return Err("context edit changed outstanding fault ownership");
    }
    if parked {
        for _ in 0..128 {
            syscall0(SYS_YIELD);
            if marker() != 0 { return Err("context edit woke blocked child"); }
        }
    }
    reply(reply_cap, TERMINAL_STATUS, 1)?;
    print_str(b"[legacy-context-probe] terminal reply acknowledged\n");
    let debug_event = event(endpoint, reply_cap, 4)?;
    if debug_event.info & 0xfff != 4 || debug_event.words[1] != 0
        || debug_event.words[2] != watch || debug_event.words[3] != 0 || marker() != 1 {
        return Err("missing real DR0 data-watchpoint event");
    }
    let observed = core::ptr::read_volatile(&raw const OBSERVED.registers);
    payload[4] = TERMINAL_STATUS;
    if observed.as_slice() != &payload[1..19] {
        return Err("executed GPR/control image differs after terminal reply");
    }
    let actual_fx = core::ptr::read_volatile(&raw const OBSERVED.fx);
    // FXSAVE reserved bytes and MXCSR_MASK are not runtime payload equality oracles.
    for range in [0..5, 24..28, 32..42, 160..416] {
        if actual_fx[range.clone()] != fx[range] {
            return Err("executed floating-point image differs");
        }
    }
    let debug = read_context(tcb)?;
    if debug[DEBUG_OFFSET..DEBUG_OFFSET + 4] != [watch, 0, 0, 0]
        || debug[DEBUG_OFFSET + 4] & 0xf != 1
        || debug[DEBUG_OFFSET + 5] != DR7_WATCH {
        return Err("live debug context/status differs");
    }
    if fault_binding(tcb, reply_cap, 4)? != original_binding {
        return Err("resumed debug fault changed thread/SC identity");
    }
    reply(reply_cap, 0, 0)?;
    let final_event = event(endpoint, reply_cap, 2)?;
    if final_event.info & 0xfff != 19 || buffer_word(18) != FINAL_SYSCALL || marker() != 2 {
        return Err("debug acknowledgement did not resume child exactly once");
    }
    if fault_binding(tcb, reply_cap, 2)? != original_binding {
        return Err("final fault changed thread/SC identity");
    }
    if read_context(tcb)?[DEBUG_OFFSET + 4] & 0xf != 0 {
        return Err("debug acknowledgement retained stale hardware status");
    }
    // The child remains on this final real fault Reply until checked TCB/Reply deletion.
    Ok(())
}

#[unsafe(naked)]
unsafe extern "C" fn entry() -> ! {
    core::arch::naked_asm!(
        "mov edx, {number}",
        "syscall",
        "mov qword ptr [rip + {observed} + 656], 255",
        "ud2",
        number = const FIRST_SYSCALL,
        observed = sym OBSERVED,
    );
}

#[unsafe(naked)]
unsafe extern "C" fn observe() -> ! {
    core::arch::naked_asm!(
        "mov [rip + {observed} + 8], rsp",
        "mov [rip + {observed} + 24], rax",
        "mov [rip + {observed} + 32], rbx",
        "mov [rip + {observed} + 40], rcx",
        "mov [rip + {observed} + 48], rdx",
        "mov [rip + {observed} + 56], rsi",
        "mov [rip + {observed} + 64], rdi",
        "mov [rip + {observed} + 72], rbp",
        "mov [rip + {observed} + 80], r8",
        "mov [rip + {observed} + 88], r9",
        "mov [rip + {observed} + 96], r10",
        "mov [rip + {observed} + 104], r11",
        "mov [rip + {observed} + 112], r12",
        "mov [rip + {observed} + 120], r13",
        "mov [rip + {observed} + 128], r14",
        "mov [rip + {observed} + 136], r15",
        "pushfq",
        "pop qword ptr [rip + {observed} + 16]",
        "lea rax, [rip + {entry}]",
        "mov [rip + {observed}], rax",
        "fxsave64 [rip + {observed} + 144]",
        "mov qword ptr [rip + {observed} + 656], 1",
        "mov qword ptr [rip + {watch}], 1",
        "mov qword ptr [rip + {observed} + 656], 2",
        "mov edx, {number}",
        "syscall",
        "ud2",
        observed = sym OBSERVED,
        entry = sym observe,
        watch = sym WATCH,
        number = const FINAL_SYSCALL,
    );
}
