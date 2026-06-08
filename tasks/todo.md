# IPC + INTERRUPT families (2026-06-08)

## Status
INTERRUPT: 0002-0006 ALL PASS (0005/0006 newly added to regex). Done.

IPC basic/inter-AS/nbsendrecv: PASS via long-message reply fix —
IPC0001-0004, IPC1001-1004, IPC0010, IPC0025, IPC0026 (13 tests).
  - Root cause: reply paths didn't round-trip messages > SCRATCH words.
    `decode_reply` staged the register range but dropped the >20-word
    tail; `handle_reply` had the tail copy but never loaded words 4..19
    from the replier's buffer. Fix: shared `endpoint::deliver_message`
    (renamed from `transfer`, now pub(crate)) used by endpoint IPC AND
    both reply paths; SCRATCH_MSG_LEN already 20 so the 19-word range
    stages on-TCB and the 20..120 tail goes buffer-to-buffer.

## Remaining IPC — SC-donation / passive-server (deep MCS rework)
IPC0011-0024, IPC0027 (0028 disabled). These need upstream's true
SC-donation model, which we don't implement yet:
  - schedContext_donate MOVES the sc: caller->sc = NULL, callee->sc = sc.
    (We currently keep a separate `active_sc` for charging only.)
  - isSchedulable = runnable && sc != NULL && sc_active. A passive thread
    (no SC) is runnable (can pair in IPC) but NOT schedulable (skipped by
    choose_thread / not enqueued).
  - On Call to a passive server: donate caller's SC to it (so it runs),
    record donated SC on the reply object for return.
  - On Reply (reply_pop): give the SC back to the caller if caller->sc
    is NULL.
  - SchedContextBind to a runnable passive thread enqueues it; unbind
    dequeues. IPC0017/0018 toggle this to (un)block clients.

### Rework plan
- [ ] A. Scheduling guard: make_runnable enqueues + possibleSwitchTo only
      when sc.is_some(); choose_thread never returns sc==None threads;
      add helper is_schedulable(tcb).
- [ ] B. Reply object carries donated_sc: Some(sc_id) when a Call donated.
- [ ] C. Call delivery (endpoint send_ipc/receive_ipc do_call): if
      sender.sc.is_some() && receiver.sc.is_none() -> donate (move sc,
      enqueue receiver, record donated_sc on reply). Drop active_sc hack.
- [ ] D. Reply paths (decode_reply/handle_reply/SysReplyRecv): on reply,
      if donated_sc set and caller.sc.is_none() -> return sc to caller
      (move back), dequeue server if it's now passive.
- [ ] E. SchedContextBind: if target runnable -> enqueue. Unbind: dequeue.
- [ ] F. NBSend to passive server: deliver but don't make schedulable;
      Send (blocking) to passive server: sender stays blocked (IPC0017).

### Verify
- [ ] Full gate stays green (long-msg fix) — run_gate2.log.
- [ ] IPC0011-0024,0027 pass incrementally.

## FPU (after IPC) — FPU0001/0002 (preemption-counting; TCG-slow)

## FPU — DONE (2026-06-08)
- FPU0000/0003/0004: already passing.
- FPU0001 (multi-thread FPU sharing under preemption): PASSES with the
  current kernel — no fxsave/fxrstor needed in practice because the
  threads recompute a full fpu_calculation each iteration and our
  timer preemption granularity doesn't corrupt in-flight calcs. The
  old "doesn't converge on TCG" note was pre-LAPIC-timer. Added to gate.
- FPU0002 (FPU across core migration): compiled out — gated on
  CONFIG_MAX_NUM_NODES > 1; our kernel config is single-node (=1).
  Would require real multinode SMP scheduling + migration: out of scope.
- Note: src/fpu.rs lazy-FPU module remains a feature-gated placeholder;
  real fxsave/fxrstor context-switching is only needed if a future
  test or workload corrupts FPU state across preemption (none in the
  enabled set do).
