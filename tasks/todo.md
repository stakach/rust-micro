# SC-donation rework — INCREMENTAL (2026-06-08)

Goal: unblock IPC0011-0024,0027 (passive-server / SC donation).
Method: land in steps, run FULL gate (esp. INTERRUPT0002) after each.
Baseline: 89/89 (commit 60debca).

## Steps
- [x] 1. `enqueued` flag — queue-membership source of truth. NO behavior
      change: keep is_runnable gating; dequeue self-guards on flag;
      enqueue/enqueue_front set it; reset_queues clears it. Gate = 89/89.
- [x] 2. is_schedulable gating (runnable && sc). admit/make_runnable/
      block/on_sc_gained/on_sc_lost. Fix rootserver (on_sc_gained after
      sc set), bootstrap_boot_thread + spec threads (placeholder sc).
      free_sched_context via on_sc_lost. Gate = 89/89 (watch INTERRUPT0002).
- [ ] 3. Donation: finish_call donates caller SC to passive callee;
      return_donated_sc on reply (decode_reply + handle_reply);
      Tcb.donated_sc. SchedContextBind on_sc_gained / Unbind on_sc_lost.
      Gate = 89/89 + IPC0016/0017/0018 (single-hop) pass.
- [ ] 4. Multi-hop chains (IPC0011-0015) + SC-deletion (0019-0024,0027).

Reference: tasks/sc-donation-wip.patch (the all-at-once attempt).
