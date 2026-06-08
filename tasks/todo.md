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
- [x] 3. Donation: finish_call donates caller SC to passive callee;
      return_donated_sc on reply (decode_reply + handle_reply);
      Tcb.donated_sc. SchedContextBind on_sc_gained / Unbind on_sc_lost.
      Gate = 89/89 + IPC0016/0017/0018 (single-hop) pass.
- [x] 4. Multi-hop chains (IPC0011-0015) + SC-deletion (0019-0024,0027).

Reference: tasks/sc-donation-wip.patch (the all-at-once attempt).

## Step 4 — donation family results (2026-06-08)
PASS (12, all on committed step-3 code): IPC0011,0012,0013,0014,0015
(multi-hop inheritance chains), 0016,0017,0018 (single-hop), 0019,0020
(delete SC while client sending/waiting), 0024 (delete reply cap in SC),
0027 (sched donation to low-prio server).
Remaining hard tail (NOT done):
- IPC0021 — fault handler on donated SC (fault×donation combo): HANGS.
- IPC0022 — stack-spawning server with SC donation: HANGS.
- IPC0023 — delete SC tracked in a reply cap: FAILS (state==2 vs 1,
  line 1173) — reply-cap SC-deletion semantics not modelled.
- IPC0028 — disabled upstream (false).

## Step 5 — hard tail (2026-06-08)
- [x] IPC0023 (delete SC tracked in reply cap): FIXED. free_sched_context
      now also clears any donor TCB's `donated_sc` referencing the freed
      SC, so a later reply can't return a deleted SC to the donor.
- [x] IPC0021 (fault handler on donated SC): FIXED. The fault-reply
      branches (decode_reply + handle_reply) now call return_donated_sc
      so the SC a faulter donated to a passive handler (fault delivery
      is a Call) is moved back on the fault reply.
- [ ] IPC0022 (stack-spawning server): still HANGS. Specialized acceptor
      pattern — a spawner Recv's on the shared endpoint with each new
      worker's reply cap and hands off connections via those reply caps;
      needs deeper reply-cap/donation handoff modelling. Deferred.
- IPC0028 disabled upstream.
