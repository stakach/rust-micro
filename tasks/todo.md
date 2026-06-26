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

## Remaining test families (2026-06-08)
NEW PASSES (kernel fixes this round):
- IOPORTS1000 — user-mode #GP (unprivileged in/out without IO cap) now
  delivered as a UserException fault to the handler (was: fatal kernel
  halt). Reworked the #GP entry/handler like the #UD path (full
  fault-frame capture, deliver UserException{13}, dispatch next).
- PREEMPT_REVOKE — passed as-is once enabled.
- VSPACE0000 (inter-AS diff cspace) — passed as-is.
- VSPACE0002/0003/0004/0006 — ASID pool tests. Fixes:
  * ASIDControl_MakePool: upstream extraCaps ABI (untyped=cap[0],
    root=cap[1], index=mr0, depth=mr1); MAX_ASID_POOLS=8 exhaustion
    (-> DeleteFirst); decrement the pool count when an AsidPool cap is
    deleted (maybe_free_object) so it doesn't leak across tests.
  * ASIDPool_Assign: already-assigned PML4 -> InvalidCapability
    (was DeleteFirst; matches upstream + VSPACE0002). Kernel spec
    updated to match.

REMAINING (off-regex):
- IPC0022 (stack-spawning acceptor): HANGS — needs reply-object SC
  call-stacks (the worker replies while passive via a reply cap whose
  SC lives on the reply object, not the donor TCB). Deep.
- VSPACE0005 (overassign ASID pool): needs per-pool ASID allocation
  with 512-ASID exhaustion -> DeleteFirst (we use a global offset).
- VSPACE0001/0010 not present in this single-node build.
- Config-gated/compiled-out: BENCHMARK, BREAKPOINT, SINGLESTEP, IOPT,
  MULTICORE, VCPU, CACHEFLUSH(no x86), TIMEOUTFAULT, SERSERV, FPU0002.

## VSPACE0005 — DONE (2026-06-08)
Per-pool ASID exhaustion (512 ASIDs/pool -> DeleteFirst). Reworked the
ASID-pool allocator to bitmap-based bounded pool indices:
- ASID_POOL_INUSE bitmap (8 bits) allocates/recycles pool indices 1..8
  (init pool = index 0). asid_base = index * 512 — stable + bounded
  (replaces the ever-growing NEXT_ASID_BASE that pushed indices out of
  the per-pool used array).
- ASID_POOL_USED[index] counts assigns; Assign -> DeleteFirst at 512.
- AsidPool cap delete recycles the index (free_asid_pool_index).
- reset_asid_state() at rootserver launch clears spec-phase pollution.
- Init pool (asid_base 0) keeps the global wrapping offset -> all
  inter-AS tests unaffected (zero regression risk).
Full VSPACE family: 0000,0002,0003,0004,0005,0006 all pass.

## Truly remaining runnable tail
- IPC0022 (stack-spawning) — needs reply-object SC call-stacks (the SC
  must migrate to the reply-cap holder so a passive worker can run to
  reply). Deep; not attempted (regression risk to donation tests).
- Config-gated/compiled-out (need kernel configs + major features):
  BENCHMARK, BREAKPOINT, SINGLESTEP, IOPT(IOMMU), MULTICORE(SMP),
  VCPU(VT-x), CACHEFLUSH, TIMEOUTFAULT, SERSERV, FPU0002. Out of scope.
