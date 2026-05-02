# Phase 32: MCS scheduler — DONE (32a–32g)

## Goal
Replace the classic time-slice scheduler with seL4's MCS
(Mixed-Criticality Systems) sporadic-server model. Today each
TCB has a `time_slice: u32` decremented per PIT tick; when it
hits zero we preempt. MCS instead gives each thread a
*SchedContext* with a refill schedule (period + budget); each
tick spends from the current refill; when budget runs out the
thread blocks until the next scheduled refill.

What's already in place:
* `src/sched_context.rs` (gated `feature = "mcs"`) — `SchedContext`,
  `Refill`, `refill_charge`, plus a small spec module.
* `codegen/structures_64.bf` defines `sched_context_cap` and the
  MCS variant of `reply_cap` under `#ifdef CONFIG_KERNEL_MCS`.
  `build_support/bf.rs` defaults `CONFIG_KERNEL_MCS = false`,
  so those blocks don't get generated today.

## Plan (incremental — one phase per slice)

- [x] 32a — MCS-only kernel. **DONE**
  * `CONFIG_KERNEL_MCS = true` unconditionally in
    `build_support/bf.rs::default_config`.
  * `Cap::Reply` reshaped to MCS layout:
    `{ ptr: PPtr<ReplyStorage>, can_grant: bool }` (drops the
    non-MCS `tcb` + `master`).
  * `feature = "mcs"` gates removed (`sched_context.rs`,
    `main.rs`, `spec.rs`); the cargo feature is retained as
    a no-op so existing `--features mcs` invocations still work.
  * Codegen quirk: padding spanning multiple words is now
    accepted in `lower()`. Only named fields need to fit in a
    single word (the MCS notification block declares
    `padding 3 * word_size`).
  * `Notification::SIZE_BYTES` updated 32 → 64 in two specs
    (the MCS notification carries `ntfnSchedContext` + 3-word
    padding).

- [x] 32b — typed Cap::SchedContext + retype. **DONE**
  * `Cap::SchedContext { ptr, size_bits }` (tag 22) round-trips
    through `SchedContextCap`.
  * `ObjectType::SchedContext` is now variable-sized; valid
    `user_size_bits` ∈ [`MIN_SCHED_CONTEXT_BITS`=8,
    `MAX_SCHED_CONTEXT_BITS`=16].
  * `Untyped::Retype(SchedContext, size_bits, n)` produces N
    typed `Cap::SchedContext`s of the requested size, MDB-aware
    via Phase 30 wiring.
  * Specs: round-trip + retype-into-SchedContext.


- [x] 32c — Bind SchedContext to TCB. **DONE**
  * `MAX_SCHED_CONTEXTS = 16` SchedContext pool in
    `KernelState::sched_contexts`, with bump allocator
    `alloc_sched_context()` and `sched_context_ptr() /
    sched_context_index()` helpers (same convention as
    Endpoints — PPtr.addr = pool_index + 1).
  * `Tcb::sc: Option<u16>` records the bound SC's pool index;
    `SchedContext::bound_tcb` records the reverse link.
  * `Untyped::Retype(SchedContext)` post-processes through the
    pool: emit closure swaps the carved cap for one keyed off
    the pool slot.
  * `decode_sched_context` handles `SchedContextBind` (a2 =
    TCB cap_ptr) and `SchedContextUnbind`. Refuses double-bind
    in either direction with `DeleteFirst`.
  * Spec: retype Untyped → SC, bind to a fresh TCB, verify both
    sides linked, unbind clears them, re-bind after unbind ok.
  * `CONFIG_KERNEL_MCS` flip in the XML codegen also bumped
    TCBSetSpace 10 → 11 and TCBResume 12 → 13. Rootserver's
    hardcoded label constants updated to match.

- [x] 32d — Cap::SchedControl + ConfigureFlags. **DONE**
  * Tag 24 promoted to `Cap::SchedControl { core: u32 }` typed
    variant. Round-trip via the generated `SchedControlCap`.
  * `decode_sched_control` handles
    `SchedControlConfigureFlags(target_sc, budget, period)` —
    looks up the SC cap in invoker's CSpace, rejects budget=0
    or budget>period with `RangeError`, then resets the SC to a
    fresh `(period, budget)` schedule with one ready refill at
    release_time=0.
  * Spec: `sched_control_configure_sets_period_budget` retypes
    an SC, plants a SchedControl cap, invokes Configure, asserts
    the SC's fields + ready refill, and confirms budget>period
    is rejected.

- [x] 32e — refill_charge ↔ PIT tick. **DONE**
  * `sched_context::mcs_tick(delta_ticks)` — kernel-side
    handler called once per PIT IRQ. Looks up the current
    TCB's bound SC; charges `refill_charge`; if exhausted,
    blocks the thread (state = Inactive) so the dispatcher's
    next pick finds the next runnable. Threads with `sc =
    None` (rootserver, AY demo, default-spawned TCBs) are
    unaffected.
  * `pit_isr` calls `mcs_tick(1)` after the existing
    `scheduler.tick()`.
  * Spec `mcs_tick_blocks_on_exhaustion` admits a TCB, binds
    it to a 2-tick budget SC, makes it `current`, ticks twice,
    asserts the thread is parked Inactive on the second tick.
  * Wake-up on the next refill's release_time is Phase 32f.

- [x] 32f — Refill maturity wake-up. **DONE**
  * `mcs_tick` now does two passes per call:
      1. Pre-charge wake-up scan: any parked TCB whose bound
         SC has a matured head refill (`refill_ready(sc, now)`)
         transitions Inactive → Running via `make_runnable`.
      2. Charge the current TCB's SC. On exhaustion,
         `refill_replenish` queues a new refill at `now+period`
         and the thread parks.
  * `current_time()` reads `pit::TICK_COUNT` in production;
    spec mode pins it via `set_test_time(Some(t))` so tests
    can control "now" deterministically.
  * Spec `mcs_tick_wakes_on_matured_refill`: budget=1, period=10;
    one tick exhausts the SC and parks the thread; advancing
    test_time to 10 and ticking again wakes it.
  * Wire `pit_isr` (under `cfg(feature = "mcs")`) to call
    `refill_charge(tcb.sc, ticks_elapsed)` instead of the
    classic `time_slice -= 1`.
  * On budget exhaustion: block the thread and stash a wake-up
    timestamp; on next refill (= scheduler tick reaches the
    refill's release_time) make the thread runnable again.
  * Spec: prime an SC with budget=10, period=100; charge
    9 ticks, thread runs; charge 1 more, thread blocks; advance
    to release_time, thread wakes.

- [x] 32g — Rootserver demo: mixed-criticality. **DONE**
  * Rootserver retypes 2 SchedContexts at MIN_SCHED_CONTEXT_BITS,
    configures via SchedControl (slot 14, installed by the
    kernel in `launch_rootserver`):
      SC_HIGH = period 10, budget 8 — high-criticality task.
      SC_LOW  = period 10, budget 2 — best-effort task.
  * Retypes 2 child TCBs, SetSpace + WriteRegisters +
    SetPriority(100) + SchedContextBind + Resume on each.
    Children loop `debug_put_char('H' or 'B') + yield`.
  * `launch_rootserver` enables PIT at 1000 Hz before dispatch
    so `mcs_tick` fires periodically.
  * Kernel exit hook samples 'H' / 'B' bytes after the IPC
    banner, exits at h+b ≥ 20 000 with summary
    `[MCS demo: NH MB]`. Observed split ≈ 2:1 (vs the 4:1
    budget split) because cooperative yield equalises CPU time
    *between* PIT IRQs — once SC_LOW exhausts and parks,
    SC_HIGH dominates until the next refill.

  Bugs surfaced + fixed along the way:
    * `pit_irq_entry` didn't save user-mode caller-saved
      registers (rax/rcx/rdx/rsi/rdi/r8-r11) before calling
      its Rust ISR — the ISR's call frame trashed user
      context, producing garbled `SysDebugPutChar` output and
      eventual fault loops. Added a save/restore around the
      ISR call.
    * `SysYield` re-enqueued the current TCB without
      dequeuing first — and `current` is *already* in the
      ready queue (admit/make_runnable/choose_thread all leave
      it there). The double-add corrupted the intrusive
      linked list. Fixed to dequeue → enqueue → clear current.
    * `decode_sched_control` read the target SC cap_ptr from
      `args.a0`, but `args.a0` in the SysSend path is always
      the *invoking* cap (the SchedControl). Moved target SC
      to `a2`, budget to `a3`, period to `a4`; updated the
      existing spec to match.
    * Rootserver page pool bumped 16 → 32 to fit the bigger
      .bss (HIGH_STACK + LOW_STACK + CHILD_STACK = 12 KiB).

## Out of scope (future)
* Replenishment scheduling on a wall clock vs scheduler ticks
  — we'll drive everything from PIT ticks, not nanosecond
  deadlines.
* MCS Reply caps (we keep the non-MCS reply path; the MCS reply
  shape is just a single capReplyPtr, no master, no TCB).
* Donation across IPC (the "scheduling-context-passing" feature
  where Call hands the caller's SC to the callee for the
  duration of the call).

## Verification
* AY / rootserver demos unchanged on each phase.
* New per-phase specs pass.
* Spec count rises by ~5-8.

## Review (filled on completion)


# Phase 31: ASID support — DONE

## Review

Promoted tags 11 (asid_control) and 13 (asid_pool) into typed
`Cap::AsidControl` and `Cap::AsidPool` variants, and wired the
two seL4 invocations:

  * `Cap::AsidControl` is a singleton root cap (no payload).
    `X86ASIDControlMakePool` carves 4 KiB out of an Untyped
    for pool storage and tags the new `Cap::AsidPool` with a
    fresh `asid_base` (kernel-side `NEXT_ASID_BASE` counter
    bumps by 512 — one pool's worth of ASIDs).
  * `Cap::AsidPool { ptr, asid_base }` lets userspace assign
    an ASID to a `Cap::PML4` (the vspace root). `Assign` writes
    `pool.asid_base + offset` into the PML4 cap's `asid` field;
    a second Assign on a non-zero-ASID PML4 surfaces
    `DeleteFirst`.

Phase 31 keeps the work at the cap-tracking level only —
hardware PCID integration (CR4.PCIDE + low-12-bits of CR3 +
INVPCID for selective TLB flush) is a follow-up. Today's CR3
swap unconditionally flushes the TLB; once PCID is plumbed,
threads with the same ASID will keep their TLB entries across
context switches.

Pre-existing `roundtrip_arch_passthrough` spec switched its
opaque-tag probe from 11 → 15 (io_space_cap) — 11 is now typed.

152 → 154 specs. AY / rootserver demos unchanged.

## Out of scope (future)
* Hardware PCID enable + INVPCID instructions.
* `asid_map[]` page contents — the AsidPool storage page is
  allocated but its 512 entries aren't yet read/written. With
  PCID-aware CR3 we'd track per-ASID metadata there.
* Reclaiming an ASID when its PML4 is freed.
* Cross-CPU ASID rebroadcast on Unmap (each CPU has its own
  TLB/PCID state).


# Phase 30: MDB linked-list — DONE

## Review

Replaced structural "compare physical addresses" cap-derivation
matching with a real MDB tree. Each `Cte` now records its
`mdb_parent: Option<MdbId>` (packed `(cnode_idx, slot)` → u16)
in the unused low 16 bits of `mdb_words[0]`.

Behavior:
* `Untyped::Retype` records each child's parent as the source
  Untyped's CTE id.
* `CNode::Copy` / `Mint` records the new cap's parent as the
  source slot.
* `CNode::Revoke` runs a fixed-point iteration over the
  `cnodes[]` table: any CTE whose parent is already revoked
  becomes revoked too. Sweeps until no progress, then clears
  every revoked slot except the source.
* `CNode::Delete` clears the parent edge along with the cap.

Workaround removed: the existing `cnode_revoke_zaps_descendants`
spec is back to using Endpoint children (pool-allocated outside
the Untyped's physical range — the case that broke structural
revoke and motivated this phase).

Spec count: 150 → 152.
  * `mdb_records_retype_parent_link` — every retyped child's MDB
    parent points back at the source Untyped's CTE.
  * `mdb_revoke_walks_grandchildren` — Retype→Endpoint then
    Copy that endpoint to a sibling slot. Revoking the original
    Untyped clears both the direct child AND the copy
    transitively.

Pool sizing: bumped `MAX_ENDPOINTS` 16 → 32 because the new
specs allocate more endpoints than fit before. (Pool entries
aren't reclaimed yet; that's an MDB-aware Delete improvement
for a follow-up phase.)

## Out of scope (future)
* Pool reclaim — Revoke / Delete should free pool slots so the
  bump allocator can wrap. Today next_endpoint et al. only grow.
* Doubly-linked prev/next list (we only track the parent edge;
  full seL4 MDB has prev/next siblings).
* Cross-CNode invariants under Move.


# Phase 29: ELF rootserver bootstrap

## Original goal (kept for context)
Replace structural cap-derivation matching (`is_derived_from`
comparing PPtrs) with a real linked-list MDB. Every CTE becomes
a node in a doubly-linked derivation tree:
  * `mdb_prev` / `mdb_next` — siblings in birth order.
  * `mdb_parent` — the CTE the cap was derived from (None for
    the root, e.g. the boot Untyped).

Then Revoke walks descendants exactly; Copy/Mint/Move re-link
the tree; Delete unlinks one node. No more "structural compare
paddrs" tricks, and the workaround in
`cnode_revoke_zaps_descendants` (had to switch from Endpoint to
Frame children because pool-allocated caps fall outside the
parent Untyped's range) goes away.

## Plan
- [ ] 30a — `MdbId(cnode_idx: u8, slot: u16)` packed identifier.
  Extend `Cte` with `prev`, `next`, `parent: Option<MdbId>`.
  Re-encode any code that allocates CTEs to start unlinked.
- [ ] 30b — Insertion helper `mdb_insert_after(parent, new)`.
  Used by `Untyped::Retype` (each new cap → child of source),
  `CNode::Copy / Mint / Mutate` (sibling of source), and any
  other path that creates a fresh cap.
- [ ] 30c — Removal helper `mdb_remove(node)`. Used by
  `CNode::Delete` and the slot-overwrite path.
- [ ] 30d — Tree walker `mdb_descendants(root, cb)`. Re-implement
  `cnode_revoke` on top of it.
- [ ] 30e — Drop `is_derived_from` + the structural revoke; the
  MDB walker is the source of truth.
- [ ] 30f — Tests:
    * Untyped retypes 4 endpoints, MDB shows them as siblings
      under the Untyped.
    * Copy of one endpoint adds a sibling-of-sibling.
    * Revoke of the Untyped clears all 5 (originals + copy).
    * Delete of the original endpoint removes only that node;
      the copy survives.

## Out of scope
* Cross-CNode MDB invariants under Move (we'll only support
  intra-CNode for now; cross-CNode Move just moves the cap
  bytes without re-rooting).
* MDB-aware Revoke for the rootserver demo (already works
  via the workarounds; switching it over is a follow-up
  cosmetic change).

## Verification
* All existing specs pass.
* New 30f specs cover the tree-walk shape.
* Boot output unchanged.

## Review (filled on completion)


# Phase 29: ELF rootserver bootstrap

## Goal
Mirror seL4's standard bootstrap. Today the kernel runs the
hand-asm AY demo at the end of `_start`. Phase 29 replaces that
with a real rootserver: an ELF binary built as a separate Rust
crate, loaded from memory by the kernel, granted an initial
CSpace + VSpace + BootInfo, and dispatched as the first user
thread.

End state:
* A separate `rootserver/` crate compiles to an ELF.
* The kernel embeds (or loads from BOOTBOOT initrd) the ELF.
* On boot, the kernel parses the ELF, builds the rootserver's
  VSpace + CSpace + BootInfo, dispatches the TCB.
* Rootserver runs in user mode, prints "hello from rootserver",
  retypes untypeds to spawn child workers (the "shell/init"
  shape), IPCs with them.
* A spec runs the same bootstrap path against an in-memory ELF
  fixture and verifies caps + mappings before reaching dispatch.

## Plan (incremental — one or more sessions per slice)

- [x] 29a — Separate `rootserver` crate. **DONE**
  * `rootserver/` — independent Cargo crate (no workspace).
  * Custom `triplet.json` (no `code-model: kernel`, separate
    `link.ld`).
  * `link.ld` puts text at 0x100_0040_0000 (PML4[2] +4 MiB) so
    we don't collide with BOOTBOOT's 1 GiB identity map.
  * `_start` prints "[rootserver alive]\n" via `SysDebugPutChar`
    then loops on `SysYield`. Hand-rolled syscall stubs in pure
    Rust (no_std).
  * `scripts/build_kernel.sh` builds rootserver first; kernel
    `include_bytes!`s the resulting ELF via `src/rootserver_image.rs`.

  * `rootserver/Cargo.toml` — no_std binary, x86_64 user-mode.
  * Tiny SYSCALL stub (rax=number, rdi..r9=args, syscall).
  * `_start` entry that issues `SysDebugPutChar` to print a
    sentinel byte, then loops on SysYield.
  * Linker script targeting a fixed user vaddr range.
  * Build artifact: `rootserver/target/.../rootserver` (ELF64).
  * `build.rs` (kernel side) `include_bytes!`-embeds the ELF.

- [x] 29b — ELF parser (subset). **DONE**
  * `src/elf.rs` — pure-Rust no_std parser. ELF64 LE x86_64
    only; rejects 32-bit / big-endian / non-x86_64 inputs.
  * `parse(bytes) -> Result<Image, ElfError>` returns entry
    RIP + iterator over `PT_LOAD` segments.
  * `LoadSegment { vaddr, file_off, file_size, mem_size, flags }`
    with `readable() / writable() / executable()` helpers.
  * Reads packed-struct fields via `addr_of!` + `read_unaligned`
    so we never deref a misaligned reference.
  * Specs: rejects bogus magic + class; embedded rootserver
    parses cleanly; entry matches `link.ld`; segments are
    well-formed (R always set, no W+X).

- [x] 29c — Segment loading + VSpace. **DONE**
  * `src/rootserver.rs` — `load() -> RootserverImage` parses
    the ELF, allocates pages from `ROOTSERVER_PAGE_POOL`
    (16 × 4 KiB in BSS), copies file data + zero-fills BSS
    tail, builds a fresh PML4 via `make_user_pml4`, and maps
    each segment with the right W bit.
  * Adds + maps a 4 KiB user stack page at
    `ROOTSERVER_STACK_VTOP - 0x1000`.
  * Spec `loads_and_maps_segments` runs the loader, asserts
    the entry RIP matches the ELF, the PML4 is non-zero +
    page-aligned, and at least `n_segments + 1` pages were
    consumed.

- [x] 29d+e — Rootserver TCB spawn + dispatch. **DONE**
  * `launch_rootserver()` loads the image, builds a TCB with
    the right user_context, demotes the boot thread, swaps
    CR3 to the rootserver's PML4, and `sysretq`s in.
  * `ROOTSERVER_DEMO_ACTIVE` flag + dispatcher hook in
    `rust_syscall_dispatch`: when the rootserver prints '\n'
    via `SysDebugPutChar`, log success + qemu_exit.
  * `bsp_main` now calls `launch_rootserver` instead of
    `launch_two_thread_ipc_demo` — the seL4-style bootstrap
    is the canonical boot path.
  * Boot serial output:
        [rootserver alive]
        [rootserver bootstrap complete — exiting QEMU]
  * 29d (BootInfo + initial caps layout) and 29g (workers via
    Untyped retype) deferred to follow-up phases.


- [x] 29d — BootInfo + initial caps. **DONE**
  * Loader allocates + maps an IPC buffer page at
    `ROOTSERVER_IPCBUF_VBASE` (0x100_0060_0000) and a BootInfo
    page at `ROOTSERVER_BOOTINFO_VBASE` (0x100_0070_0000) into
    the rootserver's PML4.
  * `launch_rootserver()` allocates the rootserver's CNode at
    `cnode_ptr(ROOTSERVER_CNODE_IDX=3)` and populates the
    canonical seL4 initial slots:
      0  Null
      1  TCB (self)
      2  CNode (self)
      3  PML4 (vspace root)
      9  Frame (BootInfo, R/O)
      10 Frame (IPC buffer, R/W)
      11 Untyped (16 KiB BSS pool)
  * `t.cspace_root` and `t.vspace_root` populated so any future
    invocation does cap lookup correctly.
  * `build_bootinfo()` writes the full `seL4_BootInfo` struct
    into the BootInfo page (kernel-virt mapping, before CR3
    swap): nodeID, numNodes, ipcBuffer vaddr, untyped slot
    region [11..12), the Untyped's paddr/sizeBits.
  * Rootserver `_start(bootinfo: *const BootInfo)` now reads
    the struct and prints
        "[rootserver alive] node 0/4, 1 untyped(s) of 16384 bytes\n"
    end-to-end through real Rust code in ring 3.
  * Codegen note: rootserver triplet now sets
    `code-model: large` so vaddrs above 32-bit don't overflow
    R_X86_64_32 relocations from `core::fmt`.
  * Loader handles overlapping PT_LOAD segments (lld may emit
    several R-only segments sharing a 4 KiB page); tracks
    seen pages in a fixed-size table to avoid double-allocation.
  * Mirror seL4's `seL4_BootInfo` shape (existing in types.rs);
    populate with: nodeID, numNodes, ipcBuffer vaddr, untyped
    list, slot ranges.
  * Allocate the rootserver's CNode (1 << ROOT_CNODE_BITS).
  * Populate slot 0 = NullCap, slot 1 = TCB cap (self), slot
    2 = CNode cap (self), slot 3 = VSpace cap, slot 4 = IPC
    buffer Frame cap, slot 5 = BootInfo Frame cap, then each
    free memory region as an Untyped cap from slot N onwards.
  * Map the BootInfo page so the rootserver can read it.

- [ ] 29e — TCB spawn + dispatch.
  * Build TCB: priority=255 (top), vspace_root = the new PML4
    cap, cspace_root = the new CNode cap, user_context entry =
    ELF entry RIP, rsp = top of allocated user stack page.
  * `cpu_context.cr3` = PML4 paddr.
  * Replace `launch_two_thread_ipc_demo` with a new
    `launch_rootserver` that does the above + calls
    `enter_user_via_sysret` on the rootserver's UserContext.
  * Boot output: "[rootserver hello]" or similar, then qemu_exit.

- [ ] 29f — Spec end-to-end.
  * In-memory ELF fixture (reuse the rootserver bytes).
  * Spec: parse ELF, allocate pages, build vspace+cspace, verify
    cap slots populated correctly, verify BootInfo struct fields.
  * Doesn't actually dispatch — just stops at "ready to dispatch"
    so the spec runner stays in kernel mode.

- [x] 29g — Rootserver retypes Untyped → Endpoint via SysSend. **DONE**
  * Rootserver-side syscall stubs include a `syscall5` that
    matches the kernel's invocation ABI (rdi=cap_ptr,
    rsi=MessageInfo, rdx=arg0, r10=arg1, r8=arg2).
  * High-level `untyped_retype()` helper wraps it.
  * `_start` now invokes `Untyped::Retype` on its 16 KiB
    Untyped (slot 11), writes one Endpoint into slot 12,
    and prints the result.
  * Kernel's exit hook updated to fire on the SECOND newline
    so the alive banner + retype result both land on serial.
  * Boot output:
        [rootserver alive] node 0/4, 1 untyped(s) of 16384 bytes
        [rootserver retyped Untyped -> Endpoint at slot 12 - bootstrap complete]
        [rootserver bootstrap complete — exiting QEMU]
  * End-to-end exercise of the userspace cap-allocation path:
    SYSCALL → swapgs → BKL → cspace_lookup → decode_invocation
    → decode_untyped_retype → write into rootserver CNode →
    sysretq with rax=0.

- [x] 29h — Spawn a child TCB, IPC over the new endpoint. **DONE**
  * Rootserver retypes its Untyped → TCB at slot 13, then issues
    `TCB::SetSpace(child=13, cnode=2, vspace=3)` (child shares
    rootserver's CSpace + VSpace), `TCB::WriteRegisters` to point
    rip at `child_entry`, `TCB::Resume` to make it runnable.
  * Rootserver `SysRecv`s on slot 12. Child runs `child_entry`,
    sends 0xCAFE over the endpoint, yields. Rootserver wakes
    and prints "[rootserver got 0xcafe from child]".
  * Required several kernel-side fixes:
      - `decode_untyped_retype` post-processes emitted caps for
        kernel-pool-backed types (TCB / Endpoint / Notification /
        CNode) — admit a real object into the kernel pool, encode
        the pool index into the cap's PPtr.
      - New bump allocators: `KernelState::alloc_endpoint /
        alloc_notification / alloc_cnode`.
      - `endpoint::transfer` now fans the IPC payload into the
        receiver's `user_context` immediately, so the receiver
        gets the message in registers regardless of which side
        was waiting first.
      - `SysYield` now actually rotates (under the rootserver
        demo flag, to avoid tripping spec teardowns that leave
        stale priority-bitmap state).
      - `is_derived_from` extended to recognise Frame / PT / PD /
        PDPT / PML4 children of an Untyped parent.
      - Existing CNode::Revoke spec switched from Endpoint
        children (now pool-allocated, outside the Untyped's
        physical range) to Frame children whose PPtr is still
        the carved paddr.
  * Boot output:
        [rootserver alive] node 0/4, 1 untyped(s) of 16384 bytes
        [rootserver retyped Untyped -> Endpoint at slot 12]
        [rootserver got 0xcafe from child]
        [rootserver bootstrap complete — exiting QEMU]

## Out of scope (future phases)
* Multi-segment ELF dynamic linking (we only handle static-PIE).
* Loading rootserver from BOOTBOOT initrd (we embed via
  `include_bytes!` for now).
* Multiple init processes / Linux-style fork.
* The rootserver implementing a real filesystem / networking.
* Shutting down / killing the rootserver.

## Verification
* AY demo retired; new rootserver path runs at boot.
* Rootserver's user-mode `SysDebugPutChar` reaches serial.
* 29f spec covers the bootstrap data layout.
* Spec count rises by ~3-5.

## Review (filled on completion)


# Phase 28: SMP / AP CPU bring-up

## Goal
BOOTBOOT already starts every CPU in long mode at `_start` —
no trampoline / INIT-SIPI-SIPI needed. `main.rs` already has
the BSP/AP split (BSP runs init, APs `halt_cpu`). This phase
turns AP halts into a real per-CPU init path, so every CPU
ends up sitting in a scheduler loop ready to run threads.

What's already in the repo:
* `main.rs:117-181` — `_start` runs on all cores. BSP (matched
  via APIC ID == BOOTBOOT BSP ID) does init + spec runner; APs
  call `arch::halt_cpu()` and loop.
* `src/smp.rs` — `PerCpu<T>`, `NodeState`, `IpiKind`, signal +
  handle IPI bookkeeping (gated behind `smp` feature, BSP-only
  specs today).
* `arch/x86_64/acpi.rs` — MADT walker producing `LocalApic`
  entries; can enumerate APs.
* `arch/x86_64/lapic.rs` — LAPIC reads work today; ICR write
  for IPIs is missing.
* QEMU launch is `-smp 1` (default). Bring-up testing needs
  `-smp 4` in `scripts/run_specs.sh`.

## Plan (incremental — one session per slice)
- [x] 28a — Per-CPU init + AP barrier. **DONE**
  * Always-on `smp` module (feature gate removed).
  * GDT extended to hold MAX_CPUS TSS descriptors. Selector for
    CPU N is `TSS_SEL_BASE + N * 0x10`. Per-CPU TSS array in BSS.
  * `init_gdt_for_cpu(cpu_id)` populates GDT on BSP, just loads
    on APs; each CPU `ltr`s its own slot and writes its own
    rsp0. `set_kernel_rsp_for_cpu(cpu_id, rsp)` for per-CPU
    rsp0 updates.
  * `ap_main`: spins on `BSP_READY` → `init_gdt_for_cpu(cpu_id)`
    → `load_idt` → `init_syscall_msrs` → `mark_ap_alive` → HLT
    loop.
  * BSP barriers on `wait_for_aps(numcores - 1)` before specs /
    demo. Serial shows "Waiting for APs..." → "All APs up".
  * `scripts/run_specs.sh` runs QEMU with `-smp 4`.
  * Spec: `all_aps_came_up` asserts `APS_ALIVE == numcores - 1`.

- [x] 28b — Big kernel lock (BKL). **DONE**
  * `smp::BKL: AtomicU32` — 0 = free, else holder cpu_id + 1.
  * `bkl_acquire()` spins on cmpxchg; `bkl_release()` stores 0.
  * `BklGuard` RAII helpers in `syscall_entry.rs`,
    `exceptions.rs`, `pit.rs` — `bkl_acquire()` then
    `let _bkl = BklGuard;` releases on any return path.
  * Wrapped: `rust_syscall_dispatch`, `handle_page_fault_typed`,
    `pit_isr`. (Other exception handlers are panic-fatal —
    they don't release.)
  * Spec: `bkl_acquire_release_round_trip` confirms holder
    encoding + repeat-acquire.
  * Known follow-up for 28c: `SYSCALL_SAVE` and
    `SYSCALL_KERNEL_RSP` are still global statics; once APs
    run threads they need to be per-CPU (likely via GS_BASE
    + a per-CPU struct).

- [x] 28c — Per-CPU NodeState + runqueues. **DONE**
  * New `SchedulerNode { queues, current, idle }` per CPU.
  * `Scheduler { slab, nodes: [SchedulerNode; MAX_CPUS] }`.
  * `Tcb.affinity: u32` field — `admit()` enqueues onto
    `nodes[affinity]`. Defaults to BSP (0).
  * Helpers: `current()`/`set_current()` route through
    `crate::arch::get_cpu_id()`; `current_for_cpu(cpu)`/
    `set_current_for_cpu` for cross-CPU access.
  * `choose_thread()` / `should_preempt()` / `tick()` operate
    on the calling CPU's node.
  * All ~28 call sites in fault.rs, kernel.rs, syscall_handler.rs,
    syscall_entry.rs, usermode.rs, scheduler.rs/spec migrated
    from `s.scheduler.current = X` to
    `s.scheduler.set_current(X)`.
  * Spec: `per_cpu_queues_are_isolated` admits with affinity 0
    and 1, asserts both queues hold the right counts.
  * Behavioral parity: under -smp 4, all threads still run on
    BSP (every TCB gets affinity=0 from `Tcb::default`); APs
    remain in HLT until 28d/e wire them into the scheduler.

- [x] 28h — AP dispatches user threads end-to-end. **DONE**
  * `ap_scheduler_loop` now wires per-CPU `SYSCALL_KERNEL_RSP`
    + `TSS.rsp0` from its boot stack, then in each iteration
    dispatches `current` via `enter_user_via_sysret` (with
    optional CR3 swap) when the TCB has `cpu_context.cr3 != 0`.
  * `cpu_context.cr3 != 0` gate prevents bare scheduler-test
    TCBs from accidentally getting dispatched into RIP=0.
  * `usermode::launch_smp_ping_thread()` builds an AP1-pinned
    TCB whose user code loops on `SysYield`. BSP calls this
    + `kick_cpu(1)` to start the ping thread.
  * `smp::SYSCALL_COUNT_PER_CPU[]` per-CPU atomic — bumped in
    `rust_syscall_dispatch` after BKL acquire — gives the BSP
    a way to observe AP execution without touching BKL.
  * Spec `ap_dispatches_user_thread_end_to_end` admits the ping
    thread, kicks AP1, polls until AP1's syscall count climbs
    past 64. The ping thread keeps running on AP1 throughout
    the AY demo on BSP — true parallel SMP execution.

- [x] 28g — TLB shootdown on Frame::Unmap. **DONE**
  * `usermode::unmap_user_4k_public(vaddr)` walks the live PML4,
    clears the PTE, `invlpg`s the calling CPU.
  * `smp::shootdown_tlb(vaddr)` fans `InvalidateTlb { vaddr }`
    IPIs to every other CPU. The IPI ISR runs `invlpg` on each.
  * `decode_frame_unmap` now reads `cap.mapped` before clearing,
    invokes the local unmap + remote shootdown when `Some(vaddr)`.
    Spec mode skips the hardware step (no real PML4).
  * Spec: `shootdown_fans_invalidate_tlb_to_aps` — BSP shoots down
    a no-op vaddr; the IPI counter advances by N_APs.

- [x] 28f — Per-CPU SYSCALL_SAVE / KERNEL_RSP via swapgs. **DONE**
  * `PerCpuSyscallArea { kernel_rsp, _pad, user_ctx }` —
    `static mut PER_CPU_SYSCALL: [PerCpuSyscallArea; MAX_CPUS]`.
  * `init_per_cpu_gs()` (called from `init_syscall_msrs`) sets
    `IA32_KERNEL_GS_BASE` to the calling CPU's slot.
  * The naked SYSCALL stub does `swapgs` first thing, addresses
    saves/restores via `gs:[16 + reg_offset]` and the kernel
    stack via `gs:[0]`, then `swapgs` before `sysretq`.
  * `rust_syscall_dispatch` no longer takes a ctx pointer arg —
    recovers its `&mut UserContext` via `current_cpu_user_ctx_mut()`
    (= `&mut PER_CPU_SYSCALL[arch::get_cpu_id()].user_ctx`).
  * `set_syscall_kernel_rsp(rsp)` updates the calling CPU's slot.
  * Spec: `per_cpu_kernel_gs_base_set` — BSP's MSR points at its
    own slot in the array.
  * APs can now safely SYSCALL without corrupting BSP's save area;
    Phase 28+ work can put threads on AP queues + actually
    dispatch them.

- [x] 28e — AP scheduler loop. **DONE**
  * `ap_main` now calls `ap_scheduler_loop` instead of
    `loop { halt_cpu }`. Each iteration takes the BKL, lets the
    scheduler observe `current`, releases BKL, then `sti; hlt`
    until the next IPI / IRQ.
  * IPI ISR: `Reschedule` runs `choose_thread()` on the target's
    per-CPU node and stores the result in `set_current()`.
    `InvalidateTlb { vaddr }` runs `invlpg`. `Stop` halts the
    AP forever.
  * `smp::kick_cpu(target_cpu)` convenience wrapper around
    `send_ipi(target_cpu, Reschedule)`.
  * Spec: `ap_picks_thread_off_its_queue_via_reschedule` — BSP
    admits a TCB with `affinity=1`, `kick_cpu(1)`, polls
    `current_for_cpu(1)` until it equals the admitted TCB.
  * Still TODO (Phase 28f): per-CPU `SYSCALL_SAVE` /
    `SYSCALL_KERNEL_RSP` so APs can actually dispatch user
    threads. Today the AP picks a thread but doesn't run it.

- [x] 28d — Cross-CPU IPI driver. **DONE**
  * `IPI_VECTOR = 0x40` in `smp.rs`. `ipi_irq_entry` naked
    stub in `lapic.rs` calls `ipi_isr` which acquires BKL,
    drains via `handle_ipis`, EOIs, releases.
  * `smp::send_ipi(target_cpu, kind)` registers the cause in
    `IPI_NODES[target_cpu]` then writes the LAPIC ICR. Caller
    holds BKL while signaling.
  * `IPI_NODES: PerCpu<NodeState>` is the always-in-BSS,
    BKL-protected per-CPU bookkeeping (separate from the
    `SchedulerNode` array — they'll merge in a later phase).
  * BSP path now calls `install_kernel_page_tables` +
    `init_lapic` directly (was only via the paging spec).
  * AP path adds `init_lapic` to the per-CPU init sequence.
  * Per-CPU EFER bits: `init_syscall_msrs` now also sets
    `EFER.NXE` so APs walking the LAPIC PTE (bit 63 = NX)
    don't trip a reserved-bit fault.
  * Spec: `cross_cpu_ipi_delivers_and_runs_isr` — BSP fires
    Reschedule IPI to AP1, polls `IPI_HANDLED_COUNT` and
    confirms AP1's pending bitmap drained.

## Out of scope (later phases)
* Fine-grained locking (replace BKL with per-subsystem locks).
* Cross-CPU thread migration via cap invocations.
* TLB-shootdown IPI integration with vspace ops.
* aarch64 SMP — different bring-up sequence.
* CPU hotplug.

## Verification
* AY demo unchanged on each phase.
* Per-phase specs pass under `-smp 4`.
* Phase 28a: serial shows "all APs up: 3"; APs idle in HLT.
* Phase 28b: stress under `-smp 4` stays correct.

## Review (filled on completion)


# Phase 27: PML4Cap + userspace vspace swap — DONE

## Goal
Type the apex paging cap (PML4 — tag 9). Today PML4 falls
through `Cap::Arch`; the kernel allocates and CR3-swaps PML4s
internally via `make_user_pml4`. With a typed cap, userspace can
own its vspace root, hand a PML4 cap to a TCB via SetSpace, and
have the syscall return path swap CR3 to it on resume.

## Plan
- [x] 27a — `Cap::PML4` typed variant + tag 9 round-trip
  through the generated `Pml4Cap` bitfield.
- [x] 27b — `Untyped::Retype` produces PML4 caps via new
  `object_type::X86_PML4 = 13` (4 KiB per PML4).
- [x] 27c — `TCB::SetSpace` accepts a Cap::PML4 vspace-root and
  writes its physical address into `tcb.cpu_context.cr3`. The
  syscall return path already loads CR3 from there before
  sysretq. Non-PML4 vspace caps surface InvalidCapability.
- [x] 27d — Specs cover round-trip + Retype-to-PML4 + SetSpace
  pointing a TCB at a fresh PML4 (and rejecting a non-PML4 cap).

## Out of scope
* Hardware CR3 swap test from spec mode (no real PML4 page
  to load — the spec just verifies the cap value lands in the
  TCB context).
* ASID pool / ASID control caps (tags 11/13) — separate phase.
* Replacing `make_user_pml4`'s PML4-clone helper. The new typed
  cap lives alongside it; the AY demo continues to use the
  helper.

## Verification
* AY demo unchanged. ✓
* New SetSpace-pins-CR3 spec passes; PT/PD/PDPT/PML4 round-trip
  + Retype specs extended to cover PML4. ✓
* Spec count: 133 → 134 (the round-trip and retype bullets each
  gained a PML4 sub-case in place).

## Review

Phase 27 was clean — `Cap::PML4` slotted into the same shape as
PT/PD/PDPT (typed variant, tag 9, X86_PML4=13). The interesting
piece was extending `TCB::SetSpace` to consume a Cap::PML4 and
write `ptr.addr()` straight into `tcb.cpu_context.cr3`, since
the syscall return path already CR3-swaps from there before
sysretq. With a typed PML4, that path becomes user-driven instead
of relying on `make_user_pml4` (which the AY demo still uses
internally — no need to retire it yet).

No codegen surprises this round — the field_high fix from Phase
26 already made `capPML4BasePtr` (a plain `field 64`) round-trip
the full pointer cleanly.

# Phase 26: PageTable cap chain — DONE

## Goal
Type the rest of the x86_64 paging caps. Currently
PageTable / PageDirectory / PDPT caps fall through to the
opaque `Cap::Arch` variant. Promote them to typed variants and
wire up Map/Unmap invocations so userspace can manage page
tables explicitly (instead of relying on auto-allocation in
ensure_user_table).

## Plan
- [x] 26a — `Cap::PageTable` / `PageDirectory` / `Pdpt` typed
  variants. Round-trip via the generated `PageTableCap` /
  `PageDirectoryCap` / `PdptCap` bitfields.
- [x] 26b — `Untyped::Retype` produces them via new
  `object_type::X86_PAGE_TABLE / X86_PAGE_DIRECTORY / X86_PDPT`
  values (10, 11, 12 — extending the X86_4K/2M/1G range from
  Phase 19).
- [x] 26c — `decode_invocation` for each: `X86PageTableMap`,
  `X86PageDirectoryMap`, `X86PDPTMap` install the cap into the
  target paging structure. (Unmap variants get plumbing but no
  hardware action yet — they just clear the mapped flag in the
  cap.)
- [x] 26d — Specs cover round-trip + Retype + Map of one PT.

## Out of scope
* Actual page-table-walk integration. Today's
  `usermode::ensure_user_table` auto-allocates intermediate
  tables on demand; with explicit caps the user could chain
  them, but we don't need that for the AY demo.
* PML4Cap (the user's vspace root) — currently kernel-managed.

## Verification
* AY demo unchanged. ✓
* New round-trip + invocation specs pass. ✓
* Spec count rose by 3 (paging round-trip, retype-to-PT-chain,
  PT::Map/Unmap).

## Review

Phase 26 completed. While wiring up the typed caps we hit a real
codegen bug: `field_high` was being treated as a regular plain field
(no shift), so PT/PD/PDPT mapped-address fields would silently
truncate the high bits and round-trip to `mapped=0`. Fixed in
`build_support/bf.rs`: now parses `base 64(N,M)` properly and bakes
the active canonical_size into each `field_high` shift expression.
Existing call-sites in `arch/x86_64/vspace.rs` that pre-shifted
`paddr >> PAGE_BITS_4K` had to drop the manual shift; the codegen
handles alignment now. Captured as a lesson in tasks/lessons.md.

## Next candidates
* AP CPU bring-up (multi-core SMP).
* MCS scheduler integration (refill_charge tied to live PIT tick).
* Real BootInfo + ELF init thread (replacing the AY demo with a
  proper rootserver).
* PML4Cap (typed vspace-root cap so SetSpace can swap CR3 from
  userspace).
* MDB linked-list to replace structural Revoke.
* aarch64 hardware bring-up.
