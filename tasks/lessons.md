# Lessons captured this session

## Pattern: rootserver constants silently drift from the kernel's codegen

Symptom — the microtest suite regressed (child_send "wrong payload", reply_cap
"reply payload mismatch", register tests "rip/rax mismatch", ipc_extra_cap_staging
#PF, and the two-thread SURT test hung). ALL of it traced to the *rootserver*
carrying hardcoded constants that no longer matched the kernel, NOT a kernel bug.
The kernel was correct throughout; only the userspace rootserver was stale.

Three independent drifts, each masked because `rax` is preserved across SYSCALL
(so the rootserver's `if r != 0` success checks are meaningless — the kernel
signals errors via IPC/faults, never rax):

1. **Boot cap layout grew** (df8c734's runtime user-page region added frame
   caps): `BootInfo.empty.start` moved from ~21 to **45**, but the harness
   hardcoded `FIRST_EMPTY_SLOT=21` / `NEXT_SLOT=24`. Every retype targeted an
   OCCUPIED slot → `seL4_DeleteFirst` → no object created → the "endpoint" cap
   was a stale non-endpoint → Recv returned InvalidCapability instantly (never
   blocked) → children never scheduled. FIX: allocate from `BootInfo.empty.start`.

2. **Invocation labels renumbered** (upstream-ABI alignment): kernel codegen has
   `SchedControlConfigureFlags=37, SchedContextBind=38, CNodeCopy=25,
   IRQIssueIRQHandler=30, IRQSetIRQHandler=32`, but the rootserver still used
   33/34/21/26/28. So `spawn_child`'s SchedContext bind was misrouted → child
   had no SC → `is_schedulable()` (= runnable && sc.is_some()) false → never
   enqueued. FIX: match the generated `out/invocations.rs` values.

3. **WriteRegisters/ReadRegisters ABI**: kernel reads `count` from `mr1` (a3)
   and `rip/rsp` from `mr2/mr3` (a4/a5); the tests sent the OLD layout
   (a4=count) → count read as 0 → zero registers written → worker ran at
   `rip=0` and #PF'd. Also the reply server passed its reply cptr in r10, but
   MCS reads it from **r12** → no reply bound → caller hung. FIX: match the
   handlers in src/invocation.rs.

**Under MCS, a spawned worker that must run on its own needs a bound
SchedContext** (retype SC → SchedControl::Configure budget==period round-robin
→ SchedContext::Bind → Resume). A no-SC TCB is Resume-able but never dispatched;
plain SYS_SEND does NOT donate an SC (only Call/NBSendRecv/NBSendWait do).

**Rule for myself**: when a rootserver invocation "succeeds" (r==0) but has no
effect, suspect a stale constant, not kernel logic — rax is preserved, so r==0
proves nothing. Cross-check EVERY hardcoded label against
`target/.../out/invocations.rs`, every object-type against object_type.rs, and
derive slot numbers from `BootInfo.empty.start`, never a literal. Debug by
gating kernel-side `arch::log_n` on the invoker's priority (rootserver = 255).


## Pattern: large statics blow the BOOTBOOT default stack

Symptom — `Scheduler` (~10 KiB) on the spec stack triple-faulted
under the BOOTBOOT default 4 KiB stack. BOOTBOOT actually capped
my `initstack = 65536` request at 16 KiB. A single Scheduler fits
in 16 KiB but each `#[inline(never)]` test that constructs one
needs its own slot, and release-mode inlining merged them into
one frame's worth of stack space exceeding the budget.

Fix — `MAX_TCBS = 16` (down from 64) keeps the Scheduler ~4 KiB so
inline-merging across spec functions still fits.

Rule — when a static or stack-allocated kernel struct contains
`[Option<T>; N]` arrays, count `N * sizeof(Option<T>)` against the
target stack; bump `#[inline(never)]` on each spec function that
constructs one, and double-check the boot output's reported
"Stack size" line to know what the loader actually gave us.

## Pattern: BOOTBOOT MMIO behaviour

- Low physical memory IS identity-mapped (we read CR3-based PML4
  through its physical address).
- The `mmio` symbol's virtual range is **reserved** but **not
  populated** with mappings — driver code has to install its own.
- BOOTBOOT uses 1 GiB pages for the low-memory identity map. A
  4 KiB walk into PML4[0] hits a `PS=1` PDPT entry and clobbers
  if you treat it as a sub-table pointer. Pick user vaddrs in
  PML4[2] or higher to avoid the clash.

## Pattern: codegen `new()` argument order

`block foo` without an explicit parameter list (`block foo(a, b)
{ ... }`) generates `Foo::new(args...)` taking arguments in
**declaration order of visible fields**. With explicit params, the
order is the parameter list. I caught this by writing
`NotificationCap::new(badge, can_recv, can_send, ptr, type)` —
the actual order is `(badge, type, can_recv, can_send, ptr)`. The
mis-ordered call stored `type=NOTIFICATION` into the pointer
field, and reading the cap back gave non-Notification garbage.

Rule — when calling a generated `Cap::new(...)`, always reread the
.bf source to confirm whether explicit params exist. If not, count
the visible fields top-to-bottom in declaration order.

## Pattern: kernel needs the user half too on cloned PML4s

Symptom — first cut of `make_user_pml4` zeroed PML4 entries
0..256 and copied 256..512 from the live PML4. After CR3 swap to
the cloned PML4, the very next page-table walk inside the kernel
faulted. Cause: BOOTBOOT installs its low-memory identity map at
PML4[0] (in the user half), and the kernel relies on it to
dereference physical addresses (page tables it walks, ACPI tables
it reads, the LAPIC mapping at `mmio` etc.). With PML4[0] zeroed
in the new PML4, kernel code under that CR3 can't reach those.

Fix — copy ALL 512 PML4 entries verbatim. User isolation in our
setup comes from each thread's PML4[2] sub-tree being independent
(allocated separately by ensure_user_table). Two threads can
share PML4[0]'s identity map without sharing user-mode mappings,
because their user PAGES live in different PML4 entries.

Future cleanup — relocate the identity map to a PML4 entry in
the kernel half (e.g. PML4[256]) so the user half can be entirely
empty. Then every PML4[user-half] is a fresh allocation and we
can trust "if it's in the user half it's user-private."

## Pattern: scheduler-queue staleness across spec teardowns

Symptom — Phase 22 spec panicked at `TcbSlab::get_mut on empty
slot`. Cause: a previous spec's teardown freed TCBs that were
still linked into `scheduler.queues.heads/tails` (made_runnable
had enqueued them). The next test's `admit` re-used the freed
slot but `enqueue` followed the stale `tails[prio]` pointer to
walk an empty slot. Panic.

Fix — when a spec admits TCBs and frees them, the next spec must
reset `scheduler.queues = ReadyQueues::new()` before any new
`admit`. Better long-term: implement a proper TCB destructor that
dequeues before freeing — but skipping that is fine for spec
isolation as long as we wipe queues per test fixture.

Rule — a test fixture that touches the global Scheduler must
own clean-up of *both* the slab AND the per-priority queues.
Just freeing the slot leaves the queue inconsistent.

## Pattern: `field_high` in the .bf codegen

Real seL4's `bitfield_gen.py` treats `field_high N` as "store the
high N bits of a canonical-size value" — the codegen generates a
shift = `canonical_size - N` so the low bits drop out on write and
get re-zeroed (and sign-extended) on read. Our local `build_support/bf.rs`
originally ignored that and just stored the raw low N bits, which
made anything sized below the canonical width un-roundtrippable.

Symptom — Cap::PageTable round-trip threw away mapped-address bits
above the 28-bit storage. PT caps round-tripped to mapped=0 even
though `is_mapped` was set.

Fix — bf.rs now (a) parses the `base 64(N,M)` directive instead of
filtering it in the preprocessor, and (b) bakes the active
canonical_size into each `field_high` field's shift expression.
Existing call-sites that pre-shifted (`paddr >> PAGE_BITS_4K` into
`with_page_base_address`) had to drop the manual shift, since the
codegen does it now.

Rule — when adding bitfield types (esp. PTE-shaped or pointer-shaped
fields under a different `base` directive), trust `field_high` to
encode alignment for you. Don't shift externally; do shift the test
expectation back to the *full* address, not paddr >> bits.

## Pattern: per-CPU MSRs need explicit setup on every CPU

Symptom — under SMP, AP triple-faulted with err=0xa (reserved-bit
set) when writing to the LAPIC MMIO. cr2 pointed at a valid
mapping that BSP could reach. Cause: BOOTBOOT sets EFER.NXE=1
on the BSP, but APs come up with NXE=0. When BSP installed a
PTE with bit 63 (NX) set into the shared kernel PML4, AP saw
bit 63 as reserved during the page-table walk and #PF'd.

Fix — `init_syscall_msrs` now ORs in `EFER_NXE` alongside
`EFER_SCE`. APs run that as part of their per-CPU init.

Rule — when BOOTBOOT (or any bootloader) configures EFER, MTRRs,
PAT, or other per-CPU MSRs on the BSP, **assume APs come up with
the architectural defaults**. Replicate every per-CPU MSR write
in the AP init path. The BSP-only-ran-it bugs surface only under
SMP and as cryptic page faults.

## Pattern: gate AP dispatch on a "ready to run user code" predicate

Symptom — once `ap_scheduler_loop` started actually dispatching
threads via `enter_user_via_sysret`, the previous (passing) spec
`ap_picks_thread_off_its_queue_via_reschedule` regressed:
admitted a bare `Tcb::default()` (with `user_context.rcx = 0`,
`cpu_context.cr3 = 0`); IPI ISR set `current=Some(it)`; AP1's
loop body raced BSP's cleanup, dispatched the bare TCB,
`sysretq` landed at RIP=0 → user `#PF` on BOOTBOOT's NX-marked
identity-map → fatal "USER #PF with no current TCB".

Fix — gate dispatch on `tcb.cpu_context.cr3 != 0`. A real
user-mode thread must have a populated VSpace; a bare TCB used
by scheduler-only specs to test queue mechanics doesn't, and
`ap_scheduler_loop` now skips dispatch and HLTs.

Rule — when you make a code path do a *real* user-mode entry,
audit specs that admit bare TCBs to make sure none of them race
your new entry path. Any TCB observable as "current" on a CPU
must either be fully launchable, or the predicate that runs the
launch path must filter it out.

## Pattern: x86_64 calling-convention plumbing

- The `extern "C"` (System V) ABI puts the first arg in `rdi`,
  not `rax`. When wiring a SYSCALL stub, save user `rax` somewhere
  before invoking the Rust dispatcher; the dispatcher's first
  argument should arrive in `rdi`.
- SYSCALL clobbers `rcx` (saves user RIP) and `r11` (saves
  RFLAGS); on entry, save these to a UserContext FIRST.
- SYSRETQ does NOT restore RSP — the kernel must `mov rsp, ...`
  before issuing it.
- `#[unsafe(naked)]` functions cannot have a Rust prologue; every
  instruction is yours. Use `core::arch::naked_asm!`, not `asm!`.

## Pattern: stale-binary runs after a failed build (recurred 2026-06)

Symptom: a QEMU run shows behavior that contradicts the code just
written (e.g. new log lines absent but the failure still present).
Root cause: `build_kernel.sh` failed (compile error) but the
follow-on `make_image.sh && run_specs.sh` still executed, booting
the PREVIOUS kernel binary.

Rules:
- Chain build → stage → image → run with `&&`, never `;`. A failed
  build must make the whole pipeline stop.
- When a chain is backgrounded, the FIRST thing to check in its
  output is the build's exit code, before interpreting any test
  results.
- If expected new log markers are missing from a run, assume stale
  binary first — verify build success before debugging "the bug".

## Pattern: SC-donation passive-server rework is a deep, coupled change (2026-06-08)

Attempted the MCS passive-server / SC-donation rework to unblock
IPC0011-0024,0027 (saved as tasks/sc-donation-wip.patch). Findings:
- The model is right: schedulable = runnable && sc != NULL; donation
  MOVES the sc (caller->sc = None, callee->sc = sc) via a
  schedContext_donate equivalent; reply returns it. An explicit
  per-TCB `enqueued` flag (queue membership source of truth) cleanly
  fixes the "infer enqueued from state+sc" fragility that otherwise
  corrupts the intrusive ready-queue when blocking/freeing passive
  threads.
- BUT it's broadly coupled: changing make_runnable/block to gate on
  schedulability touches EVERY thread lifecycle path, including the
  notification-bound SC-donation path used by INTERRUPT0002 (which
  REGRESSED to a hang). And IPC0016 (simplest donation test) still
  hung in setup — the client's Call never reached finish_call, root
  cause not isolated (needs make_runnable/choose_thread/Send-block
  tracing under a live run).
- Lesson: land this behind a verified, incremental sequence — first
  the `enqueued` flag alone (prove 88/88 still green), THEN
  is_schedulable gating, THEN donation, re-running the FULL gate after
  each step. Don't stack all of it before the first gate run. Also:
  any change to make_runnable/block MUST be validated against
  INTERRUPT0002 (notification SC donation) and the full gate, not just
  the target IPC tests.
- Reverted to keep the verified 88/88 (commit 75964a0); WIP patch
  retained for a future focused attempt.

## Pattern: build_kernel.sh rewrites disk.img — never run it during a live gate (2026-06-08)

build_kernel.sh compiles the kernel AND regenerates .tmp/disk.img.
Running it while a gate QEMU is still executing rewrites the image the
gate booted from; the in-flight run wedges (observed: a full gate
stalled mid-suite at SCHED0014 with two qemu processes alive).
Rule: finish or kill the running gate before invoking build_kernel.sh,
or do code edits + builds first and only launch the gate once no other
QEMU is running. When iterating on a fix while a long gate runs, edit
source freely but DON'T rebuild until the gate is done.

## Stale-kernel trap (2026-06-26)
SYMPTOM: trace edits produced ZERO output even when present in source;
kernel binary mtime was OLDER than the edited source.
CAUSE: a compile error (e.g. E0425 from a sloppy trace edit) made the
cargo build inside build_kernel.sh fail. build_kernel.sh exits before
its make_image step, but my run commands chained with `;` (not `&&`)
then ran `cp rootserver.elf && make_image && run`, re-bundling the
STALE kernel with a fresh driver. Result: hours of meaningless traces
on an old kernel.
RULES:
- After build_kernel.sh, VERIFY freshness before trusting a run:
  `stat -f %m target/mykernel-x86/release/mykernel-rust` must be NEWER
  than your edited source, OR grep a unique trace marker in the binary:
  `strings target/.../mykernel-rust | grep -c "<my-marker>"`.
- Chain build+run with `&&`, and gate on build_kernel rc explicitly.
- Keep trace edits COMPILABLE (watch variable scopes); a broken trace
  build silently runs the previous kernel.

## gen_config.h regex edits need a forced driver recompile (2026-06-27)
Editing vendor/sel4test/build/.../gen_config/sel4test/gen_config.h
(CONFIG_TESTPRINTER_REGEX) then running ninja does NOT reliably
recompile sel4test-driver/src/main.c (which #includes it) — ninja's
dep tracking sometimes misses the header change, so the OLD regex
stays baked into the driver binary and the wrong tests run.
RULE: after editing the regex, `touch
vendor/sel4test/projects/sel4test/apps/sel4test-driver/src/main.c`
before ninja, and VERIFY the new regex is in the binary:
  strings vendor/sel4test/build/apps/sel4test-driver/sel4test-driver \
    | grep TESTPRINTER-or-your-regex

## Viability-gate before big subsystem work (2026-06-28)
Before implementing a feature whose payoff depends on the emulator, write a
cheap boot probe FIRST. Settled two calls this session:
- HW-debug: boot probe set a DR + confirmed QEMU 11 TCG delivers #DB → built it (now 8 tests pass).
- PCID (to fix DOMAINS CR3-flush slowness): probe + QEMU stderr showed "TCG doesn't
  support requested feature: ...pcid" → CPUID.PCID=0 even with -cpu max. Skipped it
  (would be dead code). Saved a multi-hour implementation.
TCG perf reality: cross-AS IPC = CR3 reload = full softmmu TLB flush (no PCID under
TCG) → DOMAINS0004/0005 busy-wait tests are ~40x slow + host-variance. Correct, not
buggy. Real kernel win found anyway: shootdown_tlb skips idle cores (510cf06).

## sel4test rootserver staging + per-test VT-d leak (2026-06-28)
Two traps hit while landing the VT-d IOPT family:
1. STAGING ORDER: `build_kernel.sh` re-stages the small DEMO rootserver into
   `.tmp/rootserver.elf` (overwriting any sel4test-driver copy). So the correct
   per-iteration order is: build_kernel.sh → cp sel4test-driver .tmp/rootserver.elf
   → make_image.sh → run_specs.sh. If you skip the re-cp, you run the demo
   rootserver (look for "[rootserver alive]/multi-vspace setup ok" + a stray #PF)
   and NO sel4test output — easy to misread as a kernel regression.
2. CROSS-TEST GLOBAL STATE: sel4test uses *_leaky allocs and a HARDCODED badge
   (DOMAIN_ID<<16 | FAKE_PCI_DEVICE) every test → same PCI request-id → same VT-d
   context entry reused across tests. The per-test cleanup that resets it is
   finaliseCap at process teardown (Untyped revoke deletes the child's leaked
   IOPageTable/IO-frame caps). MUST implement finalise-on-delete (deleteIOPageTable
   / unmapIOPage) or leaked mappings corrupt the NEXT test's translation tree.
   Symptom: only IOPT0008 fails (it's the only test hardcoding pts[EXPECTED_PT_DEPTH]);
   earlier lenient tests pass on the corrupted-but-tolerable tree.
3. Boot-pool placement: a standalone small carve_chunk lands in the lowest free
   region (conventional RAM @ paddr 0), which is exactly where place_rootserver
   lays the rootserver — vtd_init then zeroes the rootserver TCB. Slice such pools
   off the TOP of the big 16MiB user-pages carve instead.
