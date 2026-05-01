# Lessons captured this session

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
