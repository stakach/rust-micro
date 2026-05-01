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
