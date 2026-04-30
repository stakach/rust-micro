# Porting seL4 to Rust — Plan

This is the proposal for replacing the toy kernel in `src/` with a Rust
re-implementation of [seL4](https://sel4.systems) (currently `15.0.0-dev`,
checked in under `seL4/`). It establishes scope, the order we tackle
subsystems in, and the design rules we hold ourselves to. Read it end-to-end
before we start writing code — many of the decisions below are
load-bearing on later phases.

---

## 1. Scope and non-goals

### In scope (initial target = "minimum bootable seL4")

A 64-bit x86 (pc99) kernel that:
1. Boots via BOOTBOOT into long mode (already working).
2. Sets up its own page tables (kernel half mapped, user half empty).
3. Implements the seL4 capability model: `Untyped`, `CNode`, `TCB`,
   `Endpoint`, `Notification`, `Reply`, plus the x86-specific
   `Frame`/`PageDirectory`/`PageTable`/`PML4`/`ASIDPool`/`ASIDControl`/
   `IRQControl`/`IRQHandler`.
4. Implements the seL4 syscall ABI: `Send`, `NBSend`, `Call`, `Recv`,
   `NBRecv`, `Reply`, `ReplyRecv`, `Yield`. (Master/non-MCS variant.)
5. Boots a hand-written `init` userland blob that prints "hello from
   user-space" via a debug syscall — proving that the cap model, scheduler,
   IPC and trap path all line up.
6. Passes a port of the relevant subset of `sel4test`.

### Out of scope, deferred

- **MCS scheduler.** ~30% of `tcb.c`, all of `schedcontext.c`/
  `schedcontrol.c`/`sporadic.c`, plus syscall variants (`NBSendWait` etc.).
  Build it as a `mcs` cargo feature later, on top of the classic core.
- **SMP.** Boot the BSP only. The current toy kernel already halts APs;
  we keep that. Add an `smp` feature flag once UP works.
- **Fastpath.** ~300 LOC of hand-tuned hot-path IPC. Slowpath is correct;
  we measure first, optimise later.
- **Virtualisation (VT-x / EPT / VCPU caps).** Big surface area,
  orthogonal to the core kernel.
- **FPU lazy switching, hardware debug API, `CapDL`, profiler,
  benchmarking variants.** All `CONFIG_*` gated in seL4; we add them only
  when something needs them.
- **Other architectures (aarch64, riscv).** The arch trait stays in
  place so a second arch is feasible, but we do not implement it now.
- **Formal verification.** seL4's value is its proofs — we make the *code*
  shaped like the abstract spec so a future Isabelle/HOL or Verus proof
  effort is plausible, but proving is out of scope.

The hard rule: every deferred item is gated behind a cargo feature or an
`Option`-returning trait method, so re-enabling it later is additive,
not a refactor.

---

## 2. Why a port, not a fork

Three reasonable strategies exist; we pick the third.

**(a) Wrap C seL4.** Build the C kernel and link Rust glue. Loses the
point of the exercise (memory safety, no external deps).

**(b) Mechanical translation.** `c2rust` plus hand cleanup. Produces
unsafe Rust shaped like C. Carries every macro and `#ifdef` quirk and
gives no opportunity to use Rust's type system. Specifically: seL4
encodes capability variants as packed bitfields — Rust enums with payload
are strictly better. Mechanical translation can't do that.

**(c) Re-implementation against the spec.** Read seL4 (and the abstract
spec / manual) as the design document. Re-state every data structure and
algorithm in idiomatic `#![no_std]` Rust. Match the externally-visible
ABI byte-for-byte (libsel4 layouts, syscall numbers, invocation IDs,
boot info frame). Internally, use Rust's enums, traits, lifetimes,
`PhantomData`, and typestate to make illegal kernel states
unrepresentable.

We pick (c). It's more work but produces a kernel worth having.

---

## 3. ABI compatibility — what does "seL4 clone" mean?

A user binary built against seL4's `libsel4` should run unmodified
against this kernel. Concretely we freeze:

- Syscall numbers (`enum syscall` in `gen_headers/api/syscall.h`).
- Invocation labels per object type (`gen_headers/api/invocation.h`).
- Cap bitfield layouts (`include/object/structures_64.bf`).
- `seL4_BootInfo` frame layout (`libsel4/include/sel4/bootinfo_types.h`).
- IPC buffer layout, message register count, fault message layouts.
- Error codes (`libsel4/include/sel4/errors.h`).

We do not freeze internal kernel state layouts (TCB struct field order,
etc.); those become Rust types of our choosing.

---

## 4. Build-time code generation strategy

seL4 leans hard on Python codegen at CMake time. We must replace each
generator. Options per generator, picked individually:

| seL4 generator | Input | Output | Our approach |
|---|---|---|---|
| `bitfield_gen.py` | `structures_64.bf` | `structures_gen.h` (C accessors) | **Rust `proc_macro` or `build.rs`** that parses `.bf` and emits Rust `#[repr(transparent)] struct` + getter/setter `const fn`s. Keep the `.bf` file as the source of truth so user-visible cap layouts stay byte-identical. |
| `syscall_header_gen.py` | `syscall.xml` | `syscall.h` enum | `build.rs` reads XML, emits `pub enum Syscall { ... }` |
| `invocation_header_gen.py` | `interfaces/object-api*.xml` | per-object enums | same — `build.rs`-emitted enums |
| `hardware_gen.py` | `hardware.yml` + DTS | `hardware_gen.h` | static Rust tables; for pc99 the input is small (PIT, PIC, PCI cfg ports). Skip the YAML/DTS pipeline — write the constants by hand. |

Decision: **use `build.rs`, not procedural macro crates**. Procedural
macros require a separate `proc-macro = true` crate, an external
`syn`/`quote` dependency, and slow incremental builds. `build.rs` emits
plain Rust into `OUT_DIR` and we `include!` it. No external deps, which
the project rules require.

We will write a tiny ad-hoc parser for the `.bf` DSL — it's a few
hundred lines, the grammar is straightforward (`block <name> { field
<name> <bits> ... }`), and we don't need PLY.

---

## 5. Crate layout

```
mykernel-rust/                   (existing top-level — rename later)
├── Cargo.toml
├── build.rs                     ← codegen entry point
├── triplets/mykernel-x86.json
├── link.ld
├── codegen/                     ← .bf and .xml inputs (copies pinned to seL4 v15)
│   ├── structures_64.bf
│   ├── syscall.xml
│   └── object-api*.xml
└── src/
    ├── main.rs                  (entry, panic handler, BSP gate — keeps shape)
    ├── arch.rs                  (trait — already exists)
    ├── arch/x86_64/             (asm shims, traps, MSRs, paging tables)
    │
    ├── boot.rs                  ← src/kernel/boot.c
    ├── types.rs                 ← include/types.h, include/api/types.h
    ├── config.rs                ← cargo features → CONFIG_* constants
    │
    ├── cap/                     ← include/object/cap.h, generated bitfields
    │   ├── mod.rs               (Cap enum wrapping bitfield variants)
    │   ├── derive.rs            (deriveCap)
    │   ├── finalise.rs          (finaliseCap)
    │   └── rights.rs
    │
    ├── object/                  ← src/object/
    │   ├── cnode.rs
    │   ├── tcb.rs
    │   ├── endpoint.rs
    │   ├── notification.rs
    │   ├── untyped.rs
    │   ├── interrupt.rs
    │   ├── reply.rs
    │   ├── domain.rs
    │   └── objecttype.rs        (decodeInvocation dispatcher)
    │
    ├── kernel/                  ← src/kernel/
    │   ├── cspace.rs            (lookupCap, resolveAddressBits)
    │   ├── thread.rs            (schedule, switchToThread, queues)
    │   ├── faulthandler.rs
    │   └── stack.rs
    │
    ├── api/                     ← src/api/
    │   ├── syscall.rs           (handleSyscall dispatcher)
    │   ├── failures.rs
    │   └── faults.rs
    │
    ├── machine.rs               (FPU stub, IO, registerset trait)
    ├── model.rs                 (per-CPU state — `static mut` for UP)
    ├── bootinfo.rs              (seL4_BootInfo construction)
    │
    └── spec/                    (existing — extend per subsystem)
```

Each subsystem gets its own `mod` and its own `spec/` test file. The
`arch::Architecture` trait grows methods as the kernel needs them
(`flush_tlb`, `set_cr3`, `idle`, `wfi_or_hlt`, `restore_user_context`,
…), and `x86_64.rs` implements them.

---

## 6. Core type-design decisions

These shape every later file, so call them out now and let me know if
you disagree.

### 6.1 `Cap` is a Rust enum, not a packed bitfield

```rust
pub enum Cap {
    Null,
    Untyped { ptr: PPtr, block_bits: u8, free_index: usize, is_device: bool },
    Endpoint { ptr: PPtr<EndpointObj>, badge: Word, rights: EndpointRights },
    Notification { ptr: PPtr<NotificationObj>, badge: Word, rights: NotificationRights },
    CNode { ptr: PPtr, radix: u8, guard_size: u8, guard: Word },
    Thread { ptr: PPtr<Tcb> },
    Reply { ptr: PPtr<Tcb>, can_grant: bool, master: bool },
    IrqControl,
    IrqHandler { irq: Irq },
    Zombie { id: Word, ty: ZombieType },
    Domain,
    Frame { ptr: PPtr, size: FrameSize, asid: Asid, vptr: VPtr, mapped: bool },
    PageTable { ptr: PPtr<PageTable>, asid: Asid, vptr: VPtr, mapped: bool },
    /* ... arch-specific frame/PT/PD/PML4/ASIDPool/ASIDControl/IOPort/... */
}
```

For storage in CTEs we use a `repr(C)` two-word struct that mirrors the
seL4 `cap_t` *bit layout* exactly (so `CSpace` traversals see the same
words). The generated bitfield code provides `Cap::from_words(&[Word;
2]) -> Cap` and `Cap::to_words(&self) -> [Word; 2]`. Internally, every
hot path operates on the enum.

This is the single biggest deviation from seL4's C and the single
biggest win.

### 6.2 Physical and virtual pointers are distinct types

```rust
#[repr(transparent)] pub struct PAddr(pub u64);
#[repr(transparent)] pub struct VAddr(pub u64);
#[repr(transparent)] pub struct PPtr<T = ()>(NonZeroU64, PhantomData<T>);
```

`PPtr<T>` is a kernel-mapped pointer to a kernel object, statically
typed where possible. Mismatching a `PPtr<Tcb>` and a `PPtr<Endpoint>`
becomes a compile error.

### 6.3 Exceptions are `Result`

seL4's `exception_t` (`EXCEPTION_NONE`/`EXCEPTION_FAULT`/
`EXCEPTION_SYSCALL_ERROR`/`EXCEPTION_PREEMPTED`) becomes:

```rust
pub type KResult<T = ()> = Result<T, KException>;
pub enum KException {
    Fault(Fault),
    SyscallError(SyscallError),
    Preempted,
}
```

Every `?` propagates exactly the way seL4's manual `if (status !=
EXCEPTION_NONE) return status;` does, with no risk of forgetting a
check.

### 6.4 No allocator, ever

The kernel never calls `alloc`. All memory comes from:
- Static arrays (BSS) for boot-time tables.
- `Untyped` retypes — user-visible memory carving.
- The `rootserver` region — boot-allocated once, then frozen.

We do not pull in `alloc` even behind a feature flag. Anything that
looks like it wants `Box` or `Vec` is replaced by an inline array, an
intrusive list, or a slab in a fixed region. This matches seL4 exactly
and keeps the trusted code base small.

### 6.5 Concurrency model: `unsafe` per-CPU statics

For the UP target, kernel state is a singleton accessed only when the
kernel is entered (i.e. interrupts off, or no preemption point reached
yet). We model this as `static mut` with a wrapper `KernelState` whose
methods take `&mut self` only during a kernel entry. SMP later swaps
this for `[KernelState; NUM_CPUS]` keyed by `gs:0x...` — same idiom as
`NODE_STATE()` in seL4. We do *not* introduce `Mutex`/`RwLock`; there
is no preemption point inside the kernel for UP.

### 6.6 Intrusive linked lists via raw `PPtr`s

TCB queues, endpoint waiter lists, and CTE MDB nodes are all intrusive
doubly-linked lists in seL4. We mirror that with `PPtr`s and explicit
`unsafe fn enqueue`/`dequeue` helpers, encapsulated in a `linked_list`
module with strong unit-test coverage. Trying to make these "safe" with
`Rc<RefCell>` defeats the kernel's whole memory model.

---

## 7. Phasing

Each phase ends with the kernel still booting and all specs green. No
phase leaves the tree red.

### Phase 0 — preparation (no kernel changes)

- ✅ macOS toolchain and scripts (this conversation).
- Pin a snapshot of the seL4 git revision we are tracking; record the
  hash in this file.
- Copy the four codegen inputs into `codegen/`. Treat `seL4/` as
  read-only reference from here on.
- Stub `build.rs` that does nothing yet; wire it through `Cargo.toml`.

### Phase 1 — types, codegen, no logic

Goal: introduce all the user-visible ABI surface as Rust types without
implementing any kernel behaviour.

- Write the `.bf` parser in `build.rs`, emit Rust bitfield accessors
  for every block in `structures_64.bf`. Emit a constant table of cap
  type tags. **Test:** byte-for-byte round-trip against handcrafted
  reference values from a real seL4 binary.
- Emit `pub enum Syscall` and per-object `pub enum InvocationLabel`
  from XML. Compare numbers against a built C `gen_headers/api/syscall.h`.
- Hand-code the `seL4_BootInfo`, `seL4_MessageInfo`, `seL4_CapRights`,
  `seL4_Fault` types in `src/types.rs`, matching libsel4 byte layout.
- Hand-code error / fault enums.
- Add a spec under `spec/abi_layout.rs` that `static_assert`s every
  size, alignment, field offset against the seL4 `libsel4` headers.

Exit: `cargo build` passes; one new spec passes; kernel still boots and
runs the existing arch spec.

### Phase 2 — capability storage and CSpace

Goal: a working CNode lookup with no other kernel objects yet.

- `cap/mod.rs` — `Cap` enum + `to_words`/`from_words`.
- `kernel/cspace.rs` — `lookupCap`, `lookupSlot`, `resolveAddressBits`.
- `object/cnode.rs` — minimal `decode_cnode_invocation` for `Copy`,
  `Mint`, `Move`, `Mutate`, `Delete` (skip `Revoke` and `CDT`/MDB until
  later — return `not implemented`).
- Specs: hand-construct CSpaces in BSS, exercise `lookupCap` for hits,
  guard mismatches, depth overruns.

Exit: lookup is exercised by spec; no syscall path yet.

### Phase 3 — Untyped and the rootserver

Goal: be able to allocate kernel objects out of memory.

- `object/untyped.rs` — `decode_untyped_invocation` for `Retype`,
  obeying seL4's allocation rules (free index, ordering, child slots,
  device flag).
- `boot.rs` — port `kernel/boot.c`'s memory-discovery, reserved-region
  carving, `rootserver` placement, BootInfo frame construction.
- Map the BOOTBOOT-provided memory map into seL4's `available_p_regs`
  representation.
- Spec: at boot, retype an Untyped into a CNode, write a cap into a
  slot, look it up.

Exit: kernel can carve memory from Untypeds during boot.

### Phase 4 — TCBs and the scheduler

Goal: two threads exist, scheduler can switch between them.

- `object/tcb.rs` — TCB struct, `decode_tcb_invocation` minus IPC bits.
- `kernel/thread.rs` — `schedule`, `chooseThread`, `switchToThread`,
  ready-queue bitmaps. Single domain initially.
- `arch/x86_64/context.rs` — register save/restore, ring 0→3 transit.
- Idle thread (a hand-written `hlt; jmp $-1` blob).
- Spec: create two TCBs in BSS, schedule between them in kernel space
  (no userland yet).

Exit: round-robin between two kernel-mode "threads" (call them in-kernel
fibres) via `schedule`.

### Phase 5 — interrupts and traps reach the kernel

Goal: a user-space `int 0x..` reaches `handleSyscall`.

- Repurpose existing `interrupts.rs` / `exceptions.rs` to install
  full seL4-style trap entry: SYSCALL/SYSRET MSRs, syscall stub written
  in `naked_asm!`, restore path. (Mirror `arch/x86/64/traps.S` and
  `c_traps.c`, written in Rust + minimal asm.)
- `api/syscall.rs` — `handleSyscall` as a `match` on `Syscall`.
- Implement only `SysDebugPutChar` end-to-end at first: userspace
  payload prints a character via syscall.
- Build a tiny userland blob (a `.bin` ELF embedded as `include_bytes!`)
  that issues the syscall in a loop and `hlt`s. Map it as the initial
  thread's address space in `boot.rs`.

Exit: serial output from userland, via the seL4 syscall ABI.

### Phase 6 — IPC: Endpoints

Goal: two userland threads can `Send`/`Recv` over an Endpoint.

- `object/endpoint.rs` — endpoint state machine
  (Idle/Send/Recv queues), badge handling, `cancelIPC`.
- `kernel/thread.rs` extended with `doIPCTransfer` (slowpath only).
- `decode_invocation` in TCB / CNode wired up enough to set up an
  endpoint cap in the test app.
- Spec: a two-thread test where `init` forks (via `Retype`) into a
  second TCB, both share an endpoint, ping-pong N times.

Exit: user-to-user IPC works.

### Phase 7 — IRQs, Notifications, the rest

- `object/notification.rs` — `Signal`/`Wait`/binding to TCB.
- `object/interrupt.rs` — `IRQControl::GetHandler`, IRQ ack, dispatch
  to bound notification.
- Wire i8259/IOAPIC enough to deliver the timer IRQ; preemption point
  in scheduler ticks.

Exit: a userland process gets ticks via a notification cap.

### Phase 8 — paging caps

Goal: userland can map and unmap pages without kernel support.

- `arch/x86_64/vspace.rs` — port `arch/x86/64/kernel/vspace.c`.
  Implement the cap chain Frame → PageTable → PageDirectory → PDPT →
  PML4 → ASIDPool → ASIDControl with the seL4 invocation set.
- `decode_x86_invocation` dispatcher.
- Spec: userland does its own `Frame::Map` / `PageTable::Map`.

Exit: a userland that builds its own page tables.

### Phase 9 — sel4test subset

Port a chosen subset of the
[sel4test](https://github.com/seL4/sel4test) test cases into our spec
runner. Each one becomes a userland blob that issues syscalls and
reports a pass/fail word back to the kernel via `SysDebugPutChar` (or a
new spec-only syscall). Track pass rate in `PORT_PLAN.md`.

This is the milestone we call "feature-complete v0".

### Phase 10+ — deferred features

Re-enable, in roughly this order, gated by cargo features:
1. SMP (`smp`) — adds per-CPU state, IPI plumbing.
2. MCS (`mcs`) — adds `SchedContext`/`SchedControl`/`Reply` MCS
   semantics, sporadic server, `NBSendWait` syscalls.
3. Fastpath (`fastpath`).
4. FPU (`fpu`).
5. VT-x (`vmx`).
6. aarch64 / riscv (separate arch modules).

---

## 8. Testing strategy

Three layers, all already supported by the existing infrastructure:

1. **Host-side unit tests.** Run on the dev machine via plain
   `cargo test`. Targets: `.bf` parser, bitfield round-trip, type
   layout asserts, `cspace` lookup logic, scheduler queue manipulation.
   Lifted by extracting *pure* logic behind cfg gates so it can compile
   for the host. Aim: ~50% of kernel logic covered this way. This is
   the layer that survives a triple-fault.
2. **In-kernel specs (existing `spec` feature).** Run inside QEMU, on
   the real kernel, before scheduling userland. Check arch invariants
   (CR0/CR4 bits, IDT layout), allocator state after boot, cap table
   shape after `boot.rs` finishes.
3. **Userland sel4test subset.** Userland blobs that drive the syscall
   ABI; their output is captured via the debug syscall and pattern-matched.

CI is a single `make test` that builds and runs all three.

---

## 9. Risks and open questions

These are decisions we can defer but should call out now.

1. **No external crates is strict.** We will not pull in
   `bitflags`/`once_cell`/`spin`/`x86_64` crates, even though they would
   shave a few hundred lines. Re-confirm: this is firm? (CLAUDE.md says
   so; calling it out because it will hurt occasionally.)
2. **`naked_asm!` and `unsafe(naked)` are still nightly-only.** We
   already use them. Acceptable.
3. **Bootloader.** BOOTBOOT works for hobby; seL4 traditionally uses
   multiboot1 from elfloader/GRUB. Long-term, do we want to also
   support multiboot? Defer until phase 9.
4. **Spec-fidelity bug-for-bug?** seL4 has known quirks (e.g. issue
   #1540 around spurious interrupt reporting on MCS). Default: be
   correct, not bug-compatible. Document divergences.
5. **Verification.** If we ever want to attempt verification, every
   line we write should be reviewable against seL4's abstract spec
   (Haskell prototype in `seL4/haskell/` upstream). We keep our module
   names and function names aligned with the spec for exactly this
   reason.
6. **License.** seL4 is GPL-2.0. A clean-room re-implementation
   informed by the spec/manual is not derivative; a line-by-line port
   probably is. We default to GPL-2.0 for safety unless and until that
   choice gets revisited deliberately.

---

## 10. Definition of done for the port itself

The port is "done enough to be useful" when:

- A user binary built against an unmodified upstream `libsel4` (master
  branch / non-MCS) runs on our kernel without source changes.
- The chosen sel4test subset passes.
- `cargo build --release` produces a kernel of comparable size to
  upstream seL4 (within 2× — Rust no_std with no codegen overhead is
  not far off C).
- The architecture trait is clean enough that adding aarch64 is a
  matter of writing a sibling to `arch/x86_64/`, no kernel-core changes.

That target is realistic but is, to be clear, weeks of focused work,
not an afternoon. Each phase above is a natural pause point where we
can stop with a working kernel, ship, and resume later.

---

## 11. Immediate next step

Once you've reviewed this:

1. Confirm scope (section 1). Are there features I've punted that you
   want in v0?
2. Confirm the type-design decisions (section 6) — particularly the
   `Cap` enum vs. preserving seL4's bitfield-as-storage. This is the
   biggest one to ratify before we write a line.
3. Start phase 0: pin the seL4 revision, set up `codegen/`, scaffold
   `build.rs`. No kernel logic touched yet.

Your call on (3) — happy to start that work in the next message, or to
pause here for review first.
