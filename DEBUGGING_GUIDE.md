# Debugging the rust-micro kernel (and userspace) with gdb

QEMU exposes a **gdb remote stub**. You attach a debugger to it and get full
control of the virtual CPU: breakpoints on any virtual address, single-step,
register and memory inspection, disassembly — for the kernel *and* for the
userspace code running on top of it (rootserver, components, and even a mapped
Windows `ntdll.dll`).

This is the tool of last resort when serial-print tracing isn't enough — e.g.
"the loader faults deep inside ntdll and I need to know *why* a lookup returned
NULL". It's how the ntdll loader bring-up (`userspace-ntos`) was driven to
completion.

---

## TL;DR

```sh
# 1. Build a disk image (kernel + whatever rootserver you're debugging)
./scripts/build_kernel.sh extern-rootserver

# 2. Boot under the gdb stub and auto-drive lldb (halts, breaks at $BRK, dumps state)
BRK=0x78e8c966 ./scripts/run-gdb.sh
```

`scripts/run-gdb.sh` boots the image with `-s -S` (gdb stub on `:1234`, CPU
**halted at reset**), then runs `lldb --batch` to connect, break at `$BRK`,
continue, and dump registers/stack/disassembly. Edit the lldb command block in
the script for anything more involved, or drive lldb interactively (below).

---

## Prerequisites

- **QEMU** (`qemu-system-x86_64`) — already required to run the specs.
- A debugger that speaks the gdb-remote protocol:
  - **macOS**: `lldb` (ships with Xcode command-line tools). Used throughout
    this guide. lldb happily debugs a bare-metal x86-64 target over gdb-remote.
  - **Linux**: `gdb` works too; the commands map 1:1 (`target remote :1234`
    instead of `gdb-remote localhost:1234`, `x/i $pc` instead of `disassemble`,
    etc.).

No symbols are involved — this is raw-address debugging. That's fine; you drive
everything by absolute virtual address.

---

## How it works

`qemu-system-x86_64 ... -s -S`:

- `-s` opens a gdb stub on TCP `localhost:1234`.
- `-S` freezes the CPU at reset so you can set breakpoints before anything runs.
- `-smp 1` (in `run-gdb.sh`) keeps it single-core so breakpoints are
  deterministic — no "which CPU hit it" ambiguity. Multi-core also works but is
  noisier.
- Serial goes to `/tmp/gdb-serial.log` (not stdout) so it doesn't tangle with
  the lldb session; `tail -f` it in another terminal if you want the spec output.

Breakpoints are on **virtual addresses**. QEMU stops whenever `RIP` equals the
address in the *current* address space. Because the kernel and all the
userspace threads we debug share (or map) the same high-half kernel and the
same low-half image pages, a breakpoint on a userspace `.text` address fires
when — and only when — that thread executes there.

---

## Basic interactive session

Start the stub in the background and attach lldb by hand:

```sh
# terminal 1: boot halted under the stub
qemu-system-x86_64 -machine q35 \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF" \
  -drive format=raw,file=.tmp/disk.img,if=none,id=bootdisk \
  -device ahci,id=ahci0 -device ide-hd,drive=bootdisk,bus=ahci0.0,bootindex=0 \
  -m 1024M -smp 1 -serial file:/tmp/gdb-serial.log -monitor none -nographic \
  -no-reboot -device isa-debug-exit,iobase=0x501,iosize=0x2 -s -S

# terminal 2:
lldb
(lldb) gdb-remote localhost:1234
(lldb) breakpoint set --address 0x78e8c966
(lldb) continue
(lldb) register read rax rbx rcx rdx rsi rdi rsp rip
(lldb) disassemble --start-address 0x78e8c900 --count 40
(lldb) memory read --size 8 --count 16 --format x $rsp
```

(`OVMF` is the UEFI firmware path; `run_specs.sh`/`run-gdb.sh` auto-detect it.)

---

## The techniques that actually matter

### 1. Conditional breakpoints on the interesting call

A function you care about (say a lookup) is called hundreds of times; you want
the *one* call with a specific argument. Break conditionally:

```
(lldb) breakpoint set --address 0x78e77d30 --condition '$rbx == 0x78e67910'
```

**Gotcha — know which register holds the value at the breakpoint address.**
The x64 first argument is `RCX` *at function entry*, but the callee immediately
moves it elsewhere. If you break a few instructions in, `RCX` is already
clobbered. Disassemble the prologue first and pick the register that still
holds your value (e.g. `mov rbx, rcx` → condition on `$rbx`). Getting this wrong
means the breakpoint silently never fires and the process runs to exit.

### 2. `disassemble` resolves RIP-relative operands for you

The single most useful trick for raw-address work. lldb prints the *absolute*
target of `[rip + disp]` operands, so you can read the global directly:

```
(lldb) disassemble --start-address 0x78e77c20 --count 34
    0x78e77c5b: movl   0x10739f(%rip), %ecx      ; -> reads 0x78F7F000
    0x78e77c73: leaq   0x107396(%rip), %r10       ; -> table at 0x78F7F010
(lldb) memory read --size 4 --count 1 --format x 0x78f7f000    # the count
(lldb) memory read --size 8 --count 6 --format x 0x78f7f010    # the entries
```

This is how you locate and dump internal tables (e.g. ntdll's
`RtlpInvertedFunctionTable`) that have no symbol.

### 3. Verify your writes landed

When you inject state from the rootserver (structures, page contents) and aren't
sure it took, break at the consumer and read it back:

```
(lldb) memory read --size 4 --count 1 --format x 0x78f7f000
0x78f7f000: 0x00000002        # good — the loader populated it itself
```

### 4. Trace a branchy path with breakpoints, not single-step

lldb's `thread step-inst` in `--batch` mode is unreliable against a bare-metal
gdb-remote target (inconsistent output, easy to overshoot). Instead, **set
breakpoints at each candidate branch target** and see which one fires:

```
(lldb) breakpoint set --address <found-path>   --condition '$rdi == 0x78e67910'
(lldb) breakpoint set --address <not-found-1>  --condition '$rdi == 0x78e67910'
(lldb) breakpoint set --address <not-found-2>  --condition '$rdi == 0x78e67910'
(lldb) continue
```

Whichever hits tells you the path taken. Much more robust than stepping.

---

## Debugging userspace / a mapped Windows image

The loader bring-up runs a real, unmodified `ntdll.dll` mapped at its preferred
base. To turn a file offset or an export RVA into a breakpoint address:

```
VA = image_base + RVA
```

For this ntdll, `image_base = 0x78e50000`, so RVA `0x27d30` (an internal
function) is at VA `0x78e77d30`, and a fault reported by the kernel as
`rip=0x78e8c966` is RVA `0x3c966`.

Workflow to root-cause a userspace fault:

1. The kernel prints `[user #PF: tcb=N cr2=... err=... rip=VA]` on the serial log
   (`/tmp/gdb-serial.log`). Note `rip` (where it faulted) and `cr2` (the bad
   address). `err` bits: `1`=present, `2`=write, `4`=user — e.g. `err=7` is a
   user-mode write to a present (read-only) page.
2. Break at `rip`, `disassemble` around it to see the faulting instruction and
   which register is bad.
3. Follow that register back: `disassemble` earlier, or break at the `call` that
   produced it and `finish`/re-break to inspect the return value.
4. Cross-reference intent with source. For ntdll, the NT5 source
   (`references/nt5/base/ntdll/`) and ReactOS (`references/reactos/`) are close
   enough to Win7 to name the function and explain what it expects.

Worked example (the real one): a loop at RVA `0x3c900` called
`RtlLookupFunctionEntry` per ntdll function and dereferenced a NULL result.
gdb showed the lookup (`0x27d30`) fell through to a `NtQueryVirtualMemory`
fallback that checks `Type == MEM_IMAGE` at `buffer+0xC`; the rootserver's
syscall handler was only filling the class-0 `MEMORY_BASIC_INFORMATION` layout.
That one gdb session turned a vague "loader faults" into a one-field fix.

---

## Gotchas checklist

- **lldb uses AT&T syntax**: `cmpq %rax, %rdi` computes `rdi - rax` (operands
  reversed vs Intel). `jb` = unsigned below. Read carefully before concluding a
  branch is/isn't taken.
- **The process runs to `exit`** (spec's `qemu_exit`) if your breakpoint never
  fires — you'll see `Process exited with status = 3`, which is the *normal*
  microtest exit, not a crash. It just means your condition/address was wrong.
- **A user `#PF` is not a crash of the whole system** — the kernel handles it and
  keeps running (the faulting thread is suspended). So the spec can finish
  "successfully" while a thread you care about faulted. Grep the serial log for
  `#PF`.
- **Serial is in `/tmp/gdb-serial.log`**, not the lldb session.
- **Batch vs interactive**: for quick reads use `run-gdb.sh` (edit its command
  block); for exploratory work drive lldb interactively — batch `step-inst` is
  the weak spot.
