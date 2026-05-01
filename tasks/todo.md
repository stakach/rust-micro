# Active phase plan — Phase 21: user-mode dynamic allocation

## Goal
Demonstrate the full seL4-shape flow from user mode: a ring-3
thread retypes an Untyped into a Frame, maps the Frame at a
chosen vaddr, writes to the mapped memory, reads it back, and
prints the result. Proves Phase 16 (Untyped::Retype) and Phase 19
(Frame::Map) work end-to-end from user space, not just spec.

## Demo flow
- Sender: `SysSend('Y' on endpoint cap=1)` (existing).
- Receiver:
  1. `SysDebugPutChar('A')` — proof we started.
  2. `SysCall(cap=2 = Untyped, label=UntypedRetype, type=X86_4K,
     num=1, dest_offset=3)` — retype a frame into slot 3.
  3. `SysCall(cap=3 = Frame, label=X86PageMap, vaddr=V, rights=RW)`
     — install the frame at user-virtual V.
  4. `SysRecv(cap=1)` — receive the sender's 'Y'.
  5. `mov [V], received_byte` — store through the new mapping.
  6. `mov rdi, [V]` — load it back.
  7. `SysDebugPutChar(rdi)` — print it.

If we observe `AY` on serial we know:
* Slot lookup works.
* Untyped::Retype as a syscall works.
* Frame::Map as a syscall works.
* The new PTE actually points at the new frame (the byte loaded
  matches the byte stored).
* IPC still works.

## Plan
- [x] 21a — Pre-populate receiver's CNode with an Untyped cap at
  slot 2 (carved from `DEMO_POOL`, a 16 KiB BSS-aligned pool).
- [x] 21b — Hand-assembled the new receiver payload (~140 bytes).
- [x] 21c — Existing IPC_PRINTED threshold (≥ 2) already matches.
- [x] 21d — Boot output reads `AY`.

## ABI plumbing notes
* MessageInfo for Retype: label = UntypedRetype = 1. Encoded
  bits: `(label << 12) | (length & 0x7F)`. We only need length
  for IPC payload, not for invocations — kernel reads label from
  rsi.
* SyscallArgs for Retype: a0 = cap_ptr to untyped, a2 =
  object_type word (X86_4K = 7), a3 = (size_bits<<32) |
  num_objects = 1, a4 = dest_offset = 3.
* SyscallArgs for X86PageMap: a0 = cap_ptr to frame, a1 =
  (X86PageMap << 12), a2 = vaddr, a3 = FrameRights::ReadWrite
  (= 3).

## Verification
* All previous specs still pass.
* IPC demo's payload bytes line up with the assembled
  instructions (manual trace).
* Boot output ends with `AY` then exit.

## Review

* All 4 sub-tasks complete on the first build. The hand-assembled
  payload happened to be correct on the first run — every byte
  was checked against the manual encoding in the comment block.
* Boot output: `AY`. The `Y` is the byte that came:
  sender's user code → Cap::Endpoint → endpoint::transfer →
  receiver's TCB.msg_regs[0] → Phase 15a fan-out into rdx →
  user's `mov rcx, rdx` → user's store `mov [V], cl` → loaded
  back via `movzx rdi, byte [V]` → SysDebugPutChar → serial.
* This proves end-to-end:
  - SysSend on Endpoint cap from ring 3
  - SysSend on Untyped cap from ring 3 → Untyped::Retype
    invocation places a Frame cap in the receiver's CSpace
  - SysSend on Frame cap from ring 3 → Frame::Map invocation
    installs the PTE
  - The PTE actually backs real memory (DEMO_POOL) and the
    page-table walk lands the user's load on the byte the user
    just stored
  - SysRecv on Endpoint from ring 3 returns the sender's byte in
    rdx (Phase 15a fan-out)
* Specs unchanged at 128 ✓; user-mode demo is now strictly
  more impressive.
