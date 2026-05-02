# sel4test ABI audit (Phase 36a)

Compares our kernel's user-facing ABI against upstream `seL4` /
`libsel4` to enumerate everything `sel4test` would trip over on
first run. Each row is **MATCH** (we conform), **DIFF** (we differ
but cosmetic), or **GAP** (we don't yet implement / matches break
sel4test).

Upstream reference: `./seL4/libsel4/include/sel4/...` and
`./seL4/libsel4/mode_include/64/...`. Our code: `./src/types.rs`,
`./src/ipc_buffer.rs`, generated headers in
`target/.../build/.../out/{syscalls,invocations,structures}.rs`.

## Wire-level structures

| Item | Upstream | Ours | Status |
| --- | --- | --- | --- |
| `seL4_MessageInfo` bit layout | length 7 / extraCaps 2 / capsUnwrapped 3 / label 52 | length 7 / extraCaps 2 / capsUnwrapped 3 / label 52 | **MATCH** |
| `seL4_IPCBuffer` field order | tag, msg[120], userData, caps_or_badges[3], receiveCNode, receiveIndex, receiveDepth | same (see `src/ipc_buffer.rs`) | **MATCH** |
| `seL4_CapRights` bit layout | 4 bits, low: write/read/grant/grantReply | 4 bits, same | **MATCH** |
| `seL4_UntypedDesc` size | 16 bytes (paddr + sizeBits + isDevice + 6 padding) | 16 bytes — same | **MATCH** |

## seL4_BootInfo layout

| Field | Upstream offset | Ours | Status |
| --- | --- | --- | --- |
| extraLen | 0 | 0 | **MATCH** |
| nodeID | 8 | 8 | **MATCH** |
| numNodes | 16 | 16 | **MATCH** |
| numIOPTLevels | 24 | 24 | **MATCH** |
| ipcBuffer | 32 | 32 | **MATCH** |
| empty | 40 | 40 | **MATCH** |
| sharedFrames..extraBIPages | 56..96 | same | **MATCH** |
| initThreadCNodeSizeBits | 104 | 104 | **MATCH** |
| initThreadDomain | 112 | 112 | **MATCH** |
| **schedcontrol (MCS only)** | **120** (CONFIG_KERNEL_MCS=true) | **MISSING** — comment in `types.rs` claims MCS is off, but `bf.rs` flipped it to true in 32a | **GAP** |
| untyped | 136 | 120 (off-by-16) | **GAP** (consequence of missing schedcontrol) |
| untypedList | 152 | 136 | **GAP** |

**Fix:** add `pub schedcontrol: seL4_SlotRegion` between
`initThreadDomain` and `untyped`. Update the
`abi_layout_tests` spec.

## Syscall numbers

Upstream MCS API syscalls (from `api-mcs` in `syscall.xml`):

```
Call, ReplyRecv, NBSendRecv, NBSendWait, Send, NBSend,
Recv, NBRecv, Wait, NBWait, Yield
```

Our (generated from `api-master` block — same XML, wrong selector):

```
Call = -1
ReplyRecv = -2
Send = -3       (upstream MCS: NBSendRecv = -3)
NBSend = -4     (upstream MCS: NBSendWait = -4)
Recv = -5       (upstream MCS: Send = -5)
Reply = -6      (upstream MCS: NBSend = -6 — Reply isn't a syscall under MCS)
Yield = -7      (upstream MCS: Recv = -7)
NBRecv = -8     (upstream MCS: NBRecv = -8)
DebugPutChar = -9
DebugDumpScheduler = -10
```

**Status: GAP — biggest single ABI break.** Every sel4test syscall
would target the wrong handler.

**Fix:** switch `build_support/xml.rs::generate_syscalls` to read
the `api-mcs` block when `CONFIG_KERNEL_MCS=true`. Implement the
new syscalls (Wait/NBWait are notification-only Recv variants;
NBSendRecv/NBSendWait are Send+Recv composites). Drop the
standalone `SysReply` syscall handler — Reply is a cap invocation
under MCS (which depends on Phase 34e's reply-cap follow-up
landing).

## InvocationLabel numbering

| Range | Upstream MCS | Ours | Status |
| --- | --- | --- | --- |
| 0..38 (common + MCS) | matches `api.xml` ordering | matches (we use the same `api-mcs.xml` codegen path with `CONFIG_KERNEL_MCS=true`) | **MATCH** |
| 39..58 (x86) | from `arch/x86/api/x86.xml` | matches | **MATCH** |
| nInvocationLabels | 59 | 59 | **MATCH** |

Hand-spot checked: `TCBSetSpace = 11`, `TCBResume = 13`,
`SchedControlConfigureFlags = 33`, `X86PageMap = 45` — all match
the upstream ordering after the MCS flip.

## Initial CNode slot conventions

Upstream `seL4_RootCNodeCapSlots` (libsel4 `bootinfo_types.h`):

| Slot | Upstream | Ours |
| --- | --- | --- |
| 0 | CapNull | (empty) |
| 1 | InitThreadTCB | `Cap::Thread` ✓ |
| 2 | InitThreadCNode | `Cap::CNode` ✓ |
| 3 | InitThreadVSpace | `Cap::PML4` ✓ |
| 4 | IRQControl | `Cap::IrqControl` ✓ |
| 5 | ASIDControl | **MISSING** |
| 6 | InitThreadASIDPool | **MISSING** |
| 7 | IOPortControl | (null OK — we don't model) |
| 8 | IOSpace | (null OK — no IOMMU) |
| 9 | BootInfoFrame | `Cap::Frame(bi)` ✓ |
| 10 | InitThreadIPCBuffer | `Cap::Frame(ipc)` ✓ |
| 11 | Domain | **WE PUT UNTYPED HERE** — collision |
| 12 | SMMUSIDControl | (null OK) |
| 13 | SMMUCBControl | (null OK) |
| 14 | InitThreadSC (initial thread's SC) | We have `Cap::SchedControl` here — **wrong cap type** |
| 15 | SMC | (null OK) |
| 16 | NumInitialCaps | — |
| 16+ | (untyped here) | (we put untyped at slot 11) |

**Status: GAP, several issues:**
1. **Untyped at slot 11**, not slot 12+. `bi.untyped.start` is 11
   for us, but sel4test reads it from BootInfo so this only
   collides with the Domain cap at slot 11. We currently leave
   slot 11 = Untyped (no Domain cap). sel4test invokes Domain at
   slot 11 → InvalidCapability.
2. **No Cap::AsidControl at slot 5.** We have the typed cap (32a)
   but the rootserver bootstrap doesn't install one. sel4test's
   ASID tests would fail.
3. **No Cap::AsidPool at slot 6.** Same issue — we have the typed
   cap but no install.
4. **Slot 14 holds SchedControl, should hold InitThreadSC.** Under
   MCS, slot 14 is the *initial thread's* SchedContext. SchedControl
   is per-CPU and lives in `bi.schedcontrol` (a slot region), not in
   the CNode at a fixed slot.

**Fix:** rework `launch_rootserver` to install the canonical
slot 0..14 layout, allocate one SchedContext for the initial
thread, and surface SchedControl caps via the (still-to-add)
`bi.schedcontrol` slot region.

## TCB invocation surface

| Invocation | Upstream | Ours | Status |
| --- | --- | --- | --- |
| Configure | sets fault_ep + cspace + cspace_data + vspace + vspace_data + ipc_buffer + ipc_buffer_frame + priority + mcp | sets fault_ep + cspace + vspace + priority + mcp | **DIFF** (cspace_data / vspace_data / ipc_buffer_frame missing — sel4test sometimes uses cspace_data for guard config) |
| SetIPCBuffer | vaddr + frame_cap | vaddr + frame_cap | **MATCH** (Phase 34c) |
| WriteRegisters / ReadRegisters | full register set | rip + rsp + arg0 only | **GAP** (sel4test register tests would fail) |
| BindNotification / Unbind | works | works | **MATCH** |

## IPC features

| Feature | Upstream | Ours | Status |
| --- | --- | --- | --- |
| Long messages (`length > 4`) via IPC buffer | ✓ | ✓ (Phase 34c) | **MATCH** |
| Cap transfer via `extraCaps` | ✓ | ✓ (Phase 34d) | **MATCH** |
| Reply caps via `Cap::Reply` | ✓ — caller doesn't pre-allocate; receiver issues `Recv` with a designated reply slot | partial — Reply object pool + retype works (34e), but reply IPC still routes through `Tcb.reply_to: Option<TcbId>` | **GAP** (the 34e follow-up) |
| Wait / NBWait (notification-only Recv) | ✓ | **MISSING** | **GAP** |
| NBSendRecv / NBSendWait | ✓ | **MISSING** | **GAP** |

## Summary — what sel4test bring-up would need

In rough decreasing leverage:

1. **Switch syscall codegen to `api-mcs` block + add Wait /
   NBWait / NBSendRecv / NBSendWait + drop standalone SysReply.**
   Single biggest ABI break; nothing meaningful runs without it.
2. **Add `bi.schedcontrol` slot region to `seL4_BootInfo`.**
   Layout-shifts every field after `initThreadDomain`. Cheap fix
   but breaks our existing rootserver if not done together with
   #4.
3. **Reply caps through Call/Reply (the 34e follow-up).** Hard to
   skip; many sel4test cases call into a server and expect a Reply
   cap.
4. **Initial-cap slot layout fix.** Untyped at 12+, ASIDControl
   at 5, ASIDPool at 6, InitThreadSC at 14, SchedControl in the
   `bi.schedcontrol` region.
5. **`TCBConfigure` cspace_data + vspace_data + ipc_buffer_frame
   args.** Smaller; sel4test's TCB tests touch this.
6. **`Read`/`WriteRegisters` full register set.** Several
   sel4test cases depend on rax/rbx/etc. being settable.

Once these land, the next step is a dry hello-world build of
libsel4 against our generated headers (Phase 36b) and bringing up
one sel4test test (probably `tc_test_smallcaps` or similar) — see
the original Phase 34/35 plan in `tasks/todo.md`.
