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
| **schedcontrol (MCS only)** | **152** (CONFIG_KERNEL_MCS=true) | **152** — Phase 36c added `seL4_SlotRegion` between `initThreadDomain` and `untyped`; populated `start == end == 0` (empty region) until per-CPU SchedControl caps land in the audit-item-4 follow-up | **MATCH** |
| untyped | 168 | 168 | **MATCH** |
| untypedList | 184 | 184 | **MATCH** |

(Original audit numbers had this off by 32 — corrected when the
spec was wired up, since each prior `seL4_SlotRegion` is 16 bytes
not 8; cumulative offset shifts compound.)

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

**Status: ~~GAP~~ → FIXED in Phase 36b.** Codegen now reads
`api-mcs` when `CONFIG_KERNEL_MCS=true`. Wait / NBWait alias
to handle_recv (blocking and non-blocking respectively);
NBSendRecv / NBSendWait stub IllegalOperation until proper
composite-IPC support lands. SysReply is no longer a userspace
syscall — kernel specs and `SysReplyRecv` call `handle_reply`
directly; the cap-based Reply replacement still depends on
Phase 34e's follow-up.

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

**Status: ~~GAP~~ → mostly FIXED in Phase 36e:**

  * Untyped moved 11 → **20**, past the canonical initial-cap
    range. `bi.untyped = {20, 21}`.
  * `Cap::AsidControl` installed at slot **5**.
  * Per-CPU `Cap::SchedControl` caps installed at slots **16..(16
    + ncores)**. `bi.schedcontrol` points at this range.
  * Slots 6 / 7 / 8 / 11 / 12 / 13 / 14 / 15 are left Null —
    Cap::AsidPool, IO, Domain, SMMU, InitThreadSC, SMC are not
    yet wired (still GAPs but smaller; sel4test cases that don't
    touch them work).
  * CNode radix bumped 5 → **6** (32 → 64 slots) to fit the new
    layout + leave headroom for tests.
  * `bi.empty = {21, 64}`.
  * `bi.initThreadCNodeSizeBits = 6`.

  Still missing (smaller follow-ups):
    - `Cap::AsidPool` at slot 6 (need to retype one for the
      rootserver).
    - `Cap::SchedContext` for the initial thread at slot 14.

## TCB invocation surface

| Invocation | Upstream | Ours | Status |
| --- | --- | --- | --- |
| Configure | sets fault_ep + cspace + cspace_data + vspace + vspace_data + ipc_buffer + ipc_buffer_frame + priority + mcp | sets fault_ep + cspace + vspace + priority + mcp | **DIFF** (cspace_data / vspace_data / ipc_buffer / ipc_buffer_frame missing). Phase 36f moved msg + extraCaps staging in `handle_send` to before the cap-type match, so adding these fields to `decode_tcb`'s TCBConfigure handler is now mechanical (read msg_regs[3..] + pending_extra_caps[]). Left as a follow-up because none of microtest's current cases need it. |
| SetIPCBuffer | vaddr + frame_cap | vaddr + frame_cap | **MATCH** (Phase 34c) |
| WriteRegisters / ReadRegisters | full register set | rip + rsp + arg0 + (Phase 36g) full upstream `seL4_UserContext` write path when `msginfo.length > 0` (resume_target/arch_flags/count + first-18-of-20 register fields). Legacy 3-arg form retained for back-compat. ReadRegisters is still rip + rsp + rax-only — sel4test cases that *read* full register sets would fail; counted as a smaller follow-up. | **MOSTLY MATCH** |
| BindNotification / Unbind | works | works | **MATCH** |

## IPC features

| Feature | Upstream | Ours | Status |
| --- | --- | --- | --- |
| Long messages (`length > 4`) via IPC buffer | ✓ | ✓ (Phase 34c) | **MATCH** |
| Cap transfer via `extraCaps` | ✓ | ✓ (Phase 34d) | **MATCH** |
| Reply caps via `Cap::Reply` | ✓ — caller doesn't pre-allocate; receiver issues `Recv` with a designated reply slot | ~~GAP~~ → FIXED in 36d. `Recv(ep, ?, replyCap)` registers `Tcb.pending_reply`; Call binds `Reply.bound_tcb` to caller; Send-on-Cap::Reply walks the binding to wake the caller. Legacy `Tcb.reply_to` stash kept as a fallback for kernel specs. | **MATCH** |
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
