# Active phase plan — Phase 19: Frame::Map + arch caps

## Goal
Make x86 Frame caps first-class — typed `Cap::Frame` variant with
`Map` / `Unmap` / `GetAddress` invocations. Once this lands,
userspace can allocate a page from an Untyped, map it at a chosen
vaddr, and access the memory.

`PageTable` / `PageDirectory` / `PDPT` are deferred — Phase 13b's
page-table installer auto-allocates intermediate tables on demand,
so we don't need explicit cap-chain installs to demo Frame::Map.
ASID management (`AsidPool::Assign`, `AsidControl::MakePool`) is
also deferred — we use a single shared ASID for now.

## Plan

- [x] 19a — Extend `Cap` enum with `Frame { ptr, size, rights,
  mapped, asid, is_device }` variant. `from_words` / `to_words`
  via the generated `FrameCap` bitfield.
- [x] 19b — `make_object_cap` for `ObjectType::Arch(frame_size)`
  (so Untyped::Retype can produce Frame caps).
- [x] 19c — `decode_invocation` for `Cap::Frame`: X86PageMap,
  X86PageUnmap, X86PageGetAddress.
- [x] 19d — Specs: round-trip Frame cap (mapped + unmapped),
  Map verifies PTE via `live_virt_to_phys`, double-Map is
  DeleteFirst, Unmap clears the cap.

## ABI notes
- Invocation labels:
  - X86PageMap = (decoded by codegen — appears in `InvocationLabel`)
  - X86PageUnmap
  - X86PageGetAddress
- Map ABI (compressed): a2 = vaddr, a3 = rights bits, a4 = unused
- GetAddress ABI: returns paddr in the result; we stuff it into
  the caller's tcb.msg_regs[0] so user can read after sysret.

## Verification
1. Build clean.
2. New invocation specs pass.
3. Existing 124 ✓ specs unchanged.
4. User-mode IPC demo (`PM`) still works.

## Review

* All 4 sub-tasks complete. 8 invocation specs now pass (was 7).
* End-to-end Frame::Map verified by walking the live page tables
  with `paging::live_virt_to_phys` — proves the cap-shaped
  invocation actually installed the right PTE.
* Phase 13c arch round-trip spec needed a tweak: it relied on
  tag=1 falling through to `Cap::Arch`, but tag=1 is now Frame.
  Switched the test to tag=3 (page_table — still un-typed).
* User-mode IPC demo unchanged — 124 → 126 ✓ specs.
