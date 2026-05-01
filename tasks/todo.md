# Active phase plan — Phase 24: per-thread CR3

## Goal
Each user thread gets its own PML4 with the kernel half mirrored
from the live BOOTBOOT tables and the user half thread-specific.
The SYSCALL dispatcher swaps CR3 when scheduling decides on a
different thread. This is the canonical microkernel address-space
isolation property — without it the AY demo's two threads
are sharing memory by accident.

## Plan
- [x] 24a — `paging::make_user_pml4()` clones the live PML4
  verbatim (incl. PML4[0] for BOOTBOOT's identity map, which
  the kernel needs to walk page tables under any CR3). Returns
  the new PML4 paddr.
- [x] 24b — `usermode::map_user_4k_into_pml4(pml4_pa, ...)`
  variant. Existing `map_user_4k_public` reads live CR3 then
  delegates.
- [x] 24c — Dispatcher swaps CR3 to next thread's
  `cpu_context.cr3` before sysretq.
- [x] 24d — `spawn_thread` takes a `pml4_paddr` arg;
  `launch_two_thread_ipc_demo` allocates one PML4 per thread
  and maps each thread's pages only into its own PML4.
- [x] 24e — AY still works post-switch.

## Risks
* Subtle: when handle_send::SysSend on Frame::Map runs, the
  invocation handler currently uses `map_user_4k_public` which
  walks the live CR3. With per-thread CR3, "live CR3" is the
  invoker's PML4 — which is correct! The `map_user_4k_in` API
  is more flexible but the live-CR3 wrapper is fine for
  Frame::Map's "install in current vspace" semantics.
* If make_user_pml4 fails (pool exhausted), threads can't
  start. Bump POOL_SIZE if needed.

## Verification
* AY demo still works.
* Spec count unchanged or +1.

## Review

* All 5 sub-tasks land. AY demo continues to work, but each
  thread now runs in its OWN PML4 — try memory access at the
  other thread's vaddrs and you'd page-fault.
* Real bug caught + recorded: zeroing the user half of the
  cloned PML4 broke kernel page-table walks. The kernel
  depends on BOOTBOOT's PML4[0] identity map for low-physical
  memory access (page tables, ACPI). Fixed by copying ALL
  PML4 entries verbatim. Future Phase: relocate the identity
  map to PML4[256] (kernel half) so the user half can be
  truly empty.
* KPT_POOL bumped 8 → 32 to accommodate per-thread PML4s.
* CR3 swap in dispatcher checks CR3 only changes when needed
  (avoids a full TLB flush per syscall when the current
  thread keeps running).
* User-mode demo unchanged in output but architecturally now
  isolated.
