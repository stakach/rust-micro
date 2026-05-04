/*
 * Phase 38b — kernel-config header that drives libsel4's #if blocks.
 * Mirrors the CONFIG_KERNEL_MCS=true / x86_64 / debug build that
 * matches our Rust kernel's ABI.
 *
 * Real seL4 generates this file via Kbuild + CMake from a `.cfg`
 * file. Ours is hand-written.
 */

#pragma once

/* Architecture */
#define CONFIG_ARCH_X86         1
#define CONFIG_ARCH_X86_64      1
#define CONFIG_X86_64           1
#define CONFIG_WORD_SIZE        64

/* Use the SYSCALL instruction (not SYSENTER). Our kernel's
 * `syscall_entry` reads MSR-based handler registration. */
#define CONFIG_SYSCALL          1

/* MCS scheduler — Phase 32a flipped this on. */
#define CONFIG_KERNEL_MCS       1

/* Debug build for `seL4_DebugPutChar` etc. */
#define CONFIG_PRINTING         1
#define CONFIG_DEBUG_BUILD      1

/* SMP — we run 4 cores in QEMU. */
#define CONFIG_MAX_NUM_NODES    4
#define CONFIG_ENABLE_SMP_SUPPORT 1

/* Boot info — match our seL4_BootInfo's untypedList sizing. */
#define CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS 230

/* Domains — single domain. */
#define CONFIG_NUM_DOMAINS      1

/* Priority levels (0..255). seL4_MaxPrio = N-1. */
#define CONFIG_NUM_PRIORITIES   256

/* IRQ vector range. */
#define CONFIG_IRQ_REPORTING    1

/* Maximum CSpace depth (libsel4 uses for some defaults). */
#define CONFIG_MAX_CNODE_BITS   16

/* Page sizes / paging structure — x86_64 4-level. */
#define CONFIG_X86_64_VTX_64_BIT_GUESTS 0

/* Disable features we don't model. */
#define CONFIG_HARDWARE_DEBUG_API 0
#define CONFIG_BENCHMARK_NONE     1
#define CONFIG_VTX                0
#define CONFIG_IOMMU              0
#define CONFIG_HAVE_FPU           0

/* libsel4 prints invocation errors via this when present.
 * We don't, so leave undefined. */
/* #define CONFIG_KERNEL_INVOCATION_REPORT_ERROR_IPC 1 */
/* #define CONFIG_LIB_SEL4_PRINT_INVOCATION_ERRORS   0 */
