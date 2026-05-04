/*
 * Phase 38d — minimal hello-world C user program built against
 * libsel4.a + our kernel's upstream-aligned SYSCALL ABI.
 *
 * Drop-in replacement for `rootserver/target/triplet/release/rootserver`
 * (an ELF the kernel `include_bytes!`s and dispatches at boot).
 *
 * The kernel passes a `seL4_BootInfo *` in rdi (System V first arg);
 * we hand it to `seL4_InitBootInfo` which sets `bootinfo` and the
 * IPC-buffer pointer libsel4's invocation wrappers consult.
 *
 * Then we use libsel4's inline `seL4_DebugPutChar` / `seL4_Yield`
 * stubs to print the sentinel and idle. Phase 38c-followup made our
 * kernel preserve `rax` across SYSCALL, matching upstream — so the
 * libsel4 stubs (which don't list rax as a clobber) are safe.
 */

#include <sel4/sel4.h>

/*
 * libsel4's assertion macros call `__assert_fail` on failure; we
 * provide a minimal no-return stub so the freestanding link
 * resolves without pulling in libc. Loops on Yield so the kernel
 * still has a chance to schedule something else.
 */
void __assert_fail(const char *expr, const char *file, int line,
                   const char *func)
{
    (void)expr; (void)file; (void)line; (void)func;
    for (;;) seL4_Yield();
}

static const char MESSAGE[] = "HELLO from libsel4\n";

void _start(seL4_BootInfo *bi)
{
    seL4_InitBootInfo(bi);

    for (const char *p = MESSAGE; *p; p++) {
        seL4_DebugPutChar(*p);
    }

    for (;;) {
        seL4_Yield();
    }
}
