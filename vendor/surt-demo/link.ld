/* Rootserver link layout — Phase 29a.
 *
 * The rootserver runs in ring 3 in its own VSpace (a fresh PML4
 * cloned by the kernel before dispatch). We place the image inside
 * PML4[2] so it doesn't collide with BOOTBOOT's 1 GiB identity
 * mapping at PML4[0] (see lessons.md "BOOTBOOT MMIO behaviour").
 *
 *   text + rodata at 0x100_0040_0000
 *   data + bss following
 *
 * The kernel's ELF loader walks PT_LOAD segments and maps them at
 * these vaddrs in the rootserver's PML4. Layout is fixed so the
 * kernel can compute the final mapped pages deterministically.
 */

ENTRY(_start)

SECTIONS {
    . = 0x0000010000400000;

    .text : {
        *(.text._start)
        *(.text .text.*)
        /* Large-code-model text — code that references the surt-core crate
         * lands here. Must be in this loadable, executable segment or a
         * spawned thread whose entry is such a function never runs. */
        *(.ltext .ltext.*)
    }

    . = ALIGN(0x1000);
    .rodata : {
        *(.rodata .rodata.*)
        *(.lrodata .lrodata.*)
    }

    . = ALIGN(0x1000);
    .data : {
        *(.data .data.*)
        *(.ldata .ldata.*)
    }

    . = ALIGN(0x1000);
    .bss : {
        *(.bss .bss.*)
        /* Large-model BSS (e.g. the SURT ring/stack statics) — must sit in
         * the zeroed, mapped .bss segment. */
        *(.lbss .lbss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.note.*)
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.gnu.build.id)
    }
}
