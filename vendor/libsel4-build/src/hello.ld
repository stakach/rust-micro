/*
 * Hello-world user-ELF link layout — Phase 38d.
 *
 * Mirrors `rootserver/link.ld`: text + rodata + data + bss laid out
 * starting at vaddr 0x0000_0100_0040_0000 (PML4[2]). The kernel's
 * ELF loader walks PT_LOAD segments and maps them at these vaddrs
 * in the rootserver's PML4. PML4[2] avoids BOOTBOOT's identity
 * mapping at PML4[0].
 *
 * Entry: _start. Single function defined in hello.c; libsel4
 * assertion stub `__assert_fail` is referenced indirectly.
 */

ENTRY(_start)

SECTIONS {
    . = 0x0000010000400000;

    /* -mcmodel=large + -ffunction-sections emits .ltext.<func>; we
     * roll those up into one .text segment, with _start first. */
    .text : {
        *(.text._start)
        *(.ltext._start)
        *(.text .text.*)
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
