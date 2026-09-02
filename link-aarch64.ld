/* Initial QEMU virt AArch64 layout. Hardware entry and MMU bring-up are
 * intentionally separate milestones; this script establishes a linkable ELF. */
ENTRY(_start)

PHDRS
{
  kernel PT_LOAD FLAGS(7);
}

SECTIONS
{
  . = 0x40200000;

  .text : {
    KEEP(*(.text.boot))
    *(.text .text.* .gnu.linkonce.t*)
    . = ALIGN(4096);
  } :kernel

  .rodata : {
    *(.rodata*)
    . = ALIGN(4096);
  } :kernel

  .data : {
    *(.data*)
    . = ALIGN(4096);
  } :kernel

  .bss (NOLOAD) : {
    __bss_start = .;
    *(.bss*) *(COMMON)
    . = ALIGN(4096);
    __bss_end = .;
  } :kernel

  __kernel_end = .;

  /DISCARD/ : { *(.eh_frame) *(.comment) }
}
