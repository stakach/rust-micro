ENTRY(_start)

PHDRS
{
  loader PT_LOAD FLAGS(7);
}

SECTIONS
{
  . = 0x40080000;

  .text : {
    KEEP(*(.text.boot))
    *(.text .text.*)
    . = ALIGN(4096);
  } :loader

  .rodata : {
    *(.rodata .rodata.*)
    . = ALIGN(4096);
  } :loader

  .data : {
    *(.data .data.*)
    . = ALIGN(4096);
  } :loader

  .bss (NOLOAD) : {
    __bss_start = .;
    *(.bss .bss.*) *(COMMON)
    . = ALIGN(4096);
    __bss_end = .;
  } :loader

  __image_end = .;

  /DISCARD/ : { *(.eh_frame) *(.comment) *(.note*) }
}
