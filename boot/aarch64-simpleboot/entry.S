.section .text.boot, "ax"
.balign 64
.global _start
.type _start, %function
_start:
    b loader_bsp_entry
    .long 0
    .quad 0x00080000
    .quad __image_end - _start
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .long 0x644d5241
    .long 0

.equ LOADER_STACK_SHIFT, 16
.equ SIMPLEBOOT_MAGIC_LO, 0x6289
.equ SIMPLEBOOT_MAGIC_HI, 0x36d7

loader_bsp_entry:
    mov x19, x0
    mrs x9, mpidr_el1
    and x9, x9, #0xff
    adrp x10, loader_stacks
    add x10, x10, :lo12:loader_stacks
    add x9, x9, #1
    lsl x9, x9, #LOADER_STACK_SHIFT
    add sp, x10, x9

    adrp x9, __bss_start
    add x9, x9, :lo12:__bss_start
    adrp x10, __bss_end
    add x10, x10, :lo12:__bss_end
1:
    cmp x9, x10
    b.hs 2f
    stp xzr, xzr, [x9], #16
    b 1b
2:
    mov x0, x19
    bl loader_main
3:
    wfe
    b 3b

.global loader_secondary_entry
.type loader_secondary_entry, %function
loader_secondary_entry:
    cmp x0, #4
    b.hs loader_park
    mov x19, x0
    adrp x9, loader_stacks
    add x9, x9, :lo12:loader_stacks
    add x10, x19, #1
    lsl x10, x10, #LOADER_STACK_SHIFT
    add sp, x9, x10

    adrp x9, loader_ap_online
    add x9, x9, :lo12:loader_ap_online
    mov w10, #1
    str w10, [x9, x19, lsl #2]
    dmb ish
    sev
1:
    adrp x9, loader_handoff_ready
    add x9, x9, :lo12:loader_handoff_ready
    ldar w10, [x9]
    cbnz w10, 2f
    wfe
    b 1b
2:
    adrp x9, loader_kernel_entry
    add x9, x9, :lo12:loader_kernel_entry
    ldr x2, [x9]
    adrp x9, loader_mbi_address
    add x9, x9, :lo12:loader_mbi_address
    ldr x1, [x9]
    movz x0, #SIMPLEBOOT_MAGIC_LO
    movk x0, #SIMPLEBOOT_MAGIC_HI, lsl #16
    br x2

.global loader_enter_kernel
.type loader_enter_kernel, %function
loader_enter_kernel:
    mov x2, x0
    mov x1, x1
    movz x0, #SIMPLEBOOT_MAGIC_LO
    movk x0, #SIMPLEBOOT_MAGIC_HI, lsl #16
    br x2

loader_park:
    wfe
    b loader_park
