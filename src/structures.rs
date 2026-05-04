// Generated bitfield types for seL4 capabilities and kernel-object
// headers. The actual contents come from build.rs at compile time and
// are written into $OUT_DIR/structures.rs from
// codegen/structures_64.bf.
//
// The lint allows below apply to all generated code: field/method
// names are kept in seL4's camelCase to make grepping across both
// codebases trivial.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/structures.rs"));

/// Arch-specific bitfield types (x86_64): frame_cap, page_table_cap,
/// page_directory_cap, pdpt_cap, pml4_cap, asid_pool_cap, io_port_cap,
/// plus PTE/PDE/PDPTE/PML4E and GDT/IDT/TSS layouts.
pub mod arch {
    include!(concat!(env!("OUT_DIR"), "/structures_arch.rs"));
}
