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
