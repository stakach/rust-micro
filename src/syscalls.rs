// Generated syscall and invocation-label enums. The contents come
// from build.rs at compile time; see codegen/syscall.xml and
// codegen/object-api*.xml for the source of truth.
//
// The lint allows below cover the generated identifiers, which keep
// seL4's PascalCase naming so they grep cleanly across both
// codebases (`SysCall`, `TCBSetPriority`, etc.).

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

pub mod syscall {
    include!(concat!(env!("OUT_DIR"), "/syscalls.rs"));
}

pub mod invocation {
    include!(concat!(env!("OUT_DIR"), "/invocations.rs"));
}

pub use invocation::InvocationLabel;
pub use syscall::Syscall;
