//! Embedded rootserver ELF — Phase 29a.
//!
//! The kernel and the rootserver are two separate Rust crates.
//! `scripts/build_kernel.sh` compiles the rootserver first and the
//! kernel `include_bytes!`s the resulting ELF here. Phases 29b/c
//! parse this slice and load its segments into a fresh user VSpace
//! before dispatching the rootserver TCB.

/// The rootserver's compiled ELF64 image. Statically linked at the
/// vaddr range chosen by `rootserver/link.ld` (PML4[2], starting at
/// 0x100_0040_0000 — see lessons.md for why we avoid PML4[0]).
pub static ROOTSERVER_ELF: &[u8] = include_bytes!(
    "../rootserver/target/triplet/release/rootserver"
);
