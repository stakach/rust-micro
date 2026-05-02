//! Rootserver ELF locator — Phase 29a / 39.
//!
//! Pre-Phase-39 the kernel embedded the rootserver ELF at compile
//! time via `include_bytes!`, which forced a kernel rebuild every
//! time the userspace changed. We now ship the rootserver as a
//! sibling file inside the BOOTBOOT initrd (a USTAR tar archive
//! containing both `sys/core` = kernel and `boot/rootserver` =
//! rootserver). The kernel parses the initrd at runtime via
//! `crate::initrd::find_file()`.
//!
//! `scripts/make_image.sh` packs the chosen rootserver ELF (Rust
//! rootserver by default; `vendor/libsel4-build/out/hello.elf` when
//! the `libsel4-hello` cargo feature is enabled at the *make_image*
//! step) into the archive — see that script for the build wiring.
//!
//! The path inside the initrd is fixed at `boot/rootserver`.

const ROOTSERVER_PATH: &str = "boot/rootserver";

/// The rootserver's ELF64 image, located inside the BOOTBOOT initrd.
/// Panics if the initrd doesn't carry a `boot/rootserver` entry —
/// the kernel can't proceed without one and there's no useful
/// recovery from this state at boot.
pub fn rootserver_elf() -> &'static [u8] {
    let initrd = crate::initrd::slice();
    crate::initrd::find_file(initrd, ROOTSERVER_PATH).unwrap_or_else(|| {
        panic!("initrd missing required entry {:?}", ROOTSERVER_PATH);
    })
}
