//! Phase 39 — initrd (USTAR tar) walker.
//!
//! BOOTBOOT loads an initrd into RAM at `bootboot.initrd_ptr` (a
//! physical address that's also a valid virtual address while the
//! BOOTBOOT identity map at PML4[0] is live). We pack the initrd as
//! a USTAR tar so the kernel and any userspace ELFs can be shipped
//! as separate files inside one archive — see `scripts/make_image.sh`.
//!
//! BOOTBOOT extracts `sys/core` from the archive and dispatches that
//! as the kernel; everything else is left in place for the kernel to
//! enumerate at runtime via `find_file()`.
//!
//! USTAR layout (https://www.gnu.org/software/tar/manual/html_node/Standard.html):
//!   * 512-byte header per entry
//!     - bytes 0..100  : filename (NUL-terminated, may be shorter)
//!     - bytes 124..136: file size in octal ASCII (NUL-terminated)
//!     - byte 156      : type flag ('0' or '\0' = regular file)
//!   * file data follows the header, padded to a 512-byte boundary
//!   * archive ends with two consecutive 512-byte zero blocks

use crate::bootboot::{BOOTBOOT, BOOTBOOT_INFO};

const BLOCK: usize = 512;

/// Read the initrd location BOOTBOOT exposed in its info struct.
/// Safe because BOOTBOOT_INFO is mapped read-only at a fixed kernel
/// vaddr and the initrd lives in the lower-half identity map.
pub fn slice() -> &'static [u8] {
    let bb = unsafe { &*(BOOTBOOT_INFO as *const BOOTBOOT) };
    let ptr = bb.initrd_ptr as usize;
    let size = bb.initrd_size as usize;
    if ptr == 0 || size == 0 {
        return &[];
    }
    unsafe { core::slice::from_raw_parts(ptr as *const u8, size) }
}

/// Find a file in the initrd by its full path (e.g.
/// `"boot/rootserver"`). Returns the file's bytes as a slice into
/// the initrd memory, or `None` if not present.
///
/// The output borrows from the input — callers that pass a
/// `&'static [u8]` (the live BOOTBOOT initrd) get back
/// `Option<&'static [u8]>` automatically.
pub fn find_file<'a>(initrd: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let mut off = 0;
    while off + BLOCK <= initrd.len() {
        let header = &initrd[off..off + BLOCK];
        // Two zero blocks (or a single one being read here) signal
        // end of archive.
        if header.iter().all(|&b| b == 0) {
            return None;
        }

        let fname_len = header[..100].iter().position(|&b| b == 0).unwrap_or(100);
        let fname = match core::str::from_utf8(&header[..fname_len]) {
            Ok(s) => s,
            Err(_) => return None,
        };

        // Size field: octal ASCII, NUL- or space-terminated.
        let size_field = &header[124..136];
        let size_str_end = size_field.iter()
            .position(|&b| b == 0 || b == b' ')
            .unwrap_or(size_field.len());
        let size_str = match core::str::from_utf8(&size_field[..size_str_end]) {
            Ok(s) => s,
            Err(_) => return None,
        };
        let size = match u64::from_str_radix(size_str.trim(), 8) {
            Ok(n) => n as usize,
            Err(_) => return None,
        };

        if fname == name {
            let start = off + BLOCK;
            let end = start.checked_add(size)?;
            if end > initrd.len() {
                return None;
            }
            return Some(&initrd[start..end]);
        }

        // Advance: header (512) + data (rounded up to 512).
        let data_blocks = (size + BLOCK - 1) / BLOCK;
        off = off.checked_add(BLOCK + data_blocks * BLOCK)?;
    }
    None
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_initrd() {
        arch::log("Running initrd tests...\n");
        finds_rootserver_in_live_initrd();
        rejects_missing_file();
        synthetic_archive_round_trip();
        arch::log("initrd tests completed\n");
    }

    #[inline(never)]
    fn finds_rootserver_in_live_initrd() {
        let initrd = slice();
        assert!(!initrd.is_empty(), "BOOTBOOT initrd must be non-empty");
        let elf = find_file(initrd, "boot/rootserver")
            .expect("boot/rootserver must be present in initrd");
        // ELF magic.
        assert_eq!(&elf[0..4], b"\x7fELF",
            "boot/rootserver must start with ELF magic");
        arch::log("  ✓ initrd carries boot/rootserver as an ELF\n");
    }

    #[inline(never)]
    fn rejects_missing_file() {
        let initrd = slice();
        assert!(find_file(initrd, "this/does/not/exist").is_none());
        arch::log("  ✓ find_file returns None for missing entries\n");
    }

    /// Build a minimal in-memory tar archive and verify the walker
    /// extracts each file's bytes correctly. Doesn't depend on what
    /// BOOTBOOT loaded.
    #[inline(never)]
    fn synthetic_archive_round_trip() {
        // Two 512-byte headers, each followed by 512 bytes of data
        // (padded), then two zero terminator blocks. Total 4 * 512.
        let mut archive = [0u8; 4 * BLOCK];
        // First entry: name = "a", size = 3 ("ABC")
        archive[0] = b'a';
        // size field bytes 124..136: "0000000003\0\0"
        archive[124..134].copy_from_slice(b"0000000003");
        // typeflag '0' = regular file
        archive[156] = b'0';
        archive[BLOCK..BLOCK + 3].copy_from_slice(b"ABC");

        // Second entry at offset 2*BLOCK: name = "b/c", size = 5
        archive[2 * BLOCK..2 * BLOCK + 3].copy_from_slice(b"b/c");
        archive[2 * BLOCK + 124..2 * BLOCK + 134]
            .copy_from_slice(b"0000000005");
        archive[2 * BLOCK + 156] = b'0';
        archive[3 * BLOCK..3 * BLOCK + 5].copy_from_slice(b"hello");
        // Trailer: rest stays zero (already), which terminates parse.

        assert_eq!(find_file(&archive, "a"), Some(b"ABC".as_ref()));
        assert_eq!(find_file(&archive, "b/c"), Some(b"hello".as_ref()));
        assert!(find_file(&archive, "c").is_none());
        arch::log("  ✓ tar walker round-trips a synthetic archive\n");
    }
}
