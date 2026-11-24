//! Host fixture for the real Simpleboot memory-map tag walker.

extern crate self as bootstrap_clock;
pub struct WallClockSnapshot;
#[derive(PartialEq)]
pub struct PcRtcRegisters {
    second: u8,
    minute: u8,
    hour: u8,
    day: u8,
    month: u8,
    year: u8,
    century: u8,
}

pub fn decode_pc_rtc_utc(_: PcRtcRegisters, _: u8) -> Result<WallClockSnapshot, ()> {
    Err(())
}

mod arch {
    pub fn phys_to_virt(paddr: u64) -> u64 {
        paddr
    }

    pub fn get_cpu_id() -> u32 {
        0
    }

    pub mod x86_64 {
        pub mod acpi {
            pub struct PcRtc {
                pub index_port: u16,
                pub data_port: u16,
                pub century_register: Option<u8>,
            }

            pub fn find_pc_rtc(_: u64) -> Result<PcRtc, ()> {
                Err(())
            }
        }
    }
}

#[allow(dead_code)]
#[path = "../src/simpleboot.rs"]
mod simpleboot;

use std::sync::Mutex;

static MBI_OWNER: Mutex<()> = Mutex::new(());

#[cfg(legacy_mmap_walker)]
fn walk(f: impl FnMut(simpleboot::MMapEntry)) -> Result<(), ()> {
    simpleboot::for_each_mmap_entry(f);
    Ok(())
}

#[cfg(not(legacy_mmap_walker))]
fn walk(f: impl FnMut(simpleboot::MMapEntry)) -> Result<(), ()> {
    simpleboot::try_for_each_mmap_entry(f).map_err(|_| ())
}

fn mmap_tag(base: u64, stride: u32) -> Vec<u8> {
    let mut tag = Vec::new();
    tag.extend_from_slice(&simpleboot::MULTIBOOT_TAG_TYPE_MMAP.to_le_bytes());
    tag.extend_from_slice(&(40u32).to_le_bytes());
    tag.extend_from_slice(&stride.to_le_bytes());
    tag.extend_from_slice(&0u32.to_le_bytes());
    tag.extend_from_slice(&base.to_le_bytes());
    tag.extend_from_slice(&4096u64.to_le_bytes());
    tag.extend_from_slice(&simpleboot::MULTIBOOT_MEMORY_AVAILABLE.to_le_bytes());
    tag.extend_from_slice(&0u32.to_le_bytes());
    tag
}

fn mbi(tags: &[Vec<u8>], terminal: Option<(u32, usize)>) -> Vec<u64> {
    let mut bytes = vec![0u8; 8];
    for tag in tags {
        bytes.extend_from_slice(tag);
    }
    if let Some((size_field, physical_bytes)) = terminal {
        bytes.extend_from_slice(&simpleboot::MULTIBOOT_TAG_TYPE_END.to_le_bytes());
        bytes.extend_from_slice(&size_field.to_le_bytes());
        bytes.resize(bytes.len() + physical_bytes.saturating_sub(8), 0);
    }
    let total = u32::try_from(bytes.len()).unwrap();
    bytes[0..4].copy_from_slice(&total.to_le_bytes());
    let mut words = vec![0u64; bytes.len().div_ceil(8)];
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), words.as_mut_ptr() as *mut u8, bytes.len());
    }
    words
}

fn with_mbi<T>(words: Vec<u64>, f: impl FnOnce() -> T) -> T {
    let _owner = MBI_OWNER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    simpleboot::init(
        simpleboot::MULTIBOOT2_BOOTLOADER_MAGIC as u64,
        words.as_ptr() as u64,
    );
    f()
}

#[test]
fn valid_map_yields_exact_entry() {
    with_mbi(mbi(&[mmap_tag(0x4000, 24)], Some((8, 8))), || {
        let mut seen = Vec::new();
        assert_eq!(walk(|entry| seen.push(entry)), Ok(()));
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].base_addr, 0x4000);
        assert_eq!(seen[0].length, 4096);
    });
}

#[test]
fn duplicate_map_tag_is_rejected() {
    with_mbi(
        mbi(&[mmap_tag(0x4000, 24), mmap_tag(0x8000, 24)], Some((8, 8))),
        || assert!(walk(|_| {}).is_err()),
    );
}

#[test]
fn bad_entry_stride_is_rejected() {
    with_mbi(mbi(&[mmap_tag(0x4000, 16)], Some((8, 8))), || {
        assert!(walk(|_| {}).is_err())
    });
}

#[test]
fn malformed_terminal_tag_is_rejected() {
    with_mbi(mbi(&[mmap_tag(0x4000, 24)], Some((4, 8))), || {
        assert!(walk(|_| {}).is_err())
    });
}

#[test]
fn missing_terminal_tag_is_rejected() {
    with_mbi(mbi(&[mmap_tag(0x4000, 24)], None), || {
        assert!(walk(|_| {}).is_err())
    });
}
