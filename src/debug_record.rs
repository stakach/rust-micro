//! Bounded debug records: capture caller bytes completely before serial effects.

pub const MAX_RECORD_BYTES: usize = 4096;
const USER_END: u64 = 1 << 47;
const PHYSICAL_MASK: u64 = 0x000f_ffff_ffff_f000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DebugRecordError {
    InvalidRange,
    TooLong,
    Unreadable,
}

#[cfg(all(feature = "spec", target_arch = "x86_64"))]
#[path = "debug_record_spec.rs"]
pub mod spec;

pub fn capture_and_emit(
    address: u64,
    length: usize,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<(), DebugRecordError>,
    mut emit: impl FnMut(&[u8]),
) -> Result<(), DebugRecordError> {
    if length > MAX_RECORD_BYTES { return Err(DebugRecordError::TooLong); }
    if length == 0 { return Ok(()); }
    let end = address.checked_add(length as u64).ok_or(DebugRecordError::InvalidRange)?;
    if address >= USER_END || end > USER_END { return Err(DebugRecordError::InvalidRange); }
    let mut bytes = [0u8; MAX_RECORD_BYTES];
    let mut copied = 0;
    while copied < length {
        let current = address + copied as u64;
        let count = (4096 - (current as usize & 4095)).min(length - copied);
        read(current, &mut bytes[copied..copied + count])?;
        copied += count;
    }
    emit(&bytes[..length]);
    Ok(())
}

/// Resolve only present user-readable leaves from the exact caller's root.
/// The entry reader must access kernel-owned page tables while mapping mutation is excluded.
pub fn translate_x86_user(
    root: u64,
    address: u64,
    mut entry: impl FnMut(u64, usize) -> Option<u64>,
) -> Option<(u64, u64)> {
    if root == 0 || root & 4095 != 0 || root & !PHYSICAL_MASK != 0 || address >= USER_END {
        return None;
    }
    let mut table = root;
    for shift in [39u32, 30, 21, 12] {
        let value = entry(table, ((address >> shift) & 511) as usize)?;
        if value & 5 != 5 { return None; }
        let large = value & 128 != 0;
        if shift == 39 && large { return None; }
        if shift == 12 || large {
            let size = 1u64 << shift;
            let offset = address & (size - 1);
            // Large-page PAT lives at bit 12; all other low address bits must be zero.
            if shift != 12 && value & PHYSICAL_MASK & (size - 1) & !4096 != 0 {
                return None;
            }
            let physical = (value & PHYSICAL_MASK & !(size - 1)).checked_add(offset)?;
            return Some((physical, size - offset));
        }
        table = value & PHYSICAL_MASK;
        if table == 0 { return None; }
    }
    None
}

#[cfg(target_arch = "aarch64")]
pub fn translate_arm_user(
    root: u64,
    address: u64,
    mut entry: impl FnMut(u64, usize) -> Option<u64>,
) -> Option<(u64, u64)> {
    if root == 0 || root & 4095 != 0 || root & !PHYSICAL_MASK != 0 || address >= USER_END {
        return None;
    }
    let mut table = root;
    for shift in [39u32, 30, 21, 12] {
        let value = entry(table, ((address >> shift) & 511) as usize)?;
        if value & 1 == 0 { return None; }
        let leaf = if shift == 12 { value & 3 == 3 } else { shift != 39 && value & 3 == 1 };
        if leaf {
            if value & (1 << 6) == 0 { return None; }
            let size = 1u64 << shift;
            let offset = address & (size - 1);
            if value & PHYSICAL_MASK & (size - 1) != 0 { return None; }
            return Some(((value & PHYSICAL_MASK).checked_add(offset)?, size - offset));
        }
        if value & 3 != 3 || value & (1 << 61) != 0 { return None; }
        table = value & PHYSICAL_MASK;
        if table == 0 { return None; }
    }
    None
}
