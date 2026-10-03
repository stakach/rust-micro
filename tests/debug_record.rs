#[path = "../src/debug_record.rs"]
mod debug_record;
#[path = "../src/ipc_buffer.rs"]
mod ipc_buffer;

use debug_record::{capture_and_emit, translate_x86_user, DebugRecordError, MAX_RECORD_BYTES};
use std::cell::RefCell;

#[test]
fn ipc_layout_leaves_a_distinct_unused_tail_in_a_four_kib_frame() {
    assert_eq!(ipc_buffer::SIZE_BYTES, 1024);
    let last_word = 4096 - core::mem::size_of::<usize>();
    assert!(last_word >= ipc_buffer::SIZE_BYTES);
    assert!(ipc_buffer::RECEIVE_DEPTH_OFFSET * 8 < ipc_buffer::SIZE_BYTES);
}

#[test]
fn captures_entire_record_before_single_exact_emission() {
    let events = RefCell::new(Vec::new());
    let bytes = b"a\0b\nno-added-newline";
    capture_and_emit(0x1ff8, bytes.len(), |address, output| {
        events.borrow_mut().push("read");
        let offset = (address - 0x1ff8) as usize;
        output.copy_from_slice(&bytes[offset..offset + output.len()]);
        Ok(())
    }, |record| {
        events.borrow_mut().push("emit");
        assert_eq!(record, bytes);
    }).unwrap();
    assert_eq!(*events.borrow(), ["read", "read", "emit"]);
}

#[test]
fn accepts_page_sized_record_and_emits_once() {
    assert_eq!(MAX_RECORD_BYTES, 4096);
    let bytes: Vec<u8> = (0..MAX_RECORD_BYTES).map(|i| i as u8).collect();
    let mut emitted = Vec::new();
    capture_and_emit(0x2000, bytes.len(), |address, output| {
        let offset = (address - 0x2000) as usize;
        output.copy_from_slice(&bytes[offset..offset + output.len()]);
        Ok(())
    }, |record| emitted.push(record.to_vec())).unwrap();
    assert_eq!(emitted, [bytes]);
}

#[test]
fn empty_record_has_no_read_or_output_effect() {
    capture_and_emit(0, 0, |_, _| panic!("empty read"), |_| panic!("empty emit")).unwrap();
}

#[test]
fn rejects_invalid_extent_before_any_effect() {
    for (address, length) in [
        (0x1000, MAX_RECORD_BYTES + 1),
        (u64::MAX - 1, 4),
        ((1u64 << 47) - 2, 4),
        (1u64 << 47, 1),
        (0xffff_8000_0000_0000, 1),
    ] {
        assert!(capture_and_emit(address, length, |_, _| panic!("invalid read"),
            |_| panic!("invalid emit")).is_err());
    }
}

#[test]
fn late_missing_page_never_emits_a_partial_record() {
    let mut reads = 0;
    let mut emits = 0;
    let result = capture_and_emit(0x1ffc, 8, |address, output| {
        reads += 1;
        if address == 0x2000 { return Err(DebugRecordError::Unreadable); }
        output.fill(b'x');
        Ok(())
    }, |_| emits += 1);
    assert_eq!(result, Err(DebugRecordError::Unreadable));
    assert_eq!((reads, emits), (2, 0));
}

fn entry(table: u64, index: usize, leaf: u64, denied_level: Option<usize>) -> Option<u64> {
    let level = (table / 0x1000 - 1) as usize;
    if level > 3 || index != 0 { return None; }
    let flags = if denied_level == Some(level) { 1 } else { 5 };
    Some(if level == 3 { leaf | flags } else { (table + 0x1000) | flags })
}

#[test]
fn x86_small_page_requires_user_present_at_every_level() {
    assert_eq!(translate_x86_user(0x1000, 0x321, |table, index|
        entry(table, index, 0x9000, None)), Some((0x9321, 0xcdf)));
    for denied in 0..4 {
        assert_eq!(translate_x86_user(0x1000, 0x321, |table, index|
            entry(table, index, 0x9000, Some(denied))), None);
        assert_eq!(translate_x86_user(0x1000, 0x321, |table, index| {
            let level = (table / 0x1000 - 1) as usize;
            if level == denied { Some(0) } else { entry(table, index, 0x9000, None) }
        }), None);
    }
}

#[test]
fn x86_large_and_huge_user_leaves_preserve_offsets() {
    assert_eq!(translate_x86_user(0x1000, 0x1234, |table, _| match table {
        0x1000 => Some(0x2005), 0x2000 => Some(0x3005),
        0x3000 => Some(0x20_0085), _ => panic!("walk below large leaf"),
    }), Some((0x20_1234, 0x20_0000 - 0x1234)));
    assert_eq!(translate_x86_user(0x1000, 0x1234, |table, _| match table {
        0x1000 => Some(0x2005), 0x2000 => Some(0x4000_0085),
        _ => panic!("walk below huge leaf"),
    }), Some((0x4000_1234, 0x4000_0000 - 0x1234)));
}

#[test]
fn x86_rejects_invalid_root_and_supervisor_ranges_before_table_read() {
    for (root, address) in [(0, 0), (0x1001, 0), (0x1000, 1u64 << 47),
        (0x1000, u64::MAX)] {
        assert_eq!(translate_x86_user(root, address, |_, _| panic!("invalid walk")), None);
    }
    assert_eq!(translate_x86_user(0x1000, 0, |_, _| Some(0x2085)), None,
        "PML4 cannot contain a large leaf");
}

#[cfg(target_arch = "aarch64")]
#[test]
fn arm_user_page_requires_el0_access_and_accessible_tables() {
    use debug_record::translate_arm_user;
    let walk = |table, _| Some(match table {
        0x1000 => 0x2003, 0x2000 => 0x3003,
        0x3000 => 0x4003, 0x4000 => 0x9043, _ => 0,
    });
    assert_eq!(translate_arm_user(0x1000, 0x321, walk), Some((0x9321, 0xcdf)));
    for denied in [0x1000, 0x2000, 0x3000, 0x4000] {
        assert_eq!(translate_arm_user(0x1000, 0x321, |table, index| {
            let value = walk(table, index)?;
            Some(if table != denied { value } else if table == 0x4000 {
                value & !(1 << 6)
            } else { value | (1 << 61) })
        }), None);
        assert_eq!(translate_arm_user(0x1000, 0x321, |table, index| {
            if table == denied { Some(0) } else { walk(table, index) }
        }), None);
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn arm_user_blocks_preserve_offsets_and_reject_misaligned_frames() {
    use debug_record::translate_arm_user;
    for (leaf_table, frame, size) in [(0x2000, 0x4000_0000, 1u64 << 30),
        (0x3000, 0x20_0000, 1u64 << 21)] {
        let walk = |table, _| Some(if table == leaf_table { frame | 0x41 }
            else { (table + 0x1000) | 3 });
        assert_eq!(translate_arm_user(0x1000, 0x1234, walk),
            Some((frame + 0x1234, size - 0x1234)));
        assert_eq!(translate_arm_user(0x1000, 0x1234, |table, index| {
            walk(table, index).map(|value| if table == leaf_table { value | 0x1000 }
                else { value })
        }), None);
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn arm_rejects_invalid_root_range_and_top_level_block() {
    use debug_record::translate_arm_user;
    for (root, address) in [(0, 0), (0x1001, 0), (0x1000, 1u64 << 47),
        (0x1000, u64::MAX)] {
        assert_eq!(translate_arm_user(root, address, |_, _| panic!("invalid walk")), None);
    }
    assert_eq!(translate_arm_user(0x1000, 0, |_, _| Some(0x2041)), None);
}
