//! Budget for the "no next thread, idling CPU" tags a CPU logs when it goes idle.
//!
//! On a multicore desktop a CPU goes idle after nearly every user fault or syscall trap that
//! blocks its thread, so an unbudgeted tag prints thousands of times. Each tag is reported on
//! its first sighting and then every `REPORT_EVERY`th time, with its running count; the rest
//! are only counted. Tags are told apart by their identity (address and length), and a small
//! fixed table holds them. Once the table is full, further distinct tags share the last slot,
//! so nothing goes uncounted.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub const REPORT_EVERY: u64 = 1000;
const SLOTS: usize = 16;

pub struct IdleLogBudget {
    tags: [AtomicUsize; SLOTS],
    counts: [AtomicU64; SLOTS],
}

impl IdleLogBudget {
    pub const fn new() -> Self {
        Self {
            tags: [const { AtomicUsize::new(0) }; SLOTS],
            counts: [const { AtomicU64::new(0) }; SLOTS],
        }
    }

    /// Count one idle transition for `tag`. Returns the running count when this one should
    /// be printed: the first sighting and every `REPORT_EVERY`th. An empty tag never prints.
    pub fn admit(&self, tag: &str) -> Option<u64> {
        if tag.is_empty() {
            return None;
        }
        // Address and length together: distinct literals never share both.
        let key = (tag.as_ptr() as usize) ^ tag.len().rotate_left(48);
        let key = key.max(1);
        let slot = self.slot(key);
        let count = self.counts[slot].fetch_add(1, Ordering::Relaxed) + 1;
        (count == 1 || count % REPORT_EVERY == 0).then_some(count)
    }

    fn slot(&self, key: usize) -> usize {
        for slot in 0..SLOTS {
            match self.tags[slot].compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return slot,
                Err(current) if current == key => return slot,
                Err(_) => continue,
            }
        }
        SLOTS - 1
    }
}
