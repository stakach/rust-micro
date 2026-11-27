#[path = "../src/idle_log_budget.rs"]
mod idle_log_budget;

use idle_log_budget::{IdleLogBudget, REPORT_EVERY};

const PF: &str = "[user #PF: no next thread, idling CPU]\n";
const SYSCALL: &str = "[unknown syscall: no next thread, idling CPU]\n";

#[test]
fn a_tag_prints_on_first_sighting_and_every_thousandth_time() {
    let budget = IdleLogBudget::new();
    let printed: Vec<u64> = (0..3 * REPORT_EVERY).filter_map(|_| budget.admit(PF)).collect();
    assert_eq!(printed, [1, REPORT_EVERY, 2 * REPORT_EVERY, 3 * REPORT_EVERY]);
}

#[test]
fn each_tag_keeps_its_own_count() {
    let budget = IdleLogBudget::new();
    assert_eq!(budget.admit(PF), Some(1));
    assert_eq!(budget.admit(SYSCALL), Some(1), "another tag is its own first sighting");
    assert_eq!(budget.admit(PF), None);
    assert_eq!(budget.admit(SYSCALL), None);
}

#[test]
fn an_empty_tag_never_prints() {
    let budget = IdleLogBudget::new();
    assert!((0..2 * REPORT_EVERY).all(|_| budget.admit("").is_none()));
}

#[test]
fn tags_beyond_the_table_are_still_counted() {
    let budget = IdleLogBudget::new();
    let tags: Vec<String> = (0..40).map(|i| format!("[tag {i}]\n")).collect();
    let first: usize = tags.iter().filter(|tag| budget.admit(tag).is_some()).count();
    // The first 16 tags each claim a slot; the rest share the last one.
    assert_eq!(first, 16);
    let total: u64 = (0..REPORT_EVERY).filter_map(|_| budget.admit(&tags[39])).count() as u64;
    assert!(total >= 1, "the shared slot still reports every thousandth time");
}
