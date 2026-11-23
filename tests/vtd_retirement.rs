//! A DMA mapping is reusable only after VT-d acknowledged its invalidation (userspace-ntos#429).

// The kernel uses the remaining items (error kinds, ASR decode); these tests need only the ordering.
#[allow(dead_code)]
#[path = "../src/arch/x86_64/iommu/retirement.rs"]
mod retirement;

use retirement::*;
use std::cell::RefCell;

const IOTLB: u64 = 0x108;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Memory(&'static str),
    Command(u64, u64),
    Acknowledged(u64),
}

/// Remapping registers that complete each command on its first poll (or never), logging
/// memory effects and register commands into one shared timeline.
struct FakeRegisters<'a> {
    log: &'a RefCell<Vec<Event>>,
    complete: bool,
    granularity: bool,
    active: Option<u64>,
    completed: Option<u64>,
}

impl<'a> FakeRegisters<'a> {
    fn new(log: &'a RefCell<Vec<Event>>, complete: bool) -> Self {
        Self { log, complete, granularity: true, active: None, completed: None }
    }

    fn actual_granularity(&self, offset: u64) -> u64 {
        if !self.granularity { 0 } else if offset == CCMD_REG { 1 << 59 } else { 1 << 57 }
    }
}

impl VtdRegisters for FakeRegisters<'_> {
    fn read64(&mut self, offset: u64) -> u64 {
        if self.active == Some(offset) {
            if !self.complete {
                return 1 << 63;
            }
            self.active = None;
            self.completed = Some(offset);
            self.log.borrow_mut().push(Event::Acknowledged(offset));
            return self.actual_granularity(offset);
        }
        if self.completed == Some(offset) { self.actual_granularity(offset) } else { 0 }
    }

    fn write64(&mut self, offset: u64, value: u64) {
        self.log.borrow_mut().push(Event::Command(offset, value));
        self.active = Some(offset);
        self.completed = None;
    }
}

fn memory(log: &RefCell<Vec<Event>>, what: &'static str) {
    log.borrow_mut().push(Event::Memory(what));
}

#[test]
fn a_cleared_leaf_is_released_only_after_the_iotlb_acknowledges() {
    let log = RefCell::new(Vec::new());
    let mut regs = FakeRegisters::new(&log, true);
    let result = retire_leaf(&mut regs, IOTLB, || memory(&log, "clear pte"));
    assert_eq!(result, Ok(()));
    memory(&log, "release frame");
    assert_eq!(*log.borrow(), [
        Event::Memory("clear pte"),
        Event::Command(IOTLB, IOTLB_INVALIDATE),
        Event::Acknowledged(IOTLB),
        Event::Memory("release frame"),
    ]);
}

#[test]
fn an_unacknowledged_leaf_invalidation_is_reported_so_nothing_is_released() {
    let log = RefCell::new(Vec::new());
    let mut regs = FakeRegisters::new(&log, false);
    assert_eq!(retire_leaf(&mut regs, IOTLB, || memory(&log, "clear pte")), Err(VtdError::TimedOut));
    assert_eq!(*log.borrow(), [Event::Memory("clear pte"), Event::Command(IOTLB, IOTLB_INVALIDATE)]);

    let log = RefCell::new(Vec::new());
    let mut regs = FakeRegisters::new(&log, true);
    regs.granularity = false;
    assert_eq!(retire_leaf(&mut regs, IOTLB, || memory(&log, "clear pte")),
               Err(VtdError::UnsupportedGranularity));
}

#[test]
fn a_context_keeps_its_domain_until_context_cache_and_iotlb_both_acknowledge() {
    let log = RefCell::new(Vec::new());
    let mut regs = FakeRegisters::new(&log, true);
    let result = retire_context(&mut regs, IOTLB,
        || memory(&log, "clear present"), || memory(&log, "clear domain"));
    assert_eq!(result, Ok(()));
    assert_eq!(*log.borrow(), [
        Event::Memory("clear present"),
        Event::Command(CCMD_REG, CONTEXT_INVALIDATE),
        Event::Acknowledged(CCMD_REG),
        Event::Command(IOTLB, IOTLB_INVALIDATE),
        Event::Acknowledged(IOTLB),
        Event::Memory("clear domain"),
    ]);
}

#[test]
fn a_context_timeout_retains_the_domain_and_never_starts_the_iotlb() {
    let log = RefCell::new(Vec::new());
    let mut regs = FakeRegisters::new(&log, false);
    let result = retire_context(&mut regs, IOTLB,
        || memory(&log, "clear present"), || memory(&log, "clear domain"));
    assert_eq!(result, Err(VtdError::TimedOut));
    assert_eq!(*log.borrow(), [
        Event::Memory("clear present"),
        Event::Command(CCMD_REG, CONTEXT_INVALIDATE),
    ]);
}

#[test]
fn context_invalidation_precedes_iotlb_invalidation() {
    let log = RefCell::new(Vec::new());
    let mut regs = FakeRegisters::new(&log, true);
    assert_eq!(invalidate_context_and_iotlb_at(&mut regs, IOTLB), Ok(()));
    assert_eq!(*log.borrow(), [
        Event::Command(CCMD_REG, CONTEXT_INVALIDATE),
        Event::Acknowledged(CCMD_REG),
        Event::Command(IOTLB, IOTLB_INVALIDATE),
        Event::Acknowledged(IOTLB),
    ]);
}

#[test]
fn an_iotlb_timeout_is_reported_after_its_command() {
    let log = RefCell::new(Vec::new());
    let mut regs = FakeRegisters::new(&log, false);
    assert_eq!(invalidate_iotlb_at(&mut regs, IOTLB), Err(VtdError::TimedOut));
    assert_eq!(*log.borrow(), [Event::Command(IOTLB, IOTLB_INVALIDATE)]);
}

#[test]
fn an_existing_context_admits_only_its_own_live_domain() {
    let low = cte_low(0x4000, 0, true);
    let high = cte_high(2, 17);
    assert!(context_admits_domain(low, high, 17));
    assert!(!context_admits_domain(low, high, 2));
    assert!(!context_admits_domain(low, high, 0));
    assert!(!context_admits_domain(0, high, 17), "an absent context authorizes no domain");
}

#[test]
fn cnode_retirement_orders_dma_leaves_before_table_parents() {
    let levels = 4;
    let phases = [
        dma_retirement_phase(DmaRetirementKind::Table(0), levels),
        dma_retirement_phase(DmaRetirementKind::Table(1), levels),
        dma_retirement_phase(DmaRetirementKind::Frame, levels),
        dma_retirement_phase(DmaRetirementKind::Table(3), levels),
        dma_retirement_phase(DmaRetirementKind::Table(2), levels),
    ];
    assert_eq!(phases, [Some(4), Some(3), Some(0), Some(1), Some(2)]);
    assert_eq!(dma_retirement_phase(DmaRetirementKind::Table(4), levels), None);
}

#[test]
fn a_copied_iopt_alias_keeps_the_mapping_until_the_last_cap_deletes() {
    assert!(!retire_last_iopt_alias(1));
    assert!(retire_last_iopt_alias(0));
}

#[path = "../src/arch/x86_64/iommu/domain.rs"]
mod domain;

#[test]
fn domain_capacity_follows_the_advertised_width_and_refuses_reserved_encoding() {
    use domain::domain_count;
    for (nd, expected) in [16, 64, 256, 1024, 4096, 16384, 65536].into_iter().enumerate() {
        assert_eq!(domain_count(0x1080 | nd as u64), Some(expected));
    }
    assert_eq!(domain_count(7), None);
}

#[test]
fn domain_reservation_refuses_foreign_requesters_without_overwriting_the_owner() {
    use domain::{check_domain, reserve_domain};
    let mut owners = [0; 16];
    assert_eq!(reserve_domain(&mut owners, 0, 3), Err(VtdError::InvalidDomain));
    assert_eq!(reserve_domain(&mut owners, 16, 3), Err(VtdError::InvalidDomain));
    assert_eq!(reserve_domain(&mut owners, 15, 3), Ok(()));
    assert_eq!(check_domain(&owners, 15, 3), Ok(()));
    assert_eq!(reserve_domain(&mut owners, 15, 4), Err(VtdError::OwnershipConflict));
    assert_eq!(owners[15], 3);
}

#[test]
fn domain_remains_reserved_until_the_retirement_effect_acknowledges() {
    use domain::{reserve_domain, retire_owned_domain};
    let mut owners = [0; 16];
    reserve_domain(&mut owners, 6, 16).unwrap();
    let log = RefCell::new(Vec::new());
    let mut regs = FakeRegisters::new(&log, false);
    assert_eq!(
        retire_owned_domain(&mut owners, 6, 17, || unreachable!("foreign RID enters no effect")),
        Err(VtdError::OwnershipConflict)
    );
    assert_eq!(
        retire_owned_domain(&mut owners, 6, 16, || retire_context(
            &mut regs, IOTLB, || memory(&log, "clear present"), || memory(&log, "clear domain")
        )),
        Err(VtdError::TimedOut)
    );
    assert_eq!(owners[6], 16);
    assert_eq!(reserve_domain(&mut owners, 6, 17), Err(VtdError::OwnershipConflict));
    let mut regs = FakeRegisters::new(&log, true);
    retire_owned_domain(&mut owners, 6, 16, || retire_context(
        &mut regs, IOTLB, || memory(&log, "clear present"), || memory(&log, "clear domain")
    )).unwrap();
    assert_eq!(reserve_domain(&mut owners, 6, 17), Ok(()));
}
