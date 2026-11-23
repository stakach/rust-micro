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
    assert!(!retire_last_iopt_alias(2));
    assert!(retire_last_iopt_alias(1));
    assert!(!retire_last_iopt_alias(0));
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

#[path = "../src/arch/x86_64/iommu/visibility.rs"]
mod visibility;

#[test]
fn unlinked_table_is_visible_before_the_present_bit_can_be_written() {
    let log = RefCell::new(Vec::new());
    let mode = visibility::TableVisibility::new(false, true);
    let result = mode.prepare_unlinked(
        || memory(&log, "clean table"),
        || {
            memory(&log, "WBF acknowledged");
            Ok(())
        },
    );
    assert_eq!(result, Ok(()));
    memory(&log, "publish present");
    assert_eq!(*log.borrow(), [
        Event::Memory("clean table"),
        Event::Memory("WBF acknowledged"),
        Event::Memory("publish present"),
    ]);
    assert_eq!(
        mode.prepare_unlinked(|| {}, || Err(VtdError::TimedOut)),
        Err(VtdError::TimedOut)
    );
    visibility::TableVisibility::new(true, false)
        .prepare_unlinked(
            || unreachable!("coherent tables need no cache clean"),
            || unreachable!("write-buffer flush is not required"),
        )
        .unwrap();
}

#[test]
fn write_buffer_command_preserves_only_persistent_global_commands() {
    assert_eq!(
        visibility::global_command(u32::MAX, 1 << 27),
        (1 << 31) | (1 << 27) | (1 << 26) | (1 << 25) | (1 << 23)
    );
}

#[test]
fn noncoherent_table_cache_line_uses_the_advertised_cpu_width() {
    const CLFSH: u32 = 1 << 19;
    assert_eq!(visibility::cache_line_bytes(8 << 8, CLFSH), Some(64));
    assert_eq!(visibility::cache_line_bytes(8 << 8, 0), None);
    assert_eq!(visibility::cache_line_bytes(0, CLFSH), None);
    assert_eq!(visibility::cache_line_bytes(3 << 8, CLFSH), None);
}

struct FakeGlobalRegisters<'a> {
    log: &'a RefCell<Vec<Event>>,
    initial_status: u32,
    acknowledge: bool,
    issued: bool,
    polls_after_command: u32,
}

impl visibility::VtdGlobalRegisters for FakeGlobalRegisters<'_> {
    fn status(&mut self) -> u32 {
        const WBFS: u32 = 1 << 27;
        if !self.issued {
            return self.initial_status;
        }
        self.polls_after_command += 1;
        if self.acknowledge && self.polls_after_command >= 2 {
            self.log.borrow_mut().push(Event::Acknowledged(0x1c));
            self.initial_status & !WBFS
        } else {
            self.initial_status | WBFS
        }
    }

    fn command(&mut self, value: u32) {
        assert!(!self.issued, "one command until status acknowledges it");
        self.issued = true;
        self.log.borrow_mut().push(Event::Command(0x18, u64::from(value)));
    }
}

#[test]
fn unlinked_table_publication_waits_for_the_global_write_buffer_status() {
    const TE: u32 = 1 << 31;
    const RTPS: u32 = 1 << 30;
    const WBF: u32 = 1 << 27;
    let log = RefCell::new(Vec::new());
    let mut regs = FakeGlobalRegisters {
        log: &log,
        initial_status: TE | RTPS,
        acknowledge: true,
        issued: false,
        polls_after_command: 0,
    };
    visibility::TableVisibility::new(false, true)
        .prepare_unlinked(
            || memory(&log, "clean child table"),
            || visibility::flush_write_buffer(&mut regs),
        )
        .unwrap();
    memory(&log, "publish parent pointer");
    assert_eq!(*log.borrow(), [
        Event::Memory("clean child table"),
        Event::Command(0x18, u64::from(TE | WBF)),
        Event::Acknowledged(0x1c),
        Event::Memory("publish parent pointer"),
    ]);
    assert_eq!(regs.polls_after_command, 2);
}

#[test]
fn busy_write_buffer_status_never_authorizes_publication_or_command_replay() {
    const WBFS: u32 = 1 << 27;
    for initial_status in [0, WBFS] {
        let log = RefCell::new(Vec::new());
        let mut regs = FakeGlobalRegisters {
            log: &log,
            initial_status,
            acknowledge: false,
            issued: false,
            polls_after_command: 0,
        };
        let result = visibility::TableVisibility::new(true, true)
            .prepare_unlinked(
                || unreachable!("coherent table"),
                || visibility::flush_write_buffer(&mut regs),
            );
        assert_eq!(result, Err(VtdError::TimedOut));
        // A pre-existing busy status forbids a new command. Once issued, wait
        // for that command without issuing it again.
        assert_eq!(regs.issued, initial_status == 0);
        assert_eq!(log.borrow().len(), if initial_status == 0 { 1 } else { 0 });
        assert_eq!(
            regs.polls_after_command,
            if initial_status == 0 { INVALIDATION_SPINS } else { 0 },
        );
    }
}

#[test]
fn direct_vtd_retirement_precedes_the_capability_and_mdb_release() {
    let source = include_str!("../src/invocation.rs");
    let deletion = source
        .split_once("unsafe fn delete_cap_slot(")
        .expect("direct deletion")
        .1
        .split_once("\nfn cnode_delete(")
        .expect("end of direct deletion")
        .0;
    let retire = deletion
        .find("retire_vtd_mapping_before_delete(")
        .expect("direct deletion must retire its DMA mapping while it still owns the cap");
    let splice = deletion.find("splice_cte_out(").expect("MDB splice");
    let clear = deletion.find("s.write_cte_cap(").expect("CTE clear");
    assert!(retire < splice && splice < clear);
    assert!(
        deletion[retire..splice].contains("?;"),
        "a no-effect retirement refusal must return while the CTE and MDB still own the mapping",
    );
}
