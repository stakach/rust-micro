//! Pure cardinality rule for diagnostic receiver projection.
//! A reciprocal Reply binding identifies the caller, while a unique TCB `reply_to`
//! identifies the receiver. Conflicting candidates are reported, never selected.

pub const NONE: u64 = u64::MAX;
pub const AMBIGUOUS: u64 = u64::MAX - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiverObservation {
    pub tcb: u64,
    pub cspace: u64,
    pub state: u64,
}

impl ReceiverObservation {
    const fn none() -> Self {
        Self {
            tcb: NONE,
            cspace: NONE,
            state: NONE,
        }
    }

    const fn ambiguous() -> Self {
        Self {
            tcb: AMBIGUOUS,
            cspace: AMBIGUOUS,
            state: AMBIGUOUS,
        }
    }
}

pub fn select_exact_receiver(
    reciprocal_reply: bool,
    mut candidates: impl Iterator<Item = ReceiverObservation>,
) -> ReceiverObservation {
    if !reciprocal_reply {
        return ReceiverObservation::none();
    }
    let Some(first) = candidates.next() else {
        return ReceiverObservation::none();
    };
    if candidates.next().is_some() {
        ReceiverObservation::ambiguous()
    } else {
        first
    }
}
