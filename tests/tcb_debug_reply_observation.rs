#[path = "../src/invocation/tcb_debug_reply_observation.rs"]
mod tcb_debug_reply_observation;

use tcb_debug_reply_observation::{select_exact_receiver, ReceiverObservation, AMBIGUOUS, NONE};

fn receiver(tcb: u64) -> ReceiverObservation {
    ReceiverObservation {
        tcb,
        cspace: tcb + 10,
        state: 5,
    }
}

#[test]
fn reciprocal_binding_reports_one_exact_receiver_and_its_service_identity() {
    assert_eq!(
        select_exact_receiver(true, [receiver(7)].into_iter()),
        receiver(7)
    );
}

#[test]
fn unbound_or_stale_reply_never_guesses_a_receiver() {
    let expected = ReceiverObservation {
        tcb: NONE,
        cspace: NONE,
        state: NONE,
    };
    assert_eq!(select_exact_receiver(true, [].into_iter()), expected);
    assert_eq!(
        select_exact_receiver(false, [receiver(7)].into_iter()),
        expected
    );
}

#[test]
fn multiple_reciprocal_receiver_links_are_explicitly_ambiguous() {
    assert_eq!(
        select_exact_receiver(true, [receiver(7), receiver(8)].into_iter()),
        ReceiverObservation {
            tcb: AMBIGUOUS,
            cspace: AMBIGUOUS,
            state: AMBIGUOUS
        }
    );
}
