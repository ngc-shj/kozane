#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

use super::*;

#[test]
fn a_record_round_trips() {
    let r = Record { seq: 7, child: 10, label: 6, lost: 2 };
    assert_eq!(Record::decode(r.encode()), r);
    assert_eq!(r.child_name(), Some("ingress"));
}

#[test]
fn an_unknown_child_id_has_no_name() {
    assert_eq!(Record { seq: 1, child: CHILDREN.len() as u32, label: 0, lost: 0 }.child_name(), None);
}

#[test]
fn every_fault_resets() {
    for child in 0..CHILDREN.len() {
        for label in [0, 3, 4, 6, u64::MAX] {
            assert_eq!(decide(child, label), Action::Reset);
        }
    }
}
