use super::*;

#[kani::proof]
fn every_child_and_label_resets() {
    assert!(decide(kani::any(), kani::any()) == Action::Reset);
}

#[kani::proof]
fn any_record_page_decodes_and_names_safely() {
    let r = Record::decode(kani::any());
    let _ = r.child_name();
    assert!(Record::decode(r.encode()) == r);
}
