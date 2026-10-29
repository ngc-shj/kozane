use super::RELEASE_SEQ;

/// A bundle's floor of 0 admits every release, so the first release is 1:
/// a floor of 1 then already shuts out nothing older than M8.
#[test]
fn the_first_release_is_one_above_the_open_floor() {
    assert_ne!(RELEASE_SEQ, 0);
}
