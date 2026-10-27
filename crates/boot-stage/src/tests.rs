extern crate std;

// One process, one shot: these run in a test binary of their own each (the
// flag is global), so each test asserts the order it needs within itself.

#[test]
fn the_first_run_init_lends_init_and_a_second_panics() {
    let got = super::run_init(|_init| 1);
    assert_eq!(got, 1);
    let second = std::panic::catch_unwind(|| super::run_init(|_init| 2));
    assert!(second.is_err(), "a second run_init must fault");
}
