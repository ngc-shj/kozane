use super::*;

#[kani::proof]
fn the_first_run_init_runs_init_once() {
    let v: u8 = kani::any();
    let mut calls = 0u8;
    let got = run_init(|_| {
        calls = 1;
        v
    });
    assert!(got == v && calls == 1);
}

#[kani::proof]
#[kani::should_panic]
fn a_second_run_init_never_lends_init() {
    let before: bool = kani::any();
    if before {
        close();
    } else {
        run_init(|_| ());
    }
    run_init(|_| ());
}

#[kani::proof]
#[kani::should_panic]
fn run_init_inside_init_never_lends_a_second_init() {
    run_init(|_| run_init(|_| ()));
}
