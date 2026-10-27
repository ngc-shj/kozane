//! A first `run_init` after `close` (a handler ran first) faults too.

#[test]
fn run_init_after_close_panics() {
    boot_stage::close();
    assert!(std::panic::catch_unwind(|| boot_stage::run_init(|_init| ())).is_err());
}
