//! With the `boot-stop` feature, init can take the boot stop.

#[cfg(feature = "boot-stop")]
#[test]
fn a_boot_stop_is_dormant() {
    let _dormant: boot_stage::Dormant = boot_stage::run_init(|init| init.boot_stop());
}
