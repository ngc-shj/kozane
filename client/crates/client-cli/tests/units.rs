//! D6's unit files: the canonical subset, the directives the plan names,
//! and `systemd-analyze verify` (the dev image carries it, VE28).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod support;

use std::process::Command;

use support::units::{Unit, path};

#[test]
fn both_units_are_canonical() {
    Unit::load("kozane-psk.service");
    Unit::load("kozane-net.service");
}

#[test]
fn the_parser_refuses_a_repeat_or_an_inversion() {
    let ok = "[Service]\nUser=a\n";
    assert!(Unit::parse(ok).is_ok());
    for bad in [
        "[Service]\nUser=a\nUser=b\n",
        "[Service]\nSystemCallFilter=~@mount\n",
        "[Service]\nUser = a\n",
        "User=a\n",
        "[Service]\nExecStart=/bin/a \\\n",
        "[Service]\n[Service]\n",
    ] {
        assert!(Unit::parse(bad).is_err(), "units: non-canonical unit file accepted: {bad:?}");
    }
}

#[test]
fn kozane_psk_holds_net_admin_only_and_notifies() {
    let u = Unit::load("kozane-psk.service");
    let s = |k| u.get("Service", k);
    assert_eq!(s("User"), Some("kozane-psk"));
    assert_eq!(s("Group"), Some("kozane-net"));
    assert_eq!(s("Type"), Some("notify"));
    assert_eq!(s("AmbientCapabilities"), Some("CAP_NET_ADMIN"));
    assert_eq!(s("CapabilityBoundingSet"), Some("CAP_NET_ADMIN"));
    assert_eq!(s("NoNewPrivileges"), Some("yes"));
    assert_eq!(s("LimitCORE"), Some("0"));
    assert_eq!(s("RuntimeDirectory"), Some("kozane-psk"));
    assert_eq!(s("RuntimeDirectoryMode"), Some("0750"));
    assert_eq!(s("StateDirectory"), Some("kozane-psk"));
    assert_eq!(s("StateDirectoryMode"), Some("0700"));
    assert_eq!(s("ExecStopPost"), Some("/usr/bin/kzc-psk cleanup"));
    assert_eq!(u.get("Unit", "Upholds"), Some("kozane-net.service"));
}

#[test]
fn kozane_net_holds_nothing_and_follows_kozane_psk() {
    let u = Unit::load("kozane-net.service");
    let s = |k| u.get("Service", k);
    assert_eq!(s("User"), Some("kozane-net"));
    assert_eq!(s("CapabilityBoundingSet"), Some(""), "kzc: capabilities held");
    assert_eq!(s("AmbientCapabilities"), None, "kzc: capabilities held");
    assert_eq!(s("NoNewPrivileges"), Some("yes"));
    assert_eq!(s("LimitCORE"), Some("0"));
    assert_eq!(s("StateDirectory"), Some("kozane-net"));
    assert_eq!(s("StateDirectoryMode"), Some("0700"));
    for k in ["BindsTo", "After", "PartOf"] {
        assert_eq!(u.get("Unit", k), Some("kozane-psk.service"), "{k}");
    }
}

#[test]
fn systemd_analyze_verifies_both_units() {
    // The dev image carries systemd-analyze (VE28): without it this gate
    // fails rather than skipping the verify.
    let found = Command::new("systemd-analyze").arg("--version").output();
    assert!(found.is_ok_and(|o| o.status.success()), "units: systemd-analyze missing; the verify cannot run");
    let dir = std::env::temp_dir().join(format!("kzc-units-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // The units name the installed paths; verify needs them executable.
    for (name, bin) in [("kozane-psk.service", "kzc-psk"), ("kozane-net.service", "kzc")] {
        let built = if bin == "kzc" { env!("CARGO_BIN_EXE_kzc") } else { env!("CARGO_BIN_EXE_kzc-psk") };
        let text = std::fs::read_to_string(path(name)).unwrap().replace(&format!("/usr/bin/{bin}"), built);
        std::fs::write(dir.join(name), text).unwrap();
    }
    let out = Command::new("systemd-analyze")
        .args(["verify", "--man=no"])
        .arg(dir.join("kozane-psk.service"))
        .arg(dir.join("kozane-net.service"))
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success() && out.stderr.is_empty(),
        "units: systemd-analyze verify: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
