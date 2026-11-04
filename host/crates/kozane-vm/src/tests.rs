//! The embedded argv and the launcher's own file formats.

use super::*;
use crate::vmargs::{Json, parse};

#[test]
fn the_embedded_vm_args_parse_and_name_every_fd_once() {
    let args = VmArgs::parse(VM_ARGS).unwrap();
    assert_eq!(args.qemu.get(..2), Some(&["-machine".to_string(), "virt-9.0,gic-version=3,mem-merge=off,dump-guest-core=off".to_string()][..]));
    assert_eq!(args.media.len(), 8);
    assert!(args.swtpm.contains(&args.state_arg()));
    assert!(args.max_fd() <= vmargs::MAX_CHILD_FD);
}

#[test]
fn build_info_reports_the_seams_constant() {
    let info = build_info();
    let want = if resolve::SEAMS { "SEAMS=1\n" } else { "SEAMS=0\n" };
    assert!(info.starts_with(want), "{info}");
}

#[test]
fn the_json_subset_refuses_what_vm_py_never_writes() {
    assert_eq!(parse(r#"{"a": [1, "x\"y"]}"#).unwrap(), Json::Obj(vec![("a".into(), Json::Arr(vec![Json::Num(1), Json::Str("x\"y".into())]))]));
    for bad in [
        r#"{"a": 1, "a": 2}"#,
        r#"{"a": -1}"#,
        r#"{"a": 01}"#,
        r#"{"a": true}"#,
        "{\"a\": \"\\u0041\"}",
        r#"{"a": 1} x"#,
        "{\"a\": \"\u{e9}\"}",
        r#"[[[[[[[[[[1]]]]]]]]]]"#,
    ] {
        assert!(parse(bad).is_err(), "{bad}");
    }
}

fn args_with(edit: impl Fn(&str) -> String) -> Result<VmArgs, String> {
    VmArgs::parse(&edit(VM_ARGS))
}

#[test]
fn vm_args_with_a_shared_fd_or_a_low_fd_or_a_path_medium_are_refused() {
    assert!(args_with(|t| t.replacen("\"tpm\": 4", "\"tpm\": 3", 1)).unwrap_err().contains("used twice"));
    assert!(args_with(|t| t.replacen("\"tpm\": 4", "\"tpm\": 2", 1)).unwrap_err().contains("not an fd"));
    assert!(args_with(|t| t.replacen("\"published.img\"", "\"../published.img\"", 1)).unwrap_err().contains("plain file name"));
    assert!(args_with(|t| t.replacen("\"swtpm_state\": \"", "\"swtpm_state\": \"/x", 1)).unwrap_err().contains("state directory"));
}

#[test]
fn vm_conf_takes_exactly_its_four_keys_in_order() {
    let good = "inside_bridge=br-in\noutside_bridge=br-out\nqemu=/usr/bin/qemu-system-aarch64\nswtpm=/usr/bin/swtpm\n";
    assert_eq!(
        VmConf::parse(good).unwrap(),
        VmConf {
            inside_bridge: "br-in".into(),
            outside_bridge: "br-out".into(),
            qemu: "/usr/bin/qemu-system-aarch64".into(),
            swtpm: "/usr/bin/swtpm".into(),
        }
    );
    for bad in [
        good.replace("br-in", "a-bridge-name-too-long"),
        good.replace("br-in", "br in"),
        good.replace("br-in", "."),
        good.replace("br-in", ".."),
        good.replace("=/usr/bin/swtpm", "=swtpm"),
        good.replace("inside_bridge=br-in\noutside_bridge=br-out\n", "outside_bridge=br-out\ninside_bridge=br-in\n"),
        format!("{good}qemu=/x\n"),
        good.replace('\n', "\r\n"),
        good.trim_end().to_string(),
    ] {
        assert!(VmConf::parse(&bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_service_user_missing_from_the_user_database_is_refused() {
    if resolve::SEAMS {
        return;
    }
    let res = Resolver::from_args(&mut Vec::new()).unwrap();
    // The build container has no kozane-* users.
    if std::fs::read_to_string("/etc/passwd").is_ok_and(|p| p.contains("kozane-swtpm:")) {
        return;
    }
    assert!(res.creds(Service::Swtpm).unwrap_err().contains("kozane-swtpm: no such user"));
}

#[test]
fn a_service_user_or_kvm_group_of_root_is_refused() {
    for (uid, gid, kvm) in [(0, 990, Some(991)), (990, 0, Some(991)), (990, 990, Some(0))] {
        let err = resolve::service_creds("kozane-qemu", uid, gid, kvm).unwrap_err();
        assert!(err.contains("a service user is never root"), "{uid} {gid} {kvm:?}: {err}");
    }
}

#[test]
fn a_service_user_gets_its_own_group_and_a_non_root_kvm_group() {
    let qemu = resolve::service_creds("kozane-qemu", 990, 990, Some(991)).unwrap();
    assert_eq!(qemu.groups, Some(vec![990, 991]));
    assert_eq!(resolve::service_creds("kozane-swtpm", 989, 989, None).unwrap().groups, Some(vec![989]));
}

#[test]
fn without_seams_the_paths_are_fixed_and_the_owner_is_root() {
    if resolve::SEAMS {
        return;
    }
    let mut args = vec!["--root-prefix".to_string(), "/tmp/x".to_string()];
    let res = Resolver::from_args(&mut args).unwrap();
    assert_eq!(args.len(), 2, "a release build took a seam option");
    assert_eq!(res.path(PIN), Path::new("/etc/kozane/firmware.pin"));
    assert_eq!(res.owner(), (0, 0));
}

#[test]
fn a_requested_stop_is_clean_whichever_child_exits_first() {
    // QEMU closes the TPM socket as it stops, so swtpm may exit first.
    assert!(clean_exit("swtpm", true, true));
    assert!(clean_exit("qemu", true, false));
    // Unrequested: only QEMU's own success is clean.
    assert!(clean_exit("qemu", false, true));
    assert!(!clean_exit("qemu", false, false));
    assert!(!clean_exit("swtpm", false, true));
    assert!(!clean_exit("serial-reader", false, true));
}
