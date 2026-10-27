#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

const RESET: &str = "pub fn system_reset() { let _ = 0x8400_0009u64; }\n";

/// The ids of every finding over `main.rs` = `main` and the minimal reset
/// module (`reset` replaces it when given).
fn ids(main: &str, reset: Option<&str>) -> Vec<&'static str> {
    let files = vec![("main.rs".into(), main.into()), (RESET_MODULE.into(), reset.unwrap_or(RESET).into())];
    check_crate(&files).into_iter().map(|f| f.id).collect()
}

fn real_crate() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/pds/supervisor/src");
    let mut files: Vec<(String, String)> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            (p.file_name().unwrap().to_string_lossy().into_owned(), std::fs::read_to_string(&p).unwrap())
        })
        .collect();
    files.sort();
    files
}

use std::path::Path;

#[test]
fn the_real_supervisor_crate_passes() {
    let files = real_crate();
    assert!(files.iter().any(|(p, _)| p == RESET_MODULE));
    assert_eq!(check_crate(&files), vec![]);
}

#[test]
fn the_minimal_crate_passes() {
    assert_eq!(ids("use sel4_microkit::{Channel, Handler};\nfn f() {}\n", None), Vec::<&str>::new());
}

#[test]
fn tcb_method_outside_reset_is_s3() {
    assert_eq!(ids("fn f(c: C) { c.tcb(); }\n", None), vec!["S3"]);
}

#[test]
fn tcb_family_outside_reset_is_s3() {
    let src = "fn f(t: T) { t.tcb_resume(); t.tcb_write_registers(); t.tcb_suspend(); }\n";
    assert_eq!(ids(src, None), vec!["S3", "S3", "S3"]);
}

#[test]
fn cap_from_bits_outside_reset_is_s4() {
    assert_eq!(ids("fn f() { let _ = Cap::from_bits(7); }\n", None), vec!["S4"]);
}

#[test]
fn from_cptr_outside_reset_is_s4() {
    assert_eq!(ids("fn f(c: X) { let _ = c.from_cptr(); }\n", None), vec!["S4"]);
}

#[test]
fn fully_qualified_sel4_tcb_in_an_expression_is_s2() {
    let got = ids("fn f() { let _ = ::sel4::cap::Tcb::new(); }\n", None);
    assert_eq!(got, vec!["S2", "S3"]);
}

#[test]
fn reset_only_paths_outside_reset_are_s2() {
    assert_eq!(ids("fn f() { sel4::with_ipc_buffer_mut(|_| ()); }\n", None), vec!["S2"]);
}

#[test]
fn a_listed_types_associated_item_passes() {
    assert_eq!(ids("fn f() { let _ = sel4_microkit::Channel::new(1); }\n", None), Vec::<&str>::new());
}

#[test]
fn glob_and_renamed_crate_imports_are_s2() {
    assert_eq!(ids("use sel4_microkit::*;\nuse sel4 as s;\n", None), vec!["S2", "S2"]);
}

#[test]
fn unlisted_sel4_type_is_s2() {
    assert_eq!(ids("struct S { c: sel4_microkit::Pd }\n", None), vec!["S2"]);
}

#[test]
fn a_second_smc_function_id_is_s6() {
    let reset = "fn r() { let _ = 0x8400_0009u64; let _ = 0x8400_0008u64; }\n";
    assert_eq!(ids("fn f() {}\n", Some(reset)), vec!["S6"]);
}

#[test]
fn system_off_outside_reset_is_s6() {
    assert_eq!(ids("const OFF: u64 = 0x8400_0008;\n", None), vec!["S6"]);
}

#[test]
fn unsafe_block_outside_reset_is_s1() {
    assert_eq!(ids("fn f(p: *mut u8) { unsafe { p.write(0) } }\n", None), vec!["S1"]);
}

#[test]
fn unsafe_fn_impl_and_extern_outside_reset_are_s1() {
    let src = "unsafe fn f() {}\nunsafe impl Send for X {}\nextern \"C\" { fn g(); }\n";
    assert_eq!(ids(src, None), vec!["S1", "S1", "S1"]);
}

#[test]
fn unsafe_and_smc_inside_reset_pass() {
    let reset = "fn r(p: *mut u8) { unsafe { p.write(0) }; smc_call(0x8400_0009); let _ = t.tcb(); }\n";
    assert_eq!(ids("fn f() {}\n", Some(reset)), Vec::<&str>::new());
}

#[test]
fn smc_name_outside_reset_is_s5() {
    assert_eq!(ids("fn f(i: I) { i.seL4_ARM_SMC_Call(); }\n", None), vec!["S5"]);
}

#[test]
fn reset_module_without_system_reset_is_s7() {
    assert_eq!(ids("fn f() {}\n", Some("fn r() {}\n")), vec!["S7"]);
}

#[test]
fn missing_reset_module_is_s7() {
    let files = vec![("main.rs".to_string(), "fn f() {}\n".to_string())];
    let got: Vec<_> = check_crate(&files).into_iter().map(|f| f.id).collect();
    assert_eq!(got, vec!["S7"]);
}

#[test]
fn a_file_that_does_not_parse_is_s8_and_named() {
    let files = vec![("main.rs".to_string(), "fn f( {".to_string()), (RESET_MODULE.into(), RESET.into())];
    let got = check_crate(&files);
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].id, got[0].file.as_str()), ("S8", "main.rs"));
}

#[test]
fn findings_carry_the_line() {
    let files = vec![("main.rs".to_string(), "fn f() {}\nfn g(c: C) { c.tcb(); }\n".to_string()),
                     (RESET_MODULE.into(), RESET.into())];
    assert_eq!(check_crate(&files)[0].to_string(), "S3 main.rs:2: TCB name `tcb` outside the reset module");
}
