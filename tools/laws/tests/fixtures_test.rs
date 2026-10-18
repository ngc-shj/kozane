//! Drives the compiled `laws` binary over `tests/fixtures/*.{system,toml}`
//! pairs. Each fixture asserts the exact violated-law-ID set (from the
//! `VIOLATIONS:` line) with no parse error, per the C7 acceptance criteria
//! in docs/archive/review/secureos-pq-vpn-architecture-plan.md.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, Output};

fn fixtures_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn run(name: &str) -> Output {
    let dir = fixtures_dir();
    Command::new(env!("CARGO_BIN_EXE_laws"))
        .arg("check")
        .arg("--system")
        .arg(dir.join(format!("{name}.system")))
        .arg("--policy")
        .arg(dir.join(format!("{name}.toml")))
        .arg("--search-path")
        .arg(&dir)
        .arg("--no-elf-check")
        .output()
        .expect("failed to run the laws binary")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Asserts `name` is clean: exit 0, no `VIOLATIONS:` line.
fn assert_allow(name: &str) {
    let out = run(name);
    let text = stdout(&out);
    assert!(
        out.status.success(),
        "fixture '{name}' expected to pass but exited {:?}\nstdout:\n{text}\nstderr:\n{}",
        out.status.code(),
        stderr(&out)
    );
    assert!(!text.contains("VIOLATIONS:"), "fixture '{name}' unexpectedly reported violations:\n{text}");
}

/// Asserts `name` violates exactly the laws in `expected` (e.g. `&["L1",
/// "L2"]`): exit 1, and the `VIOLATIONS:` line's id set matches exactly.
fn assert_deny(name: &str, expected: &[&str]) {
    let out = run(name);
    let text = stdout(&out);
    assert_eq!(
        out.status.code(),
        Some(1),
        "fixture '{name}' expected exit 1 (a law violation, not a parse error)\nstdout:\n{text}\nstderr:\n{}",
        stderr(&out)
    );
    let line = text
        .lines()
        .find(|l| l.starts_with("VIOLATIONS:"))
        .unwrap_or_else(|| panic!("fixture '{name}' printed no VIOLATIONS: line\nstdout:\n{text}"));
    let mut actual: Vec<&str> = line.trim_start_matches("VIOLATIONS:").split_whitespace().collect();
    actual.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(actual, expected, "fixture '{name}' violated law set mismatch\nstdout:\n{text}");
}

/// Asserts `name` is a parse/usage error: exit 2, never reported as a law
/// violation.
fn assert_parse_error(name: &str) {
    let out = run(name);
    let text = stdout(&out);
    assert_eq!(
        out.status.code(),
        Some(2),
        "fixture '{name}' expected exit 2 (parse error)\nstdout:\n{text}\nstderr:\n{}",
        stderr(&out)
    );
    assert!(
        !text.contains("VIOLATIONS:"),
        "fixture '{name}' is a parse error and must never be reported as a law violation:\n{text}"
    );
}

#[test]
fn secrets_mr_into_untrusted_pd_is_l1_l2() {
    assert_deny("secrets_deny", &["L1", "L2"]);
}

#[test]
fn secrets_mr_into_key_only_is_allowed() {
    assert_allow("secrets_allow");
}

#[test]
fn driver_maps_own_device_page_is_allowed() {
    assert_allow("device_page_own_allow");
}

#[test]
fn another_pd_mapping_a_driver_device_page_is_l5() {
    assert_deny("device_page_other_deny", &["L5"]);
}

#[test]
fn driver_setvar_own_dma_paddr_is_allowed() {
    assert_allow("dma_setvar_own_allow");
}

#[test]
fn non_driver_setvar_dma_paddr_is_l5() {
    assert_deny("dma_setvar_other_deny", &["L5"]);
}

#[test]
fn dma_mr_mapped_only_into_owner_is_allowed() {
    assert_allow("dma_shared_allow");
}

#[test]
fn dma_mr_also_mapped_into_another_pd_is_l5() {
    assert_deny("dma_shared_deny", &["L5"]);
}

#[test]
fn default_budget_on_tainted_pd_is_l13() {
    assert_deny("tainted_default_budget_deny", &["L13"]);
}

#[test]
fn explicit_budget_under_period_on_tainted_pd_is_allowed() {
    assert_allow("tainted_explicit_budget_allow");
}

#[test]
fn non_passive_key_is_l13() {
    assert_deny("key_non_passive_deny", &["L13"]);
}

#[test]
fn passive_key_is_allowed() {
    assert_allow("key_passive_allow");
}

#[test]
fn per_pd_ratio_over_cap_is_l13() {
    assert_deny("ratio_per_pd_over_deny", &["L13"]);
}

#[test]
fn per_pd_ratio_under_cap_is_allowed() {
    assert_allow("ratio_per_pd_under_allow");
}

#[test]
fn ratio_sum_over_cap_is_l13() {
    assert_deny("ratio_sum_over_deny", &["L13"]);
}

#[test]
fn ratio_sum_under_cap_is_allowed() {
    assert_allow("ratio_sum_under_allow");
}

#[test]
fn unknown_element_is_l4() {
    assert_deny("unknown_element_deny", &["L4"]);
}

#[test]
fn baseline_without_unknown_element_is_allowed() {
    assert_allow("unknown_element_allow");
}

#[test]
fn doctype_is_a_parse_error_not_a_violation() {
    assert_parse_error("doctype_deny");
}

#[test]
fn same_system_without_doctype_is_allowed() {
    assert_allow("doctype_allow");
}

#[test]
fn duplicate_attribute_is_a_parse_error() {
    assert_parse_error("duplicate_attr_deny");
}

#[test]
fn m0_system_allows_against_its_minimal_policy() {
    assert_allow("m0_hello_allow");
}

#[test]
fn taint_propagates_transitively_over_two_channel_hops() {
    assert_deny("taint_transitive_channel_deny", &["L1", "L2"]);
}

#[test]
fn two_hop_channel_chain_without_a_secret_is_allowed() {
    assert_allow("taint_transitive_channel_allow");
}

#[test]
fn taint_propagates_transitively_over_two_shared_mr_hops() {
    assert_deny("taint_transitive_mr_deny", &["L1", "L2"]);
}

#[test]
fn two_hop_mr_chain_without_a_secret_is_allowed() {
    assert_allow("taint_transitive_mr_allow");
}

#[test]
fn key_channel_with_wrong_pp_direction_is_l1() {
    assert_deny("key_exemption_wrong_pp_deny", &["L1"]);
}

#[test]
fn key_channel_meeting_the_exemption_is_allowed() {
    assert_allow("key_exemption_correct_allow");
}

/// Regression test against the real files (not a frozen fixture): keeps
/// `policy/laws.toml` honest as `system/secureos.system` grows, since C2
/// wires `laws check` into `make image` against exactly these two paths.
#[test]
fn live_repo_system_passes_against_live_policy() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new(env!("CARGO_BIN_EXE_laws"))
        .arg("check")
        .arg("--system")
        .arg(repo_root.join("system/secureos.system"))
        .arg("--policy")
        .arg(repo_root.join("policy/laws.toml"))
        .arg("--search-path")
        .arg(repo_root.join("build"))
        .arg("--no-elf-check")
        .output()
        .expect("failed to run the laws binary");
    let text = stdout(&out);
    assert!(
        out.status.success(),
        "system/secureos.system does not pass policy/laws.toml\nstdout:\n{text}\nstderr:\n{}",
        stderr(&out)
    );
}

#[test]
fn dma_mr_without_owner_setvar_is_l5() {
    // Without region_paddr the driver's paddr symbol stays 0, a real address.
    assert_deny("dma_no_setvar_deny", &["L5"]);
}

#[test]
fn misspelled_policy_section_is_a_parse_error() {
    // Ignoring it would silently drop the priority law.
    assert_parse_error("policy_typo_deny");
}
