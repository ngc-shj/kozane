//! The gate's verdict over a run (M4 plan C9 "Decision"): memcheck's log
//! and the harness's own report lines. Anything not listed as a pass
//! condition fails; there is no function-name filter beyond the canary.

use std::collections::BTreeSet;

use crate::policy::Site;

const CANARY_KIND: &str = "Conditional jump or move depends on uninitialised value(s)";
const CANARY_SYMBOL: &str = "ct_harness::ct::canary";

/// One memcheck error: its kind line and its innermost frame.
#[derive(Debug, PartialEq, Eq)]
pub struct McError {
    pub kind: String,
    pub at: String,
}

/// The errors memcheck printed, and its `ERROR SUMMARY` line.
pub fn parse_memcheck(log: &str) -> (Vec<McError>, Option<String>) {
    let lines: Vec<&str> = log.lines().map(strip_pid).collect();
    let mut errors = Vec::new();
    let mut summary = None;
    for (i, line) in lines.iter().enumerate() {
        if let Some(s) = line.strip_prefix("ERROR SUMMARY: ") {
            summary = Some(s.trim().to_owned());
            continue;
        }
        if line.is_empty() || line.starts_with(' ') {
            continue;
        }
        if let Some(at) = lines
            .get(i + 1)
            .and_then(|n| n.trim_start().strip_prefix("at "))
        {
            errors.push(McError {
                kind: line.trim().to_owned(),
                at: at.trim().to_owned(),
            });
        }
    }
    (errors, summary)
}

/// `==123== text` to `text`.
fn strip_pid(line: &str) -> &str {
    if let Some(rest) = line.strip_prefix("==")
        && let Some(end) = rest
            .find("== ")
            .or_else(|| rest.ends_with("==").then(|| rest.len() - 2))
        && rest[..end].bytes().all(|b| b.is_ascii_digit())
    {
        return rest.get(end + 3..).unwrap_or("");
    }
    line
}

fn value<'a>(out: &'a str, key: &str) -> Vec<&'a str> {
    out.lines()
        .filter_map(|l| l.strip_prefix(key)?.strip_prefix(' '))
        .collect()
}

fn one_number(out: &str, key: &str, why: &mut Vec<String>) -> Option<u64> {
    match value(out, key).as_slice() {
        [v] => v
            .trim()
            .parse()
            .map_err(|_| why.push(format!("{key} {v:?} is not a number")))
            .ok(),
        vs => {
            why.push(format!("{key}: {} lines, want 1", vs.len()));
            None
        }
    }
}

/// CT mode: the reasons it fails (empty on a pass).
pub fn verdict_ct(status: i32, log: &str, out: &str, policy: &[Site]) -> Vec<String> {
    let mut why = Vec::new();
    if status != 97 {
        why.push(format!(
            "exit status {status}, want 97 (memcheck's --error-exitcode: the canary's error)"
        ));
    }
    let (errors, summary) = parse_memcheck(log);
    match summary.as_deref() {
        Some(s) if s.starts_with("1 errors from 1 contexts") => {}
        Some(s) => why.push(format!("ERROR SUMMARY: {s}, want 1 errors (the canary)")),
        None => why.push("no ERROR SUMMARY in the memcheck log".into()),
    }
    let canaries = errors
        .iter()
        .filter(|e| e.kind == CANARY_KIND && e.at.contains(CANARY_SYMBOL))
        .count();
    if canaries != 1 {
        why.push(format!(
            "{canaries} canary reports at {CANARY_SYMBOL}, want 1"
        ));
    }
    for e in errors
        .iter()
        .filter(|e| !(e.kind == CANARY_KIND && e.at.contains(CANARY_SYMBOL)))
    {
        why.push(format!("memcheck: {} at {}", e.kind, e.at));
    }

    for l in out
        .lines()
        .filter(|l| l.starts_with("CT-FAIL") || l.starts_with("CT-DECLASSIFY-REFUSED"))
    {
        why.push(l.to_owned());
    }
    if !out.lines().any(|l| l == "CT-CANARY done") {
        why.push("the canary did not run".into());
    }
    let last = out
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    let done = last
        .strip_prefix("CT-DONE ")
        .and_then(|n| n.parse::<u64>().ok());
    if done.is_none() {
        why.push(format!("last line {last:?}, want CT-DONE <cases>"));
    }
    let cases = one_number(out, "CT-CASES", &mut why);
    if let (Some(d), Some(c)) = (done, cases)
        && d != c
    {
        why.push(format!("CT-DONE {d}, CT-CASES {c}"));
    }
    if let Some(m) = one_number(out, "CT-MARKED-BYTES", &mut why)
        && m == 0
    {
        why.push("CT-MARKED-BYTES 0: nothing was marked secret".into());
    }

    let used: BTreeSet<&str> = value(out, "CT-DECLASSIFY-SITE")
        .iter()
        .filter_map(|l| l.split(' ').next())
        .collect();
    let listed: BTreeSet<&str> = policy.iter().map(|s| s.id.as_str()).collect();
    if used != listed {
        why.push(format!("declassify sites {used:?}, policy {listed:?}"));
    }
    if let Some(n) = one_number(out, "CT-DECLASSIFY", &mut why)
        && n != listed.len() as u64
    {
        why.push(format!("CT-DECLASSIFY {n}, policy has {}", listed.len()));
    }
    why
}

/// Residue mode: the reasons it fails (empty on a pass).
pub fn verdict_residue(status: i32, out: &str) -> Vec<String> {
    let mut why = Vec::new();
    if status != 0 {
        why.push(format!("exit status {status}, want 0"));
    }
    for l in out.lines().filter(|l| {
        [
            "RESIDUE-HIT",
            "RESIDUE-SHALLOW",
            "RESIDUE-DEEP",
            "RESIDUE-FAIL",
            "RESIDUE-UNDER-VALGRIND",
        ]
        .iter()
        .any(|p| l.starts_with(p))
    }) {
        why.push(l.to_owned());
    }
    let last = out
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    let done = last
        .strip_prefix("RESIDUE-DONE ")
        .and_then(|n| n.parse::<u64>().ok());
    if done.is_none() {
        why.push(format!("last line {last:?}, want RESIDUE-DONE <cases>"));
    }
    if let (Some(d), Some(c)) = (done, one_number(out, "RESIDUE-CASES", &mut why))
        && d != c
    {
        why.push(format!("RESIDUE-DONE {d}, RESIDUE-CASES {c}"));
    }
    why
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Kind;

    const CANARY_LOG: &str = "\
==41== Memcheck, a memory error detector
==41== Command: ./ct-harness --policy p.toml
==41==
==41== Conditional jump or move depends on uninitialised value(s)
==41==    at 0x40A1C4: ct_harness::ct::canary (ct.rs:22)
==41==    by 0x40A8F0: ct_harness::ct::run (ct.rs:80)
==41==
==41== HEAP SUMMARY:
==41==     in use at exit: 0 bytes in 0 blocks
==41==
==41== For lists of detected and suppressed errors, rerun with: -s
==41== ERROR SUMMARY: 1 errors from 1 contexts (suppressed: 0 from 0)
";

    const OUT: &str = "CT-CASES 2\nCT-CANARY done\nCT-DECLASSIFY-SITE ss-out 2\nCT-MARKED-BYTES 13608\nCT-DECLASSIFY 1\nCT-DONE 2\n";

    fn policy() -> Vec<Site> {
        vec![Site {
            id: "ss-out".into(),
            kind: Kind::Output,
            width: 32,
        }]
    }

    #[test]
    fn parses_the_error_kind_and_innermost_frame() {
        let (errors, summary) = parse_memcheck(CANARY_LOG);
        assert_eq!(
            errors,
            [McError {
                kind: CANARY_KIND.into(),
                at: "0x40A1C4: ct_harness::ct::canary (ct.rs:22)".into()
            }]
        );
        assert_eq!(
            summary.as_deref(),
            Some("1 errors from 1 contexts (suppressed: 0 from 0)")
        );
    }

    #[test]
    fn passes_the_canary_alone() {
        assert_eq!(
            verdict_ct(97, CANARY_LOG, OUT, &policy()),
            Vec::<String>::new()
        );
    }

    #[test]
    fn fails_and_names_a_second_error_by_file_and_line() {
        let log = CANARY_LOG
            .replace(
                "==41== HEAP SUMMARY:",
                "==41== Conditional jump or move depends on uninitialised value(s)\n==41==    at 0x4100F0: mce460896::bm::bm (bm.rs:150)\n==41==\n==41== HEAP SUMMARY:",
            )
            .replace("1 errors from 1 contexts", "2 errors from 2 contexts");
        let why = verdict_ct(97, &log, OUT, &policy());
        assert!(
            why.iter()
                .any(|w| w.contains("mce460896::bm::bm (bm.rs:150)")),
            "{why:?}"
        );
        assert!(
            why.iter().any(|w| w.starts_with("ERROR SUMMARY: 2 errors")),
            "{why:?}"
        );
    }

    #[test]
    fn fails_without_the_canary() {
        let log = CANARY_LOG.replace("ct_harness::ct::canary", "ct_harness::ct::other");
        assert!(!verdict_ct(97, &log, OUT, &policy()).is_empty());
        let none = "==41== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)\n";
        assert!(!verdict_ct(0, none, OUT, &policy()).is_empty());
    }

    #[test]
    fn fails_when_the_run_stops_early_or_counts_differ() {
        let early = OUT.replace("CT-DONE 2\n", "");
        assert!(
            verdict_ct(97, CANARY_LOG, &early, &policy())
                .iter()
                .any(|w| w.contains("want CT-DONE"))
        );
        let short = OUT.replace("CT-DONE 2", "CT-DONE 1");
        assert!(
            verdict_ct(97, CANARY_LOG, &short, &policy())
                .iter()
                .any(|w| w.contains("CT-DONE 1, CT-CASES 2"))
        );
        let unmarked = OUT.replace("CT-MARKED-BYTES 13608", "CT-MARKED-BYTES 0");
        assert!(!verdict_ct(97, CANARY_LOG, &unmarked, &policy()).is_empty());
    }

    #[test]
    fn fails_when_the_declassify_set_differs_from_the_policy() {
        let extra = OUT.replace(
            "CT-DECLASSIFY-SITE ss-out 2\n",
            "CT-DECLASSIFY-SITE ss-out 2\nCT-DECLASSIFY-SITE e 1\n",
        );
        assert!(
            verdict_ct(97, CANARY_LOG, &extra, &policy())
                .iter()
                .any(|w| w.starts_with("declassify sites"))
        );
        let unused = OUT.replace("CT-DECLASSIFY-SITE ss-out 2\n", "");
        assert!(!verdict_ct(97, CANARY_LOG, &unused, &policy()).is_empty());
    }

    #[test]
    fn residue_passes_only_clean_and_complete() {
        let ok = "RESIDUE-CASES 2\nRESIDUE-DEPTH a 1\nRESIDUE-DONE 2\n";
        assert_eq!(verdict_residue(0, ok), Vec::<String>::new());
        let hit = "RESIDUE-CASES 2\nRESIDUE-HIT ss case=a windows=3 depth=9\nRESIDUE-FAILED\n";
        assert!(
            verdict_residue(1, hit)
                .iter()
                .any(|w| w.starts_with("RESIDUE-HIT ss"))
        );
        assert!(!verdict_residue(0, "RESIDUE-CASES 2\nRESIDUE-DONE 1\n").is_empty());
        let deep = "RESIDUE-CASES 1\nRESIDUE-DEEP x: 9 bytes below the pad, the scrub covers 8\nRESIDUE-FAILED\n";
        assert!(
            verdict_residue(1, deep)
                .iter()
                .any(|w| w.starts_with("RESIDUE-DEEP x"))
        );
    }
}
