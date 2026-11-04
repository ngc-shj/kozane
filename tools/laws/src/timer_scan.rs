//! `timer-scan.txt` as laws' ELF check reads it (M9 plan D13, C12): the
//! result `tools/timer-scan` wrote for the ELFs under the same search path.
//! The timer's L1 exemption needs it clean, and it must describe exactly the
//! ELFs laws hashes, so a stale result from another build is refused.

use std::collections::BTreeMap;

pub const FILE: &str = "timer-scan.txt";

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Clean,
    Control(u64),
}

/// Why the result does not cover `images` (program_image -> sha256 hex)
/// cleanly, with `timer_images` the timer-role pds' images. Empty when it
/// does.
pub fn problems(text: &str, images: &BTreeMap<String, String>, timer_images: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut lines: BTreeMap<&str, (&str, Verdict)> = BTreeMap::new();
    let mut count = None;
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let entry = match words.as_slice() {
            ["TIMER-SCAN-PDS", n] if count.is_none() => {
                count = n.parse::<usize>().ok();
                if count.is_none() {
                    out.push(format!("{FILE}: bad line '{line}'"));
                }
                continue;
            }
            ["pd", name, sha, "clean"] => sha.strip_prefix("sha256=").map(|s| (*name, s, Verdict::Clean)),
            ["pd", name, sha, control] => sha
                .strip_prefix("sha256=")
                .zip(control.strip_prefix("control=").and_then(|n| n.parse().ok()))
                .map(|(s, n)| (*name, s, Verdict::Control(n))),
            _ => None,
        };
        match entry {
            Some((name, sha, verdict)) if !lines.contains_key(name) => {
                lines.insert(name, (sha, verdict));
            }
            _ => out.push(format!("{FILE}: bad line '{line}'")),
        }
    }
    for (image, sha) in images {
        let timer = timer_images.contains(&image.as_str());
        match lines.get(image.as_str()) {
            None => out.push(format!("{FILE} does not cover '{image}'")),
            Some((got, _)) if got != sha => out.push(format!("{FILE} scanned another '{image}' (a stale result)")),
            Some((_, Verdict::Clean)) if timer => out.push(format!("{FILE}: timer '{image}' was scanned, not exempted")),
            Some((_, Verdict::Control(_))) if !timer => out.push(format!("{FILE}: '{image}' was exempted as the timer")),
            Some((_, Verdict::Control(0))) => out.push(format!("{FILE}: no timer access in timer '{image}'")),
            Some(_) => {}
        }
    }
    for name in lines.keys().filter(|n| !images.contains_key(**n)) {
        out.push(format!("{FILE} names '{name}', which the system does not"));
    }
    let scanned = images.keys().filter(|i| !timer_images.contains(&i.as_str())).count();
    if count != Some(scanned) {
        out.push(format!("{FILE}: TIMER-SCAN-PDS {count:?}, the system has {scanned} pds besides the timer"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn images() -> BTreeMap<String, String> {
        [("pd-a.elf", "aa"), ("pd-timer.elf", "tt")].into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    const CLEAN: &str = "pd pd-a.elf sha256=aa clean\npd pd-timer.elf sha256=tt control=5\nTIMER-SCAN-PDS 1\n";

    #[test]
    fn a_clean_result_for_the_same_elfs_passes() {
        assert!(problems(CLEAN, &images(), &["pd-timer.elf"]).is_empty());
    }

    #[test]
    fn a_result_for_other_elfs_is_stale() {
        let p = problems(&CLEAN.replace("sha256=aa", "sha256=ab"), &images(), &["pd-timer.elf"]);
        assert_eq!(p, ["timer-scan.txt scanned another 'pd-a.elf' (a stale result)"]);
    }

    #[test]
    fn a_timer_without_access_or_a_missing_pd_fails() {
        let p = problems(&CLEAN.replace("control=5", "control=0"), &images(), &["pd-timer.elf"]);
        assert_eq!(p, ["timer-scan.txt: no timer access in timer 'pd-timer.elf'"]);
        let p = problems("pd pd-timer.elf sha256=tt control=5\nTIMER-SCAN-PDS 1\n", &images(), &["pd-timer.elf"]);
        assert_eq!(p, ["timer-scan.txt does not cover 'pd-a.elf'"]);
    }

    #[test]
    fn a_timer_role_on_another_image_is_refused() {
        let p = problems(CLEAN, &images(), &["pd-a.elf"]);
        assert_eq!(p.len(), 2, "{p:?}");
    }

    #[test]
    fn an_empty_or_garbled_result_fails() {
        assert!(!problems("", &images(), &["pd-timer.elf"]).is_empty());
        assert!(!problems(&format!("{CLEAN}pd pd-a.elf sha256=aa clean\n"), &images(), &["pd-timer.elf"]).is_empty());
    }
}
