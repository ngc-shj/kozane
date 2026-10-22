//! I5's stack scrub: `SCRUB_DEPTH` must cover the stack peak of the
//! `_core` stages, measured here by stack exhaustion.
//!
//! Each measurement runs a child copy of this test binary
//! (`stack_probe_child`) that calls one stage on a thread with a given
//! stack size; the smallest size that does not overflow, minus that of an
//! empty call, is the stage's peak (to a page). The stages are constant
//! time, so the depth does not depend on the inputs. A padding frame keeps
//! every size above the platform's minimum thread stack.

mod common;

use std::hint::black_box;
use std::process::{Command, Stdio};

use common::boxed;
use mce460896::{
    CT_LEN, ENCAPS_RAND_LEN, PK_LEN, SCRUB_DEPTH, SCRUB_DEPTH_ENCAPS, SK_LEN, SS_LEN, decaps_core, encaps_attempt_core,
};

const CHILD: &str = "MCE460896_STACK_PROBE";
const PAGE: usize = 4096;
const PAD: usize = 256 * 1024;
/// Slack over the measured peak: the page granularity of the measurement
/// and code-generation differences between the host and the PD target.
const MARGIN: usize = 16 * 1024;

#[inline(never)]
fn padded(f: impl FnOnce()) {
    let mut pad = [0u8; PAD];
    black_box(&mut pad);
    f();
    black_box(&pad);
}

/// Not a test of its own: the child half of `scrub_depth_covers_the_core_stack_peak`,
/// run only by it (with `--ignored`), so it is not counted as a test.
#[test]
#[ignore = "the child half of scrub_depth_covers_the_core_stack_peak"]
fn stack_probe_child() {
    let Ok(spec) = std::env::var(CHILD) else { return };
    let (stage, size) = spec.split_once(':').expect("stage:size");
    let size: usize = size.parse().expect("size");
    let stage = stage.to_owned();

    let sk = boxed::<SK_LEN>();
    let pk = boxed::<PK_LEN>();
    let ct = Box::new([0x5au8; CT_LEN]);
    let rand = Box::new([0xa5u8; ENCAPS_RAND_LEN]);
    let mut ct_out = Box::new([0u8; CT_LEN]);
    let mut ss = Box::new([0u8; SS_LEN]);

    std::thread::Builder::new()
        .stack_size(size)
        .spawn(move || {
            padded(|| match stage.as_str() {
                "none" => {}
                "decaps" => decaps_core(&sk, &ct, &mut ss),
                "encaps" => {
                    black_box(encaps_attempt_core(&pk, &rand, &mut ct_out, &mut ss));
                }
                other => panic!("unknown stage {other}"),
            })
        })
        .expect("spawn")
        .join()
        .expect("join");
}

fn fits(stage: &str, size: usize) -> bool {
    Command::new(std::env::current_exe().expect("test binary"))
        .args(["stack_probe_child", "--exact", "--ignored", "--test-threads=1", "--quiet"])
        .env(CHILD, format!("{stage}:{size}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("child")
        .success()
}

/// The smallest stack, in pages, on which `stage` runs.
fn min_stack(stage: &str) -> usize {
    let (mut lo, mut hi) = (PAD / PAGE, (PAD + (4 << 20)) / PAGE);
    assert!(!fits(stage, lo * PAGE), "{stage} fits in its padding alone");
    assert!(fits(stage, hi * PAGE), "{stage} does not fit in 4 MB");
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        if fits(stage, mid * PAGE) { hi = mid } else { lo = mid }
    }
    hi * PAGE
}

#[test]
fn scrub_depth_covers_the_core_stack_peak() {
    let base = min_stack("none");
    let decaps = min_stack("decaps") - base;
    let encaps = min_stack("encaps") - base;
    eprintln!(
        "stack peak: decaps_core {decaps} B, encaps_attempt_core {encaps} B (base {base} B); \
         SCRUB_DEPTH {SCRUB_DEPTH} B, SCRUB_DEPTH_ENCAPS {SCRUB_DEPTH_ENCAPS} B"
    );
    assert!(decaps > 0 && encaps > 0, "the measurement sees the stages");
    assert!(SCRUB_DEPTH >= decaps + MARGIN, "SCRUB_DEPTH below decaps_core's peak plus {MARGIN}");
    assert!(SCRUB_DEPTH_ENCAPS >= encaps + MARGIN, "SCRUB_DEPTH_ENCAPS below encaps_attempt_core's peak plus {MARGIN}");
}
