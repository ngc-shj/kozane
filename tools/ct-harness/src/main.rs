//! The dynamic constant-time gate and residue scan for `mce460896`
//! (M4 plan C9). `make ct` (`tools/ct-gate`) runs one build of this binary
//! twice:
//!
//! - `ct-harness --policy <ct-declassify.toml>`: CT mode, under memcheck;
//! - `ct-harness --residue`: residue mode, natively;
//!
//! and judges both with `--verdict-ct` / `--verdict-residue`.
//!
//! `unsafe` is confined to `vg.rs` (the client requests) and `stack.rs`
//! (the residue scan's owned thread stack).

#![deny(unsafe_code)]

mod ct;
mod policy;
mod report;
mod residue;
mod stack;
mod vectors;
mod vg;

use std::process::exit;

/// Ends a CT-mode run on a harness-side failure (a wrong output or an
/// unmarked input). Under memcheck the exit status is 97 regardless, so
/// the verdict reads this line and the missing `CT-DONE`.
pub fn fail(why: &str) -> ! {
    println!("CT-FAIL {why}");
    exit(1);
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("ct-harness: {path}: {e}");
        exit(2)
    })
}

fn load_policy(path: &str) -> Vec<policy::Site> {
    policy::parse(&read(path)).unwrap_or_else(|e| {
        eprintln!("ct-harness: {path}: {e}");
        exit(2)
    })
}

fn usage() -> ! {
    eprintln!(
        "usage: ct-harness --policy <toml>\n\
         \x20      ct-harness --residue\n\
         \x20      ct-harness --verdict-ct <status> <memcheck.log> <ct.out> <policy.toml>\n\
         \x20      ct-harness --verdict-residue <status> <residue.out>"
    );
    exit(2)
}

fn verdict(kind: &str, why: Vec<String>) -> ! {
    if why.is_empty() {
        println!("{kind}-VERDICT pass");
        exit(0);
    }
    for w in &why {
        println!("{kind}-VERDICT fail: {w}");
    }
    exit(1)
}

fn status(s: &str) -> i32 {
    s.parse().unwrap_or_else(|_| usage())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["--policy", p] => {
            vg::set_policy(load_policy(p));
            ct::run()
        }
        ["--residue"] => residue::run(),
        ["--verdict-ct", s, log, out, p] => verdict(
            "CT",
            report::verdict_ct(status(s), &read(log), &read(out), &load_policy(p)),
        ),
        ["--verdict-residue", s, out] => {
            verdict("RESIDUE", report::verdict_residue(status(s), &read(out)))
        }
        _ => usage(),
    }
}
