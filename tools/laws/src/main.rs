//! CLI entry point; see `lib.rs` for the checker itself.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(laws::run(&args))
}
