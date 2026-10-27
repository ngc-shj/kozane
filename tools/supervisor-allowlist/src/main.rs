//! `supervisor-allowlist <crate src dir>`: prints each finding and exits 1,
//! or prints `SUPERVISOR-ALLOWLIST-OK <files>`. A directory it cannot read
//! is a refusal (exit 2).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn sources(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) -> std::io::Result<()> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?.map(|e| e.map(|e| e.path())).collect::<Result<_, _>>()?;
    entries.sort();
    for p in entries {
        if p.is_dir() {
            sources(&p, root, out)?;
        } else if p.extension().is_some_and(|e| e == "rs") {
            let rel = p.strip_prefix(root).unwrap_or(&p).to_string_lossy().into_owned();
            out.push((rel, std::fs::read_to_string(&p)?));
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [dir] = args.as_slice() else {
        eprintln!("usage: supervisor-allowlist <crate src dir>");
        return ExitCode::from(2);
    };
    let root = Path::new(dir);
    let mut files = Vec::new();
    if let Err(e) = sources(root, root, &mut files) {
        eprintln!("supervisor-allowlist: cannot read {dir}: {e}");
        return ExitCode::from(2);
    }
    if files.is_empty() {
        eprintln!("supervisor-allowlist: no .rs files under {dir}");
        return ExitCode::from(2);
    }
    let findings = supervisor_allowlist::check_crate(&files);
    for f in &findings {
        println!("{f}");
    }
    if findings.is_empty() {
        println!("SUPERVISOR-ALLOWLIST-OK {}", files.len());
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
