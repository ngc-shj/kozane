//! `tools/laws`: the C7 laws checker.
//!
//! Checks a Microkit `.system` file against `policy/laws.toml` for the
//! architecture-wide security laws in
//! docs/archive/review/secureos-pq-vpn-architecture-plan.md ("Architecture-wide
//! security laws", L1-L13). See `policy/laws.toml` for the policy schema and
//! `check` for which laws are evaluated.

pub mod check;
pub mod cli;
pub mod law;
pub mod numbers;
pub mod policy;
pub mod sdf;
pub mod sha256;

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use law::LawId;
use policy::Policy;

/// A parse or usage error: the input could not even be evaluated against
/// the laws. Per the C7 contract, this is never reported as a law
/// violation.
#[derive(Debug)]
pub struct CheckError(String);

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<policy::PolicyError> for CheckError {
    fn from(e: policy::PolicyError) -> Self {
        CheckError(e.to_string())
    }
}

impl From<sdf::SdfError> for CheckError {
    fn from(e: sdf::SdfError) -> Self {
        CheckError(e.to_string())
    }
}

pub struct Outcome {
    pub violations: std::collections::BTreeSet<LawId>,
    pub messages: Vec<String>,
    pub elf_lines: Vec<String>,
}

fn read_file(path: &Path, what: &str) -> Result<String, CheckError> {
    fs::read_to_string(path).map_err(|e| CheckError(format!("cannot read {what} '{}': {e}", path.display())))
}

/// Resolves `name` against `search_path` and returns its path and sha256
/// hex digest. Missing-file is an error unless the caller set
/// `--no-elf-check` (fixtures do not ship real ELFs).
fn resolve_elf(name: &str, search_path: &Path) -> Result<(PathBuf, String), CheckError> {
    let path = search_path.join(name);
    let bytes = fs::read(&path)
        .map_err(|e| CheckError(format!("program_image '{name}' not found under search-path '{}': {e}", search_path.display())))?;
    Ok((path, sha256::hex_digest(&bytes)))
}

pub fn check(args: &cli::Args) -> Result<Outcome, CheckError> {
    let policy_text = read_file(&args.policy, "policy")?;
    let policy = Policy::load(&policy_text)?;

    let system_text = read_file(&args.system, "system")?;
    let (system, mut findings) = sdf::parse(&system_text)?;
    findings.extend(check::check(&system, &policy));

    let mut pds: Vec<&sdf::Pd> = system.pds.iter().collect();
    pds.sort_by(|a, b| a.name.cmp(&b.name));

    let mut elf_lines = Vec::new();
    if !args.no_elf_check {
        for pd in &pds {
            let (path, hash) = resolve_elf(&pd.program_image, &args.search_path)?;
            elf_lines.push(format!("sha256 {hash} {}", path.display()));
            if let Some(sym) = &pd.path_for_symbols {
                let (path, hash) = resolve_elf(sym, &args.search_path)?;
                elf_lines.push(format!("sha256 {hash} {}", path.display()));
            }
        }
    }

    findings.sort_by(|a, b| a.law.cmp(&b.law).then_with(|| a.message.cmp(&b.message)));
    let violations = findings.iter().map(|f| f.law).collect();
    let messages = findings.into_iter().map(|f| format!("{}: {}", f.law, f.message)).collect();

    Ok(Outcome { violations, messages, elf_lines })
}

/// Runs the CLI over `args` (excluding the program name) and returns the
/// process exit code: 0 clean, 1 violations found, 2 parse/usage error.
pub fn run(args: &[String]) -> u8 {
    let parsed = match cli::parse(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };

    match check(&parsed) {
        Ok(outcome) => {
            for line in &outcome.elf_lines {
                println!("{line}");
            }
            if outcome.violations.is_empty() {
                0
            } else {
                let ids: Vec<String> = outcome.violations.iter().map(ToString::to_string).collect();
                println!("VIOLATIONS: {}", ids.join(" "));
                for msg in &outcome.messages {
                    println!("{msg}");
                }
                1
            }
        }
        Err(e) => {
            eprintln!("{e}");
            2
        }
    }
}
