//! `tools/laws`: the C7 laws checker.
//!
//! Checks a Microkit `.system` file against `policy/laws.toml` for the
//! architecture-wide security laws in
//! docs/archive/review/secureos-pq-vpn-architecture-plan.md ("Architecture-wide
//! security laws", L1-L13). See `policy/laws.toml` for the policy schema and
//! `check` for which laws are evaluated.

pub mod check;
pub mod cli;
pub mod elf;
pub mod law;
pub mod numbers;
pub mod policy;
pub mod sdf;
pub mod sha256;
pub mod timer_scan;

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

/// Reads `name` under `search_path`. Missing-file is an error unless the
/// caller set `--no-elf-check` (fixtures do not ship real ELFs).
fn resolve_elf(name: &str, search_path: &Path) -> Result<(PathBuf, Vec<u8>), CheckError> {
    let path = search_path.join(name);
    let bytes = fs::read(&path)
        .map_err(|e| CheckError(format!("program_image '{name}' not found under search-path '{}': {e}", search_path.display())))?;
    Ok((path, bytes))
}

/// The ELF check (M9 plan D13; `make package` runs it after
/// `tools/timer-scan`): each ELF's sha256 line, W^X over every
/// program_image, and whether `timer-scan.txt` under the search path is a
/// clean result for exactly these ELFs (`Err` with the reasons if not).
fn elf_check(
    pds: &[&sdf::Pd],
    policy: &Policy,
    search_path: &Path,
    findings: &mut Vec<law::Finding>,
) -> Result<(Vec<String>, Result<(), String>), CheckError> {
    let mut elf_lines = Vec::new();
    let mut images = std::collections::BTreeMap::new();
    for pd in pds {
        let (path, bytes) = resolve_elf(&pd.program_image, search_path)?;
        let hash = sha256::hex_digest(&bytes);
        elf_lines.push(format!("sha256 {hash} {}", path.display()));
        let segments = elf::load_segments(&bytes).map_err(|e| CheckError(format!("program_image '{}': {e}", pd.program_image)))?;
        for message in elf::wx_violations(&pd.program_image, &segments) {
            findings.push(law::Finding::new(LawId::L5, message));
        }
        images.insert(pd.program_image.clone(), hash);
        if let Some(sym) = &pd.path_for_symbols {
            let (path, bytes) = resolve_elf(sym, search_path)?;
            elf_lines.push(format!("sha256 {} {}", sha256::hex_digest(&bytes), path.display()));
        }
    }
    let timers: Vec<&str> =
        pds.iter().filter(|pd| policy.role(&pd.name) == Some(policy::Role::Timer)).map(|pd| pd.program_image.as_str()).collect();
    let scan = match fs::read_to_string(search_path.join(timer_scan::FILE)) {
        Ok(text) => timer_scan::problems(&text, &images, &timers),
        Err(e) => vec![format!("cannot read {}: {e}; tools/timer-scan runs first", search_path.join(timer_scan::FILE).display())],
    };
    Ok((elf_lines, if scan.is_empty() { Ok(()) } else { Err(scan.join("; ")) }))
}

pub fn check(args: &cli::Args) -> Result<Outcome, CheckError> {
    let policy_text = read_file(&args.policy, "policy")?;
    let policy = Policy::load(&policy_text)?;

    let system_text = read_file(&args.system, "system")?;
    let (system, mut findings) = sdf::parse(&system_text)?;

    let mut pds: Vec<&sdf::Pd> = system.pds.iter().collect();
    pds.sort_by(|a, b| a.name.cmp(&b.name));

    let (elf_lines, timer_scan) = if args.no_elf_check {
        (Vec::new(), None)
    } else {
        let (lines, scan) = elf_check(&pds, &policy, &args.search_path, &mut findings)?;
        (lines, Some(scan))
    };
    findings.extend(check::check(&system, &policy, timer_scan.as_ref()));

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
