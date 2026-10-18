//! Argument parsing for `laws check --system <file> --policy <file>
//! --search-path <dir> [--no-elf-check]`. No argument-parsing crate is
//! pulled in for one subcommand and four flags.

use std::path::PathBuf;

pub struct Args {
    pub system: PathBuf,
    pub policy: PathBuf,
    pub search_path: PathBuf,
    pub no_elf_check: bool,
}

const USAGE: &str = "usage: laws check --system <file> --policy <file> --search-path <dir> [--no-elf-check]";

pub fn parse(args: &[String]) -> Result<Args, String> {
    let mut it = args.iter();
    match it.next().map(String::as_str) {
        Some("check") => {}
        Some(other) => return Err(format!("unknown subcommand '{other}'\n{USAGE}")),
        None => return Err(USAGE.to_string()),
    }

    let mut system = None;
    let mut policy = None;
    let mut search_path = None;
    let mut no_elf_check = false;

    while let Some(a) = it.next() {
        match a.as_str() {
            "--system" => system = Some(PathBuf::from(need_value(&mut it, "--system")?)),
            "--policy" => policy = Some(PathBuf::from(need_value(&mut it, "--policy")?)),
            "--search-path" => search_path = Some(PathBuf::from(need_value(&mut it, "--search-path")?)),
            "--no-elf-check" => no_elf_check = true,
            other => return Err(format!("unknown argument '{other}'\n{USAGE}")),
        }
    }

    Ok(Args {
        system: system.ok_or_else(|| format!("missing --system\n{USAGE}"))?,
        policy: policy.ok_or_else(|| format!("missing --policy\n{USAGE}"))?,
        search_path: search_path.ok_or_else(|| format!("missing --search-path\n{USAGE}"))?,
        no_elf_check,
    })
}

fn need_value<'a>(it: &mut std::slice::Iter<'a, String>, flag: &str) -> Result<&'a str, String> {
    it.next().map(String::as_str).ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_all_flags() {
        let a = parse(&args(&[
            "check",
            "--system",
            "s.system",
            "--policy",
            "p.toml",
            "--search-path",
            "build",
            "--no-elf-check",
        ]))
        .unwrap();
        assert_eq!(a.system, PathBuf::from("s.system"));
        assert_eq!(a.policy, PathBuf::from("p.toml"));
        assert_eq!(a.search_path, PathBuf::from("build"));
        assert!(a.no_elf_check);
    }

    #[test]
    fn rejects_missing_subcommand() {
        assert!(parse(&args(&[])).is_err());
    }

    #[test]
    fn rejects_missing_required_flag() {
        assert!(parse(&args(&["check", "--system", "s.system"])).is_err());
    }
}
