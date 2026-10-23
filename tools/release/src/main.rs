//! Release signing and verification (M5 plan C13).
//!
//!   release keygen --dir <new dir> [--forbid <path>]...
//!   release render <key=value>...                 (canonical manifest on stdout)
//!   release sign --keys <dir> --manifest <file> --out <file>
//!   release verify --pub <dir> --manifest <file> --sig <file>
//!
//! Keys are dev keys (owner decision, residual RM5-1): `keygen` refuses a
//! directory under any `--forbid` root (the Makefile passes the repo, build/
//! and the cache volumes, as L6 does for secrets), creates it 0700 and the
//! private key files 0600. `verify` reads only the public files.

mod manifest;
mod sig;
#[cfg(test)]
mod tests;

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use libcrux_ml_dsa::ml_dsa_65::{MLDSA65SigningKey, MLDSA65VerificationKey};

fn urandom(buf: &mut [u8]) -> bool {
    fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf)).is_ok()
}

fn arg(args: &[String], name: &str) -> Result<String, String> {
    let i = args.iter().position(|a| a == name).ok_or(format!("missing {name}"))?;
    args.get(i + 1).cloned().ok_or(format!("{name} needs a value"))
}

fn read_hex(path: &Path) -> Result<Vec<u8>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    sig::unhex(text.trim_end_matches('\n')).ok_or(format!("{}: not lowercase hex", path.display()))
}

fn write_new(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .and_then(|mut f| f.write_all(data))
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// A key directory must not resolve under any forbidden root.
fn check_location(dir: &Path, forbid: &[PathBuf]) -> Result<(), String> {
    let parent = dir.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let parent = parent.canonicalize().map_err(|e| format!("{}: {e}", parent.display()))?;
    for root in forbid {
        let root = root.canonicalize().map_err(|e| format!("{}: {e}", root.display()))?;
        if parent.starts_with(&root) {
            return Err(format!("{} is inside {}; keys must live elsewhere", dir.display(), root.display()));
        }
    }
    Ok(())
}

fn keygen(args: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(arg(args, "--dir")?);
    let forbid: Vec<PathBuf> =
        args.windows(2).filter(|w| w[0] == "--forbid").map(|w| PathBuf::from(&w[1])).collect();
    check_location(&dir, &forbid)?;
    fs::DirBuilder::new().mode(0o700).create(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let (sk, pk) = sig::keygen(&mut urandom).map_err(|e| e.to_string())?;
    write_new(&dir.join("ed25519.key"), format!("{}\n", sig::hex(&sk.ed25519)).as_bytes(), 0o600)?;
    write_new(&dir.join("ml-dsa-65.key"), format!("{}\n", sig::hex(sk.ml_dsa.as_ref())).as_bytes(), 0o600)?;
    write_new(&dir.join("ed25519.pub"), format!("{}\n", sig::hex(&pk.ed25519)).as_bytes(), 0o644)?;
    write_new(&dir.join("ml-dsa-65.pub"), format!("{}\n", sig::hex(pk.ml_dsa.as_ref())).as_bytes(), 0o644)?;
    println!("release: dev keys in {}", dir.display());
    Ok(())
}

fn fixed<const N: usize>(bytes: Vec<u8>, what: &str) -> Result<[u8; N], String> {
    bytes.try_into().map_err(|_| format!("{what}: wrong length"))
}

fn load_signing(dir: &Path) -> Result<sig::SigningKeys, String> {
    let ed = fixed::<32>(read_hex(&dir.join("ed25519.key"))?, "ed25519.key")?;
    let mut ml = MLDSA65SigningKey::zero();
    let bytes = read_hex(&dir.join("ml-dsa-65.key"))?;
    if bytes.len() != MLDSA65SigningKey::len() {
        return Err("ml-dsa-65.key: wrong length".into());
    }
    ml.as_ref_mut().copy_from_slice(&bytes);
    Ok(sig::SigningKeys { ed25519: ed, ml_dsa: ml })
}

fn load_verifying(dir: &Path) -> Result<sig::VerifyingKeys, String> {
    let ed = fixed::<32>(read_hex(&dir.join("ed25519.pub"))?, "ed25519.pub")?;
    let mut ml = MLDSA65VerificationKey::zero();
    let bytes = read_hex(&dir.join("ml-dsa-65.pub"))?;
    if bytes.len() != MLDSA65VerificationKey::len() {
        return Err("ml-dsa-65.pub: wrong length".into());
    }
    ml.as_ref_mut().copy_from_slice(&bytes);
    Ok(sig::VerifyingKeys { ed25519: ed, ml_dsa: ml })
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("keygen") => keygen(args),
        Some("render") => {
            let pairs: Vec<(&str, &str)> = args[1..]
                .iter()
                .map(|a| a.split_once('=').ok_or(format!("render: `{a}` is not key=value")))
                .collect::<Result<_, _>>()?;
            let bytes = manifest::render(&pairs).map_err(|e| e.to_string())?;
            std::io::stdout().write_all(&bytes).map_err(|e| e.to_string())
        }
        Some("sign") => {
            let keys = load_signing(Path::new(&arg(args, "--keys")?))?;
            let m = fs::read(arg(args, "--manifest")?).map_err(|e| e.to_string())?;
            manifest::parse(&m).map_err(|e| e.to_string())?;
            let s = sig::sign(&keys, &m, &mut urandom).map_err(|e| e.to_string())?;
            write_new(Path::new(&arg(args, "--out")?), &s, 0o644)
        }
        Some("verify") => {
            let keys = load_verifying(Path::new(&arg(args, "--pub")?))?;
            let m = fs::read(arg(args, "--manifest")?).map_err(|e| e.to_string())?;
            let fields = manifest::parse(&m).map_err(|e| e.to_string())?;
            let s = fs::read(arg(args, "--sig")?).map_err(|e| e.to_string())?;
            sig::verify(&keys, &m, &s).map_err(|e| e.to_string())?;
            for (k, v) in fields {
                println!("{k}={v}");
            }
            println!("release: both signatures verify");
            Ok(())
        }
        _ => Err("usage: release keygen|render|sign|verify ...".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("release: {e}");
            ExitCode::FAILURE
        }
    }
}
