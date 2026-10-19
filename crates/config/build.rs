//! Compiles the gateway configuration into the image (law L6). The file is
//! `config/gateway.toml`, or the path in SECUREOS_CONFIG (tests generate one
//! with fresh keys). Key files it names are relative to its directory. Any
//! validation error fails the build.

// Shared with mksecrets, which also uses the encoders.
#[allow(dead_code)]
mod validate {
    include!("src/validate.rs");
}

use std::path::{Path, PathBuf};

// The secrets region must hold every peer an image can serve.
const _: () = assert!(validate::MAX_PEERS <= secret_blob::MAX_PEERS);

fn main() {
    let path = std::env::var("SECUREOS_CONFIG")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/gateway.toml").into());
    println!("cargo:rerun-if-env-changed=SECUREOS_CONFIG");
    println!("cargo:rerun-if-changed={path}");
    println!("cargo:rerun-if-changed=src/validate.rs");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    let dir = Path::new(&path).parent().unwrap_or(Path::new(".")).to_path_buf();
    let load = |name: &str| -> Result<Vec<u8>, String> {
        let file = dir.join(name);
        println!("cargo:rerun-if-changed={}", file.display());
        std::fs::read(&file).map_err(|e| format!("cannot read {}: {e}", file.display()))
    };
    let checked = validate::check(&text, validate::MAX_PEERS, &load).unwrap_or_else(|e| panic!("{path}: {e}"));

    // Copies of the McEliece public keys, for `include_bytes!` in `pq` only.
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let copy = |name: String, key: &validate::RpKey| -> String {
        let file = out_dir.join(name);
        std::fs::write(&file, &key.public).unwrap_or_else(|e| panic!("write {}: {e}", file.display()));
        file.to_str().unwrap_or_else(|| panic!("{}: not UTF-8", file.display())).to_string()
    };
    let gateway_rp = copy("rp-gateway.pk".into(), &checked.gateway_rp);
    let peer_rps: Vec<String> = checked.peers.iter().enumerate().map(|(i, p)| copy(format!("rp-peer-{i}.pk"), &p.rp)).collect();
    std::fs::write(out_dir.join("config.rs"), validate::render(&checked, &gateway_rp, &peer_rps)).expect("write config.rs");
}
