//! Compiles the gateway configuration into the image (law L6). The file is
//! `config/gateway.toml`, or the path in SECUREOS_CONFIG (tests generate one
//! with fresh keys). Any validation error fails the build.

mod validate {
    include!("src/validate.rs");
}

// The secrets region must hold every peer an image can serve.
const _: () = assert!(validate::MAX_PEERS <= secret_blob::MAX_PEERS);

fn main() {
    let path = std::env::var("SECUREOS_CONFIG")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/gateway.toml").into());
    println!("cargo:rerun-if-env-changed=SECUREOS_CONFIG");
    println!("cargo:rerun-if-changed={path}");
    println!("cargo:rerun-if-changed=src/validate.rs");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    let checked = validate::check(&text, validate::MAX_PEERS).unwrap_or_else(|e| panic!("{path}: {e}"));
    let out = std::path::Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("config.rs");
    std::fs::write(out, validate::render(&checked)).expect("write config.rs");
}
