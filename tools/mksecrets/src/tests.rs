#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

const TEMPLATE: &str = include_str!("../../../config/gateway.toml");

#[test]
fn encode_key_round_trips_through_the_config_decoder() {
    for seed in [[0u8; 32], [0xff; 32], core::array::from_fn(|i| i as u8)] {
        assert_eq!(validate::decode_key(&encode_key(&seed)), Ok(seed));
    }
}

#[test]
fn encode_key_matches_a_known_wireguard_key() {
    let k = validate::decode_key("YBS8Ds6hLNV9RKN63rn+Z7o/7hO6Iwmh1xhxEHInuGg=").unwrap_or([0; 32]);
    assert_eq!(encode_key(&k), "YBS8Ds6hLNV9RKN63rn+Z7o/7hO6Iwmh1xhxEHInuGg=");
}

#[test]
fn generated_blob_matches_generated_config() {
    let d = generate(TEMPLATE, 3, "127.0.0.1:1").unwrap_or_else(|e| panic!("{e}"));
    let checked = validate::check(&d.config, secret_blob::MAX_PEERS).unwrap_or_else(|e| panic!("{e}"));
    let blob = secret_blob::Blob::parse(&d.blob[..], 3).unwrap_or_else(|e| panic!("{}", e.message()));

    let mut public = [0u8; 32];
    libcrux_curve25519::secret_to_public(&mut public, blob.gateway_private());
    assert_eq!(public, checked.gateway_public);
    for (i, (peer_public, _)) in checked.peers.iter().enumerate() {
        let (hash, _) = blob.peer(i).unwrap_or_else(|| panic!("peer {i} missing"));
        assert_eq!(*hash, secret_blob::blake2s(&[peer_public]));
    }
}

#[test]
fn peer_config_carries_the_blob_psk_and_gateway_key() {
    let d = generate(TEMPLATE, 1, "127.0.0.1:1").unwrap_or_else(|e| panic!("{e}"));
    let checked = validate::check(&d.config, secret_blob::MAX_PEERS).unwrap_or_else(|e| panic!("{e}"));
    let blob = secret_blob::Blob::parse(&d.blob[..], 1).unwrap_or_else(|e| panic!("{}", e.message()));
    let (_, psk) = blob.peer(0).unwrap_or_else(|| panic!("peer missing"));
    let conf = &d.peer_configs[0];
    assert!(conf.contains(&format!("PresharedKey = {}\n", encode_key(psk))));
    assert!(conf.contains(&format!("PublicKey = {}\n", encode_key(&checked.gateway_public))));
}

#[test]
fn two_runs_produce_different_keys() {
    let a = generate(TEMPLATE, 1, "x:1").unwrap_or_else(|e| panic!("{e}"));
    let b = generate(TEMPLATE, 1, "x:1").unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(a.blob[..], b.blob[..]);
}

#[test]
fn rejects_zero_peers() {
    assert!(generate(TEMPLATE, 0, "x:1").is_err());
}

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("mksecrets-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&d);
    d.canonicalize().unwrap_or(d)
}

#[test]
fn out_dir_inside_a_forbidden_root_is_refused() {
    let root = scratch();
    assert!(check_out_dir(&root.join("secrets"), std::slice::from_ref(&root)).is_err());
}

#[test]
fn out_dir_reached_through_a_symlink_into_a_forbidden_root_is_refused() {
    let root = scratch().join("forbidden");
    let outside = scratch().join("outside");
    let _ = std::fs::create_dir_all(&root);
    let _ = std::fs::create_dir_all(&outside);
    let link = outside.join("link");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&root, &link).unwrap_or_else(|e| panic!("{e}"));
    assert!(check_out_dir(&link.join("secrets"), std::slice::from_ref(&root)).is_err());
}

#[test]
fn out_dir_outside_forbidden_roots_is_accepted() {
    let root = scratch().join("forbidden2");
    let _ = std::fs::create_dir_all(&root);
    assert!(check_out_dir(&scratch().join("ok"), &[root]).is_ok());
}

#[test]
fn the_repository_is_a_forbidden_root() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap_or_default();
    assert!(forbidden_roots().contains(&repo));
}
