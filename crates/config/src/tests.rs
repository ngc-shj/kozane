#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::string::String;

#[allow(dead_code)]
mod validate {
    use std::{format, string::String, vec::Vec};
    include!("validate.rs");
}

use std::vec::Vec;

const RP_LEN: usize = validate::RP_PUBLIC_KEY_LEN;

/// `TLS_PUBLIC_HEX` decoded.
const TLS_PUBLIC: [u8; validate::TLS_PUBLIC_LEN] = {
    let mut p = [0x11; validate::TLS_PUBLIC_LEN];
    p[0] = 0x04;
    p
};
const TLS_PUBLIC_HEX: &str = "0411111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";

/// A stand-in certificate: DER-ish bytes around the SPKI of `public`.
fn cert_for(public: &[u8], pad: usize) -> Vec<u8> {
    let mut c = std::vec![0x30, 0x82, 0x01, 0x23];
    c.extend(std::iter::repeat_n(0xa0, pad));
    c.extend_from_slice(&validate::P256_SPKI_PREFIX);
    c.extend_from_slice(public);
    c.extend_from_slice(&[0xa3, 0x00]);
    c
}

/// Key files served from memory: `rp-<n>.pk` is a public key of [n; RP_LEN],
/// `short.pk` and `long.pk` miss the size by one byte; `tls.der` holds
/// `TLS_PUBLIC`, `other.der` another point, `big.der` is one byte over the
/// size limit and `noprefix.der` has the point without its SPKI prefix.
fn load(name: &str) -> Result<Vec<u8>, String> {
    let mut other = TLS_PUBLIC;
    other[64] ^= 1;
    match name {
        "short.pk" => Ok(std::vec![1; RP_LEN - 1]),
        "long.pk" => Ok(std::vec![1; RP_LEN + 1]),
        "tls.der" => Ok(cert_for(&TLS_PUBLIC, 0)),
        "max.der" => Ok(cert_for(&TLS_PUBLIC, validate::MAX_TLS_CERT - cert_for(&TLS_PUBLIC, 0).len())),
        "big.der" => Ok(cert_for(&TLS_PUBLIC, validate::MAX_TLS_CERT + 1 - cert_for(&TLS_PUBLIC, 0).len())),
        "other.der" => Ok(cert_for(&other, 0)),
        "noprefix.der" => Ok([&[0x30u8, 0x00][..], &TLS_PUBLIC[..]].concat()),
        "mldsa.pk" => Ok(std::vec![0x33; validate::MLDSA65_PUB_LEN]),
        "mldsa-short.pk" => Ok(std::vec![0x33; validate::MLDSA65_PUB_LEN - 1]),
        "mldsa-zero.pk" => Ok(std::vec![0; validate::MLDSA65_PUB_LEN]),
        _ => name
            .strip_prefix("rp-")
            .and_then(|n| n.strip_suffix(".pk"))
            .and_then(|n| n.parse::<u8>().ok())
            .map(|n| std::vec![n; RP_LEN])
            .ok_or_else(|| std::format!("no such file {name}")),
    }
}

fn rp_hash(n: u8) -> String {
    validate::encode_hash(&secret_blob::blake2s(&[&std::vec![n; RP_LEN]]))
}

fn check(text: &str) -> Result<validate::Checked, String> {
    validate::check(text, &load)
}

const KG: &str = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=";

fn base() -> String {
    std::format!(
        r#"[gateway]
public_key = "{KG}"
listen_port = 51820
rp_port = 51819
https_port = 443
rp_pub_path = "rp-0.pk"
rp_hash = "{gw_rp}"
outside_ip = "10.0.2.15"
outside_mac = "52:54:00:12:34:56"
outside_router_mac = "52:55:0a:00:02:02"
inside_ip = "10.99.0.1"
inside_prefix = "10.99.0.0/24"
inside_mac = "52:54:00:12:34:57"
tls_ports = {{ start = 40000, count = 1024 }}
backend = {{ ip = "10.99.0.2", port = 8080 }}
tls_cert = "tls.der"
tls_public = "{TLS_PUBLIC_HEX}"

[[neighbors]]
ip = "10.99.0.2"
mac = "02:00:00:00:99:02"
"#,
        gw_rp = rp_hash(0)
    )
}

fn err(text: &str) -> String {
    check(text).err().unwrap()
}

#[test]
fn valid_config_is_accepted() {
    let c = check(&base()).unwrap();
    assert_eq!(c.gateway_public, [9; 32]);
}

/// M8 plan D4, C7: peers are not configuration; a `[[peers]]` table is
/// refused like any unknown one, and nothing peer-shaped is rendered.
#[test]
fn a_peers_table_is_refused_and_no_peer_is_rendered() {
    let peer = "\n[[peers]]\nwg_pub = \"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\"\nrp_pub_path = \"rp-1.pk\"\n\
                rp_hash = \"00\"\nallowed_ips = [\"10.200.0.2/32\"]\n";
    assert!(err(&(base() + peer)).contains("unknown field `peers`"));
    let r = validate::render(&check(&base()).unwrap(), "gw.pk");
    assert!(!r.contains("const PEERS") && !r.contains("peer_rp_publics"));
    assert!(r.contains("pub const MAX_PEERS: usize = 8;\n"));
}

#[test]
fn malformed_gateway_key_is_rejected() {
    assert!(err(&base().replace(KG, "not-a-key")).contains("base64"));
    let short = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    assert!(err(&base().replace(KG, short)).contains("expected 44 base64 characters"));
}

#[test]
fn unknown_field_is_rejected() {
    assert!(err(&(base() + "\n[extra]\nx = 1\n")).contains("config"));
}

#[test]
fn multicast_mac_is_rejected() {
    let text = base().replace("02:00:00:00:99:02", "03:00:00:00:99:02");
    assert!(err(&text).contains("unicast"));
}

fn with_neighbors(n: usize) -> String {
    let mut c = base();
    for i in 0..n {
        c += &std::format!("\n[[neighbors]]\nip = \"10.99.0.{}\"\nmac = \"02:00:00:00:00:{:02x}\"\n", i + 3, i + 3);
    }
    c
}

#[test]
fn neighbor_count_is_bounded() {
    // `cfg` already declares one neighbor.
    assert!(check(&with_neighbors(validate::MAX_NEIGHBORS - 1)).is_ok());
    assert!(err(&with_neighbors(validate::MAX_NEIGHBORS)).contains("at most 64 neighbors"));
}

#[test]
fn neighbor_on_a_gateway_address_is_rejected() {
    let c = base() + "\n[[neighbors]]\nip = \"10.99.0.1\"\nmac = \"02:00:00:00:99:09\"\n";
    assert!(err(&c).contains("uses a gateway address"));
}

#[test]
fn duplicate_neighbor_is_rejected() {
    let c = base() + "\n[[neighbors]]\nip = \"10.99.0.2\"\nmac = \"02:00:00:00:99:03\"\n";
    assert!(err(&c).contains("duplicate neighbor 10.99.0.2"));
}

#[test]
fn zero_listen_port_is_rejected() {
    let c = base().replace("listen_port = 51820", "listen_port = 0");
    assert!(err(&c).contains("listen_port must be non-zero"));
}

#[test]
fn prefix_length_over_32_is_rejected() {
    assert!(err(&base().replace("10.99.0.0/24", "10.99.0.0/33")).contains("bad prefix length"));
}

#[test]
fn malformed_ipv4_is_rejected() {
    assert!(err(&base().replace("outside_ip = \"10.0.2.15\"", "outside_ip = \"10.0.2.256\"")).contains("bad IPv4 address"));
}

#[test]
fn malformed_mac_is_rejected() {
    let c = base().replace("52:54:00:12:34:57", "52:54:00:12:34");
    assert!(err(&c).contains("bad MAC"));
}

#[test]
fn neighbor_outside_the_inside_network_is_rejected() {
    let c = base() + "\n[[neighbors]]\nip = \"10.98.0.5\"\nmac = \"02:00:00:00:98:05\"\n";
    assert!(err(&c).contains("outside inside_prefix"));
}

#[test]
fn inside_address_outside_its_prefix_is_rejected() {
    // Only inside_ip moves, so it is the sole violation.
    let c = base().replace("inside_ip = \"10.99.0.1\"", "inside_ip = \"10.98.0.1\"");
    assert!(err(&c).contains("inside_ip 10.98.0.1 is outside inside_prefix"));
}

#[test]
fn outside_address_inside_the_inside_network_is_rejected() {
    let c = base().replace("outside_ip = \"10.0.2.15\"", "outside_ip = \"10.99.0.200\"");
    assert!(err(&c).contains("outside_ip lies inside inside_prefix"));
}

#[test]
fn outside_address_next_to_the_inside_network_is_accepted() {
    let c = base().replace("outside_ip = \"10.0.2.15\"", "outside_ip = \"10.99.1.1\"");
    assert!(check(&c).is_ok());
}

#[test]
fn malformed_inside_prefix_is_named_in_the_error() {
    let c = base().replace("inside_prefix = \"10.99.0.0/24\"", "inside_prefix = \"10.99.0.1/24\"");
    let e = err(&c);
    assert!(e.contains("inside_prefix: prefix \"10.99.0.1/24\" has host bits set"), "{e}");
    assert!(!e.contains("allowed IP"), "{e}");
}

#[test]
fn addresses_adjacent_to_the_inside_network_are_accepted() {
    // One past each end of 10.99.0.0/24: the overlap test is inclusive, not wider.
    for outside in ["10.99.1.0", "10.98.255.255"] {
        let c = base().replace("outside_ip = \"10.0.2.15\"", &std::format!("outside_ip = \"{outside}\""));
        assert!(check(&c).is_ok(), "{outside}");
    }
}

#[test]
fn mceliece_public_key_must_be_exactly_524160_bytes() {
    assert_eq!(RP_LEN, 524_160);
    let ok = base();
    assert!(check(&ok).is_ok());
    for (file, len) in [("short.pk", RP_LEN - 1), ("long.pk", RP_LEN + 1)] {
        let hash = validate::encode_hash(&secret_blob::blake2s(&[&std::vec![1u8; len]]));
        let text = ok.replace("rp-0.pk", file).replace(&rp_hash(0), &hash);
        assert_eq!(err(&text), std::format!("config: McEliece public key {file}: {len} bytes, expected 524160"));
    }
}

#[test]
fn mceliece_key_not_matching_its_hash_is_rejected() {
    let text = base().replace(&rp_hash(0), &rp_hash(2));
    assert!(err(&text).contains("rp-0.pk does not match its rp_hash"));
}

#[test]
fn malformed_rp_hash_is_rejected() {
    let text = base().replace(&rp_hash(0), "00");
    assert!(err(&text).contains("expected 64 hex digits"));
}

#[test]
fn missing_mceliece_key_file_is_rejected() {
    let text = base().replace("rp-0.pk", "absent.pk");
    assert!(err(&text).contains("no such file absent.pk"));
}

#[test]
fn rp_port_must_be_non_zero_and_distinct_from_listen_port() {
    let base = base();
    assert!(err(&base.replace("rp_port = 51819", "rp_port = 0")).contains("rp_port must be non-zero"));
    assert!(err(&base.replace("rp_port = 51819", "rp_port = 51820")).contains("rp_port must differ from listen_port"));
    assert!(err(&base.replace("rp_port = 51819\n", "")).contains("missing field `rp_port`"));
    assert!(check(&base.replace("rp_port = 51819", "rp_port = 51821")).is_ok());
}

#[test]
fn compiled_mceliece_keys_match_their_hashes() {
    assert_eq!(secret_blob::blake2s(&[gateway_rp_public!()]), crate::GATEWAY_RP_HASH);
    assert_ne!(crate::RP_PORT, crate::LISTEN_PORT);
}

#[test]
fn https_port_must_be_present_and_non_zero() {
    let base = base();
    assert!(err(&base.replace("https_port = 443", "https_port = 0")).contains("https_port must be non-zero"));
    assert!(err(&base.replace("https_port = 443\n", "")).contains("missing field `https_port`"));
    assert_eq!(check(&base.replace("https_port = 443", "https_port = 1")).map(|c| c.https_port), Ok(1));
    // TCP: the same number as a UDP port is no conflict.
    assert!(check(&base.replace("https_port = 443", "https_port = 51820")).is_ok());
}

#[test]
fn https_port_is_rendered_for_the_pds() {
    let checked = check(&base()).unwrap();
    assert!(validate::render(&checked, "gw.pk").contains("pub const HTTPS_PORT: u16 = 443;\n"));
    assert_ne!(crate::HTTPS_PORT, 0);
}

fn with_ports(start: u32, count: u32) -> String {
    base().replace("tls_ports = { start = 40000, count = 1024 }", &std::format!("tls_ports = {{ start = {start}, count = {count} }}"))
}

/// M6 plan C3 (F-N-d): start ≠ 0, count ≥ 8, start + count ≤ 65536, each
/// bound tested on both sides.
#[test]
fn tls_ports_start_must_be_non_zero() {
    assert!(err(&with_ports(0, 1024)).contains("tls_ports.start must be non-zero"));
    assert_eq!(check(&with_ports(1, 1024)).map(|c| c.tls_ports), Ok((1, 1024)));
}

#[test]
fn tls_ports_count_must_cover_every_connection() {
    assert!(err(&with_ports(40000, 7)).contains("tls_ports.count must be at least 8, got 7"));
    assert_eq!(check(&with_ports(40000, 8)).map(|c| c.tls_ports), Ok((40000, 8)));
}

#[test]
fn tls_ports_must_end_at_or_before_port_65535() {
    assert_eq!(check(&with_ports(65528, 8)).map(|c| c.tls_ports), Ok((65528, 8)));
    assert!(err(&with_ports(65529, 8)).contains("tls_ports 65529+8 runs past port 65535"));
    assert_eq!(check(&with_ports(1, 65535)).map(|c| c.tls_ports), Ok((1, 65535)));
    assert!(err(&with_ports(2, 65535)).contains("runs past port 65535"));
    assert!(err(&with_ports(u32::MAX, u32::MAX)).contains("runs past port 65535"));
}

#[test]
fn tls_ports_and_backend_are_required_fields() {
    assert!(err(&base().replace("tls_ports = { start = 40000, count = 1024 }\n", "")).contains("missing field `tls_ports`"));
    assert!(err(&base().replace("backend = { ip = \"10.99.0.2\", port = 8080 }\n", "")).contains("missing field `backend`"));
    assert!(err(&base().replace("count = 1024 }", "count = 1024, end = 3 }")).contains("unknown field"));
}

/// M6 plan C4 (F16a): the backend lies in `inside_prefix` and is a
/// configured neighbor.
#[test]
fn backend_must_be_a_configured_inside_neighbor() {
    let b = |ip: &str| {
        base().replace("ip = \"10.99.0.2\", port", &std::format!("ip = \"{ip}\", port"))
            + "\n[[neighbors]]\nip = \"10.99.0.3\"\nmac = \"02:00:00:00:99:03\"\n"
    };
    assert_eq!(check(&b("10.99.0.3")).map(|c| c.backend), Ok(([10, 99, 0, 3], 8080)));
    assert!(err(&b("10.99.0.4")).contains("backend 10.99.0.4 is not a configured neighbor"));
    assert!(err(&b("10.98.0.2")).contains("backend 10.98.0.2 is outside inside_prefix"));
    // The gateway's own inside address is in the prefix but no neighbor.
    assert!(err(&b("10.99.0.1")).contains("is not a configured neighbor"));
    assert!(err(&b("10.99.0")).contains("config: backend: bad IPv4 address"));
}

#[test]
fn backend_port_must_be_non_zero() {
    assert!(err(&base().replace("port = 8080", "port = 0")).contains("backend port must be non-zero"));
    assert_eq!(check(&base().replace("port = 8080", "port = 1")).map(|c| c.backend.1), Ok(1));
}

/// M6 plan C11: the certificate holds the 26-byte P-256 SPKI prefix
/// followed by `tls_public`.
#[test]
fn tls_cert_must_hold_tls_public_as_a_p256_spki() {
    let c = check(&base()).unwrap();
    assert_eq!((c.tls_public, c.tls_cert.clone()), (TLS_PUBLIC, cert_for(&TLS_PUBLIC, 0)));
    let with_cert = |f: &str| base().replace("tls_cert = \"tls.der\"", &std::format!("tls_cert = \"{f}\""));
    assert!(err(&with_cert("other.der")).contains("does not hold tls_public as a P-256 public key"));
    assert!(err(&with_cert("noprefix.der")).contains("does not hold tls_public as a P-256 public key"));
    assert!(err(&with_cert("missing.der")).contains("no such file missing.der"));
}

#[test]
fn tls_cert_size_is_bounded() {
    let with_cert = |f: &str| base().replace("tls_cert = \"tls.der\"", &std::format!("tls_cert = \"{f}\""));
    assert_eq!(check(&with_cert("max.der")).map(|c| c.tls_cert.len()), Ok(validate::MAX_TLS_CERT));
    assert!(err(&with_cert("big.der")).contains(&std::format!("{} bytes, at most {}", validate::MAX_TLS_CERT + 1, validate::MAX_TLS_CERT)));
}

#[test]
fn tls_public_must_be_an_uncompressed_point_in_hex() {
    let with_public = |h: &str| base().replace(TLS_PUBLIC_HEX, h);
    assert!(err(&with_public(&TLS_PUBLIC_HEX[..128])).contains("expected 130 hex digits"));
    assert!(err(&with_public(&std::format!("{TLS_PUBLIC_HEX}11"))).contains("expected 130 hex digits"));
    assert!(err(&with_public(&TLS_PUBLIC_HEX.replacen("04", "02", 1))).contains("uncompressed P-256 point"));
    assert!(err(&with_public(&TLS_PUBLIC_HEX.replacen("11", "1g", 1))).contains("expected 130 hex digits"));
}

#[test]
fn tls_outputs_are_rendered_for_the_pds() {
    let r = validate::render(&check(&base()).unwrap(), "gw.pk");
    assert!(r.contains("pub const TLS_PORTS: (u16, u16) = (40000, 1024);\n"));
    assert!(r.contains("pub const BACKEND: ([u8; 4], u16) = ([10, 99, 0, 2], 8080);\n"));
    assert!(r.contains(&std::format!("pub const TLS_CERT: &[u8] = &{:?};\n", cert_for(&TLS_PUBLIC, 0))));
    assert!(r.contains(&std::format!("pub const TLS_PUBLIC: [u8; 65] = {:?};\n", TLS_PUBLIC)));
}

/// The compiled configuration's certificate holds its public key (the
/// build-time check, on what the PDs get).
#[test]
fn compiled_tls_cert_holds_the_compiled_tls_public() {
    let mut spki = validate::P256_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(&crate::TLS_PUBLIC);
    assert!(crate::TLS_CERT.windows(spki.len()).any(|w| w == spki.as_slice()));
    assert!(crate::TLS_PORTS.1 >= 8);
    assert!(crate::NEIGHBORS.iter().any(|n| n.ip == crate::BACKEND.0));
}

// M8 plan C3: the policy indices' expected Names.

const CTR_NAME_HEX: &str = "000b1111111111111111111111111111111111111111111111111111111111111111";
const BASE_NAME_HEX: &str = "000b2222222222222222222222222222222222222222222222222222222222222222";

const FLEET_HEX: &str = "0123456789abcdef0123456789abcdef";
const ED_HEX: &str = "4444444444444444444444444444444444444444444444444444444444444444";

fn policy_table(fleet: &str, ed: &str, mldsa: &str, ctr: &str, base_name: &str) -> String {
    std::format!(
        "{}\n[policy]\nfleet_id = \"{fleet}\"\ned25519_pub = \"{ed}\"\nmldsa65_pub = \"{mldsa}\"\n\
         nv_ctr_name = \"{ctr}\"\nnv_base_name = \"{base_name}\"\n",
        base()
    )
}

fn with_policy(ctr: &str, base_name: &str) -> String {
    policy_table(FLEET_HEX, ED_HEX, "mldsa.pk", ctr, base_name)
}

#[test]
fn policy_names_are_decoded_and_rendered() {
    let c = check(&with_policy(CTR_NAME_HEX, BASE_NAME_HEX)).unwrap();
    let mut ctr = [0x11; validate::NV_NAME_LEN];
    ctr[..2].copy_from_slice(&[0x00, 0x0B]);
    let mut base_name = [0x22; validate::NV_NAME_LEN];
    base_name[..2].copy_from_slice(&[0x00, 0x0B]);
    assert_eq!((c.nv_ctr_name, c.nv_base_name), (ctr, base_name));
    let r = validate::render(&c, "gw.pk");
    assert!(r.contains(&std::format!("pub const NV_CTR_NAME: [u8; 34] = {ctr:?};\n")));
    assert!(r.contains(&std::format!("pub const NV_BASE_NAME: [u8; 34] = {base_name:?};\n")));
}

/// Absent means fail closed: an all-zero Name, which no index has.
#[test]
fn without_a_policy_table_the_names_render_all_zero() {
    let c = check(&base()).unwrap();
    assert_eq!((c.nv_ctr_name, c.nv_base_name), ([0; 34], [0; 34]));
    let zero = std::format!("pub const NV_CTR_NAME: [u8; 34] = {:?};\n", [0u8; 34]);
    assert!(validate::render(&c, "gw.pk").contains(&zero));
    // The compiled default configuration has no [policy] yet.
    assert_eq!((crate::NV_CTR_NAME, crate::NV_BASE_NAME), ([0; 34], [0; 34]));
}

#[test]
fn malformed_policy_names_are_rejected() {
    let bad = [
        &CTR_NAME_HEX[..66],
        &std::format!("{CTR_NAME_HEX}11"),
        &CTR_NAME_HEX.replacen("11", "1g", 1),
        &CTR_NAME_HEX.replacen("000b", "000c", 1),
        &std::format!("000b{}", "00".repeat(32)),
    ];
    for name in bad {
        assert!(err(&with_policy(name, BASE_NAME_HEX)).contains("expected 68 hex digits"), "{name}");
        assert!(err(&with_policy(CTR_NAME_HEX, name)).contains("expected 68 hex digits"), "{name}");
    }
    assert!(err(&with_policy(CTR_NAME_HEX, CTR_NAME_HEX)).contains("are the same Name"));
    let renamed = with_policy(CTR_NAME_HEX, BASE_NAME_HEX).replace("nv_base_name", "nv_other_name");
    assert!(err(&renamed).contains("unknown field"));
    let one = with_policy(CTR_NAME_HEX, BASE_NAME_HEX).replace(&std::format!("nv_base_name = \"{BASE_NAME_HEX}\"\n"), "");
    assert!(err(&one).contains("missing field `nv_base_name`"));
}

// M8 plan C5, C7: the fleet ID and the bundle signing keys.

#[test]
fn policy_fleet_id_and_keys_are_decoded_and_rendered() {
    let c = check(&with_policy(CTR_NAME_HEX, BASE_NAME_HEX)).unwrap();
    let fleet: [u8; 16] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    assert_eq!((c.fleet_id, c.ed25519_pub), (fleet, [0x44; 32]));
    assert_eq!(c.mldsa65_pub, std::vec![0x33; validate::MLDSA65_PUB_LEN]);
    let r = validate::render(&c, "gw.pk");
    assert!(r.contains(&std::format!("pub const FLEET_ID: [u8; 16] = {fleet:?};\n")));
    assert!(r.contains(&std::format!("pub const POLICY_ED25519_PUB: [u8; 32] = {:?};\n", [0x44u8; 32])));
    assert!(r.contains(&std::format!("pub const POLICY_MLDSA65_PUB: [u8; 1952] = {:?};\n", std::vec![0x33u8; 1952])));
}

/// Absent means fail closed: all-zero keys, which `policy` refuses before
/// any verifier runs, and a fleet ID no signed bundle carries.
#[test]
fn without_a_policy_table_the_fleet_and_keys_render_all_zero() {
    let c = check(&base()).unwrap();
    assert_eq!((c.fleet_id, c.ed25519_pub), ([0; 16], [0; 32]));
    assert_eq!(c.mldsa65_pub, std::vec![0; validate::MLDSA65_PUB_LEN]);
    let r = validate::render(&c, "gw.pk");
    assert!(r.contains(&std::format!("pub const POLICY_MLDSA65_PUB: [u8; 1952] = {:?};\n", std::vec![0u8; 1952])));
    assert_eq!((crate::FLEET_ID, crate::POLICY_ED25519_PUB), ([0; 16], [0; 32]));
    assert!(crate::POLICY_MLDSA65_PUB.iter().all(|b| *b == 0));
}

#[test]
fn malformed_policy_fleet_id_and_keys_are_rejected() {
    let table = |fleet: &str, ed: &str, mldsa: &str| policy_table(fleet, ed, mldsa, CTR_NAME_HEX, BASE_NAME_HEX);
    for fleet in [&FLEET_HEX[..30], &std::format!("{FLEET_HEX}00"), &FLEET_HEX.replacen('0', "g", 1), &"00".repeat(16)] {
        assert!(err(&table(fleet, ED_HEX, "mldsa.pk")).contains("policy fleet_id"), "{fleet}");
    }
    for ed in [&ED_HEX[..62], &std::format!("{ED_HEX}44"), &ED_HEX.replacen('4', "x", 1), &"00".repeat(32)] {
        assert!(err(&table(FLEET_HEX, ed, "mldsa.pk")).contains("policy ed25519_pub"), "{ed}");
    }
    assert!(err(&table(FLEET_HEX, ED_HEX, "mldsa-short.pk")).contains("1951 bytes, expected 1952"));
    assert!(err(&table(FLEET_HEX, ED_HEX, "mldsa-zero.pk")).contains("is all zero"));
    assert!(err(&table(FLEET_HEX, ED_HEX, "missing.pk")).contains("no such file"));
    let no_fleet = with_policy(CTR_NAME_HEX, BASE_NAME_HEX).replace(&std::format!("fleet_id = \"{FLEET_HEX}\"\n"), "");
    assert!(err(&no_fleet).contains("missing field `fleet_id`"));
}

/// `node_config()` is the compiled configuration, field by field.
#[test]
fn node_config_is_the_compiled_configuration() {
    let n = crate::node_config();
    assert_eq!(n.fleet_id, crate::FLEET_ID);
    assert_eq!(n.inside_prefix, crate::INSIDE_PREFIX);
    assert!(n.inside_prefix.contains(crate::INSIDE_IP));
    assert_eq!((n.inside_ip, n.outside_ip), (crate::INSIDE_IP, crate::OUTSIDE_IP));
    let ips: Vec<[u8; 4]> = crate::NEIGHBORS.iter().map(|x| x.ip).collect();
    assert_eq!(n.neighbors, ips.as_slice());
    assert_eq!((n.gateway_wg_public, n.gateway_rp_digest), (crate::GATEWAY_PUBLIC, crate::GATEWAY_RP_HASH));
}
