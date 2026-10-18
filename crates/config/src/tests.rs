#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::string::String;

#[allow(dead_code)]
mod validate {
    use std::{format, string::String, vec::Vec};
    include!("validate.rs");
}

const K1: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const K2: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
const KG: &str = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=";

fn cfg(peers: &str) -> String {
    std::format!(
        r#"[gateway]
public_key = "{KG}"
listen_port = 51820
outside_ip = "10.0.2.15"
outside_mac = "52:54:00:12:34:56"
outside_router_mac = "52:55:0a:00:02:02"
inside_ip = "10.99.0.1"
inside_prefix = "10.99.0.0/24"
inside_mac = "52:54:00:12:34:57"

[[neighbors]]
ip = "10.99.0.2"
mac = "02:00:00:00:99:02"
{peers}"#
    )
}

fn peer(key: &str, ips: &str) -> String {
    std::format!("[[peers]]\npublic_key = \"{key}\"\nallowed_ips = [{ips}]\n")
}

fn err(text: &str) -> String {
    validate::check(text, 4).err().unwrap()
}

#[test]
fn valid_config_is_accepted() {
    let c = validate::check(&cfg(&(peer(K1, "\"10.200.0.2/32\"") + &peer(K2, "\"10.200.1.0/24\""))), 4).unwrap();
    assert_eq!(c.peers.len(), 2);
    assert_eq!(c.gateway_public, [9; 32]);
}

#[test]
fn overlapping_allowed_ips_are_rejected() {
    assert!(err(&cfg(&(peer(K1, "\"10.200.0.0/16\"") + &peer(K2, "\"10.200.1.0/24\"")))).contains("overlap"));
}

#[test]
fn adjacent_allowed_ips_are_accepted() {
    assert!(validate::check(&cfg(&(peer(K1, "\"10.200.0.0/24\"") + &peer(K2, "\"10.200.1.0/24\""))), 4).is_ok());
}

#[test]
fn duplicate_peer_is_rejected() {
    assert!(err(&cfg(&(peer(K1, "\"10.200.0.2/32\"") + &peer(K1, "\"10.200.0.3/32\"")))).contains("duplicate peer"));
}

#[test]
fn malformed_key_is_rejected() {
    assert!(err(&cfg(&peer("not-a-key", "\"10.200.0.2/32\""))).contains("base64"));
}

#[test]
fn host_bits_in_prefix_are_rejected() {
    let e = err(&cfg(&peer(K1, "\"10.200.0.2/24\"")));
    assert_eq!(e, "config: allowed IP: prefix \"10.200.0.2/24\" has host bits set");
}

#[test]
fn too_many_peers_are_rejected() {
    let mut p = String::new();
    for (i, k) in [K1, K2, KG].iter().enumerate() {
        p += &peer(k, &std::format!("\"10.200.{i}.0/24\""));
    }
    assert!(validate::check(&cfg(&p), 2).err().unwrap().contains("peers"));
}

#[test]
fn peer_with_gateway_key_is_rejected() {
    assert!(err(&cfg(&peer(KG, "\"10.200.0.2/32\""))).contains("gateway's own key"));
}

#[test]
fn unknown_field_is_rejected() {
    assert!(err(&(cfg(&peer(K1, "\"10.200.0.2/32\"")) + "\n[extra]\nx = 1\n")).contains("config"));
}

#[test]
fn multicast_mac_is_rejected() {
    let text = cfg(&peer(K1, "\"10.200.0.2/32\"")).replace("02:00:00:00:99:02", "03:00:00:00:99:02");
    assert!(err(&text).contains("unicast"));
}

#[test]
fn compiled_config_routes_by_allowed_ips() {
    let first = crate::PEERS[0].allowed[0];
    assert_eq!(crate::peer_for(first.addr), Some(0));
    assert_eq!(crate::peer_for([192, 0, 2, 1]), None);
}

#[test]
fn peer_count_bound_is_the_deployable_limit() {
    let many = |n: usize| -> String {
        (0..n)
            .map(|i| {
                let k = base64_key(i as u8 + 1);
                peer(&k, &std::format!("\"10.200.{i}.0/24\""))
            })
            .collect()
    };
    assert!(validate::check(&cfg(&many(validate::MAX_PEERS)), validate::MAX_PEERS).is_ok());
    let e = validate::check(&cfg(&many(validate::MAX_PEERS + 1)), validate::MAX_PEERS).err().unwrap();
    assert!(e.contains("need 1..=8 peers"), "{e}");
}

/// The 32-byte key [b; 32] in base64.
fn base64_key(b: u8) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = [b; 32];
    let mut s = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            s.push(if i <= c.len() { char::from(A[(n >> (18 - 6 * i) & 63) as usize]) } else { '=' });
        }
    }
    s
}

fn with_neighbors(n: usize) -> String {
    let mut c = cfg(&peer(K1, "\"10.200.0.2/32\""));
    for i in 0..n {
        c += &std::format!("\n[[neighbors]]\nip = \"10.99.0.{}\"\nmac = \"02:00:00:00:00:{:02x}\"\n", i + 3, i + 3);
    }
    c
}

#[test]
fn neighbor_count_is_bounded() {
    // `cfg` already declares one neighbor.
    assert!(validate::check(&with_neighbors(validate::MAX_NEIGHBORS - 1), 4).is_ok());
    assert!(err(&with_neighbors(validate::MAX_NEIGHBORS)).contains("at most 64 neighbors"));
}

#[test]
fn neighbor_on_a_gateway_address_is_rejected() {
    let c = cfg(&peer(K1, "\"10.200.0.2/32\"")) + "\n[[neighbors]]\nip = \"10.99.0.1\"\nmac = \"02:00:00:00:99:09\"\n";
    assert!(err(&c).contains("uses a gateway address"));
}

#[test]
fn allowed_ips_covering_a_neighbor_are_rejected() {
    assert!(err(&cfg(&peer(K1, "\"10.99.0.0/24\""))).contains("cover"));
    assert!(err(&cfg(&peer(K1, "\"0.0.0.0/0\""))).contains("cover"));
    assert!(err(&cfg(&peer(K1, "\"10.99.0.2/32\""))).contains("cover neighbor 10.99.0.2"));
}

#[test]
fn allowed_ips_covering_the_outside_address_are_rejected() {
    assert!(err(&cfg(&peer(K1, "\"10.0.2.15/32\""))).contains("cover a gateway address"));
}

#[test]
fn allowed_ips_next_to_the_inside_network_are_accepted() {
    assert!(validate::check(&cfg(&peer(K1, "\"10.98.0.0/24\"")), 4).is_ok());
}

#[test]
fn zero_peers_are_rejected() {
    // Without any [[peers]] table deserialization refuses the missing field.
    assert!(err(&cfg("")).contains("missing field `peers`"));
}

#[test]
fn peer_without_allowed_ips_is_rejected() {
    assert!(err(&cfg(&peer(K1, ""))).contains("has no allowed IPs"));
}

#[test]
fn duplicate_neighbor_is_rejected() {
    let c = cfg(&peer(K1, "\"10.200.0.2/32\"")) + "\n[[neighbors]]\nip = \"10.99.0.2\"\nmac = \"02:00:00:00:99:03\"\n";
    assert!(err(&c).contains("duplicate neighbor 10.99.0.2"));
}

#[test]
fn zero_listen_port_is_rejected() {
    let c = cfg(&peer(K1, "\"10.200.0.2/32\"")).replace("listen_port = 51820", "listen_port = 0");
    assert!(err(&c).contains("listen_port must be non-zero"));
}

#[test]
fn prefix_length_over_32_is_rejected() {
    assert!(err(&cfg(&peer(K1, "\"10.200.0.2/33\""))).contains("bad prefix length"));
}

#[test]
fn malformed_ipv4_is_rejected() {
    assert!(err(&cfg(&peer(K1, "\"10.200.0.256/32\""))).contains("bad IPv4 address"));
}

#[test]
fn malformed_mac_is_rejected() {
    let c = cfg(&peer(K1, "\"10.200.0.2/32\"")).replace("52:54:00:12:34:57", "52:54:00:12:34");
    assert!(err(&c).contains("bad MAC"));
}

#[test]
fn key_of_the_wrong_length_is_rejected() {
    let short = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    assert!(err(&cfg(&peer(short, "\"10.200.0.2/32\""))).contains("expected 44 base64 characters"));
}

#[test]
fn allowed_ips_overlapping_the_inside_network_are_rejected_without_a_listed_neighbor() {
    // 10.99.0.128/25 covers no listed neighbor and not the gateway, but an
    // unlisted inside host could be impersonated from it.
    assert!(err(&cfg(&peer(K1, "\"10.99.0.128/25\""))).contains("overlap inside_prefix"));
}

#[test]
fn neighbor_outside_the_inside_network_is_rejected() {
    let c = cfg(&peer(K1, "\"10.200.0.2/32\"")) + "\n[[neighbors]]\nip = \"10.98.0.5\"\nmac = \"02:00:00:00:98:05\"\n";
    assert!(err(&c).contains("outside inside_prefix"));
}

#[test]
fn inside_address_outside_its_prefix_is_rejected() {
    // Only inside_ip moves, so it is the sole violation.
    let c = cfg(&peer(K1, "\"10.200.0.2/32\"")).replace("inside_ip = \"10.99.0.1\"", "inside_ip = \"10.98.0.1\"");
    assert!(err(&c).contains("inside_ip 10.98.0.1 is outside inside_prefix"));
}

#[test]
fn outside_address_inside_the_inside_network_is_rejected() {
    let c = cfg(&peer(K1, "\"10.200.0.2/32\"")).replace("outside_ip = \"10.0.2.15\"", "outside_ip = \"10.99.0.200\"");
    assert!(err(&c).contains("outside_ip lies inside inside_prefix"));
}

#[test]
fn outside_address_next_to_the_inside_network_is_accepted() {
    let c = cfg(&peer(K1, "\"10.200.0.2/32\"")).replace("outside_ip = \"10.0.2.15\"", "outside_ip = \"10.99.1.1\"");
    assert!(validate::check(&c, 4).is_ok());
}

#[test]
fn malformed_inside_prefix_is_named_in_the_error() {
    let c = cfg(&peer(K1, "\"10.200.0.2/32\"")).replace("inside_prefix = \"10.99.0.0/24\"", "inside_prefix = \"10.99.0.1/24\"");
    let e = err(&c);
    assert!(e.contains("inside_prefix: prefix \"10.99.0.1/24\" has host bits set"), "{e}");
    assert!(!e.contains("allowed IP"), "{e}");
}

#[test]
fn overlap_boundaries_of_the_inside_network_are_both_refused() {
    // Inclusive at both ends: the network's first and last address.
    assert!(err(&cfg(&peer(K1, "\"10.99.0.0/32\""))).contains("overlap inside_prefix"));
    assert!(err(&cfg(&peer(K1, "\"10.99.0.255/32\""))).contains("overlap inside_prefix"));
    assert!(validate::check(&cfg(&peer(K1, "\"10.100.0.0/32\"")), 4).is_ok());
}

#[test]
fn addresses_adjacent_to_the_inside_network_are_accepted() {
    // One past each end of 10.99.0.0/24: the overlap test is inclusive, not wider.
    assert!(validate::check(&cfg(&peer(K1, "\"10.99.1.0/32\"")), 4).is_ok());
    assert!(validate::check(&cfg(&peer(K1, "\"10.98.255.255/32\"")), 4).is_ok());
    for outside in ["10.99.1.0", "10.98.255.255"] {
        let c = cfg(&peer(K1, "\"10.200.0.2/32\"")).replace("outside_ip = \"10.0.2.15\"", &std::format!("outside_ip = \"{outside}\""));
        assert!(validate::check(&c, 4).is_ok(), "{outside}");
    }
}
