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
    assert!(err(&cfg(&peer(K1, "\"10.200.0.2/24\""))).contains("host bits"));
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
