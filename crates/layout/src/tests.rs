//! The .system file and these constants are written independently; these
//! tests are what keeps them in agreement.

extern crate std;

use std::collections::HashMap;
use std::string::String;

use super::*;

fn parse_num(s: &str) -> usize {
    let s: String = s.chars().filter(|c| *c != '_').collect();
    match s.strip_prefix("0x") {
        Some(hex) => usize::from_str_radix(hex, 16).expect("hex number"),
        None => s.parse().expect("decimal number"),
    }
}

fn mr_sizes() -> HashMap<String, usize> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../system/secureos.system");
    let text = std::fs::read_to_string(path).expect("read .system");
    let doc = roxmltree::Document::parse(&text).expect("parse .system");
    doc.descendants()
        .filter(|n| n.has_tag_name("memory_region"))
        .map(|n| (n.attribute("name").expect("name").into(), parse_num(n.attribute("size").expect("size"))))
        .collect()
}

#[test]
fn net_data_regions_match_net_region_size() {
    let m = mr_sizes();
    assert_eq!(m["net_rx_data"], NET_REGION_SIZE);
    assert_eq!(m["net_tx_data"], NET_REGION_SIZE);
}

#[test]
fn net_rings_fit_their_regions() {
    let m = mr_sizes();
    let need = ring::shmem::ring_bytes::<ring::Desc, NET_RING_SLOTS>();
    for mr in ["net_rx_used", "net_rx_free", "net_tx_used", "net_tx_free"] {
        assert!(m[mr] >= need, "{mr}: {} < {need}", m[mr]);
    }
}

#[test]
fn audit_rings_fit_their_regions() {
    let m = mr_sizes();
    let need = ring::shmem::ring_bytes::<audit_event::Record, AUDIT_RING_SLOTS>();
    for mr in ["audit_ingress", "audit_eth_out"] {
        assert!(m[mr] >= need, "{mr}: {} < {need}", m[mr]);
    }
}

#[test]
fn eth_out_dma_matches() {
    assert_eq!(mr_sizes()["eth_out_dma"], ETH_OUT_DMA_SIZE);
}

// NET_RING_SLOTS >= NET_BUFFERS is a compile-time assert in ring::link.
