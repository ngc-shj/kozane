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

fn system_text() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../system/secureos.system");
    std::fs::read_to_string(path).expect("read .system")
}

fn mr_sizes() -> HashMap<String, usize> {
    let text = system_text();
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

/// (pd a, id at a) -> (pd b, id at b) for every channel end pair.
fn channel_ids() -> std::vec::Vec<((String, usize), (String, usize))> {
    let text = system_text();
    let doc = roxmltree::Document::parse(&text).expect("parse .system");
    doc.descendants()
        .filter(|n| n.has_tag_name("channel"))
        .map(|c| {
            let ends: std::vec::Vec<(String, usize)> = c
                .children()
                .filter(|e| e.has_tag_name("end"))
                .map(|e| (e.attribute("pd").expect("pd").into(), parse_num(e.attribute("id").expect("id"))))
                .collect();
            assert_eq!(ends.len(), 2);
            (ends[0].clone(), ends[1].clone())
        })
        .collect()
}

fn has_channel(a: (&str, usize), b: (&str, usize)) -> bool {
    channel_ids().iter().any(|(x, y)| {
        (x.0 == a.0 && x.1 == a.1 && y.0 == b.0 && y.1 == b.1) || (x.0 == b.0 && x.1 == b.1 && y.0 == a.0 && y.1 == a.1)
    })
}

#[test]
fn channel_ids_match_layout() {
    assert!(has_channel(("eth_out", eth_out::CH_INGRESS), ("ingress", ingress::CH_ETH_OUT)));
    assert!(has_channel(("eth_out", eth_out::CH_AUDIT), ("audit", audit::CH_ETH_OUT)));
    assert!(has_channel(("ingress", ingress::CH_AUDIT), ("audit", audit::CH_INGRESS)));
    assert_eq!(channel_ids().len(), 3, "a channel not described by layout");
}

#[test]
fn eth_out_irq_matches_layout() {
    let text = system_text();
    let doc = roxmltree::Document::parse(&text).expect("parse .system");
    let pd = doc
        .descendants()
        .find(|n| n.has_tag_name("protection_domain") && n.attribute("name") == Some("eth_out"))
        .expect("eth_out pd");
    let irqs: std::vec::Vec<(usize, usize)> = pd
        .children()
        .filter(|n| n.has_tag_name("irq"))
        .map(|n| (parse_num(n.attribute("irq").expect("irq")), parse_num(n.attribute("id").expect("id"))))
        .collect();
    assert_eq!(irqs, [(ETH_OUT_IRQ, eth_out::CH_DEVICE)]);
}
