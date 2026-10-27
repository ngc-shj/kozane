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
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../system/kozane.system");
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

/// Every link (pdkit / ring::link): used ring, free ring, data region.
const LINKS: [&str; 18] = [
    "net_rx", "net_tx", "inner_rx", "inner_tx", "ih", "hi", "hd", "id", "di", "dn", "nd", "ipq", "pqi", "pqh", "itl", "tli",
    "tln", "ntl",
];
const AUDITS: [&str; 8] =
    ["audit_ingress", "audit_eth_out", "audit_eth_in", "audit_inner", "audit_hs", "audit_data", "audit_pq", "audit_tls"];

#[test]
fn link_data_regions_match_net_region_size() {
    let m = mr_sizes();
    for l in LINKS {
        assert_eq!(m[&std::format!("{l}_data")], NET_REGION_SIZE, "{l}");
    }
}

#[test]
fn link_rings_fit_their_regions() {
    let m = mr_sizes();
    let need = ring::shmem::ring_bytes::<ring::Desc, NET_RING_SLOTS>();
    for l in LINKS {
        for side in ["used", "free"] {
            let mr = std::format!("{l}_{side}");
            assert!(m[&mr] >= need, "{mr}: {} < {need}", m[&mr]);
        }
    }
}

#[test]
fn audit_rings_fit_their_regions() {
    let m = mr_sizes();
    let need = ring::shmem::ring_bytes::<audit_event::Record, AUDIT_RING_SLOTS>();
    for mr in AUDITS {
        assert!(m[mr] >= need, "{mr}: {} < {need}", m[mr]);
    }
}

#[test]
fn dma_regions_match() {
    assert_eq!(mr_sizes()["eth_out_dma"], ETH_OUT_DMA_SIZE);
    assert_eq!(mr_sizes()["eth_in_dma"], ETH_IN_DMA_SIZE);
    assert_eq!(mr_sizes()["rng_dma"], RNG_DMA_SIZE);
}

#[test]
fn every_region_is_a_link_an_audit_ring_or_a_named_singleton() {
    let mut expected: std::vec::Vec<String> = LINKS
        .iter()
        .flat_map(|l| ["used", "free", "data"].map(|s| std::format!("{l}_{s}")))
        .chain(AUDITS.iter().map(|a| String::from(*a)))
        .chain(
            ["eth_out_mmio", "eth_out_dma", "eth_in_mmio", "eth_in_dma", "timer_mmio", "uart_mmio", "tpm_mmio", "rng_mmio", "rng_dma", "secrets", "pq_secrets", "tls_secrets"]
                .map(String::from),
        )
        .collect();
    expected.sort();
    let mut actual: std::vec::Vec<String> = mr_sizes().into_keys().collect();
    actual.sort();
    assert_eq!(actual, expected);
}

#[test]
fn secrets_region_holds_one_blob() {
    // Mirrors secret_blob::REGION_SIZE (key maps it whole).
    assert_eq!(mr_sizes()["secrets"], 4096);
}

#[test]
fn tpm_region_is_the_tis_page() {
    let text = system_text();
    let doc = roxmltree::Document::parse(&text).expect("parse .system");
    let mr = doc
        .descendants()
        .find(|n| n.has_tag_name("memory_region") && n.attribute("name") == Some("tpm_mmio"))
        .expect("tpm_mmio");
    assert_eq!(parse_num(mr.attribute("phys_addr").expect("phys_addr")), tpm::TIS_PADDR);
    assert_eq!(parse_num(mr.attribute("size").expect("size")), tpm::TIS_SIZE);
}

#[test]
fn tpm_messages_round_trip_through_words_at_every_length() {
    let bytes: std::vec::Vec<u8> = (0..tpm::MSG_BYTES).map(|i| (i * 7 + 1) as u8).collect();
    for len in [0, 1, 7, 8, 9, 365, tpm::MSG_BYTES - 1, tpm::MSG_BYTES] {
        let mut words = [0u64; tpm::MSG_WORDS];
        assert_eq!(tpm::pack(&bytes[..len], &mut words), Some(tpm::words(len)), "len {len}");
        assert!(words[tpm::words(len)..].iter().all(|w| *w == 0), "len {len}: words past the message");
        let mut out = [0u8; tpm::MSG_BYTES];
        assert_eq!(tpm::unpack(&words[..tpm::words(len)], len, &mut out), Some(()), "len {len}");
        assert_eq!(&out[..len], &bytes[..len], "len {len}");
    }
}

#[test]
fn tpm_pack_and_unpack_refuse_what_does_not_fit() {
    let mut words = [0u64; tpm::MSG_WORDS];
    assert_eq!(tpm::pack(&[1; tpm::MSG_BYTES + 1], &mut words), None);
    let mut out = [0u8; tpm::MSG_BYTES];
    assert_eq!(tpm::unpack(&words[..2], 17, &mut out), None, "fewer words than the length needs");
    assert_eq!(tpm::unpack(&words, 9, &mut out[..8]), None, "an output shorter than the length");
}

#[test]
fn tpm_labels_carry_kind_and_length() {
    let l = tpm::label(tpm::RSP_OK, tpm::MSG_BYTES);
    assert_eq!((tpm::kind(l), tpm::arg(l)), (tpm::RSP_OK, tpm::MSG_BYTES));
    assert_ne!(tpm::label(tpm::REQ_DONE, 0), tpm::label(tpm::REQ_FAILED, 0));
    for req in [tpm::REQ_COMMAND, tpm::REQ_DONE, tpm::REQ_FAILED] {
        assert_ne!(tpm::REQ_CAP_STATUS, req);
    }
}

#[test]
fn pq_secrets_region_holds_one_blob() {
    // Mirrors secret_blob::pq::REGION_SIZE (pqkey maps it whole).
    assert_eq!(mr_sizes()["pq_secrets"], 16384);
}

#[test]
fn tls_secrets_region_holds_one_blob() {
    // Mirrors secret_blob::tls::REGION_SIZE (tlskey maps it whole).
    assert_eq!(mr_sizes()["tls_secrets"], 4096);
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
    let expected = [
        (("eth_out", eth_out::CH_INGRESS), ("ingress", ingress::CH_ETH_OUT)),
        (("eth_out", eth_out::CH_AUDIT), ("audit", audit::CH_ETH_OUT)),
        (("ingress", ingress::CH_AUDIT), ("audit", audit::CH_INGRESS)),
        (("eth_in", eth_in::CH_INNER), ("inner", inner::CH_ETH_IN)),
        (("eth_in", eth_in::CH_AUDIT), ("audit", audit::CH_ETH_IN)),
        (("inner", inner::CH_AUDIT), ("audit", audit::CH_INNER)),
        (("hs", hs::CH_AUDIT), ("audit", audit::CH_HS)),
        (("data", data::CH_AUDIT), ("audit", audit::CH_DATA)),
        (("ingress", ingress::CH_HS), ("hs", hs::CH_INGRESS)),
        (("ingress", ingress::CH_DATA), ("data", data::CH_INGRESS)),
        (("hs", hs::CH_DATA), ("data", data::CH_HS)),
        (("data", data::CH_INNER), ("inner", inner::CH_DATA)),
        (("hs", hs::CH_KEY), ("key", key::CH_HS)),
        (("timer", timer::CH_DATA), ("data", data::CH_TIMER)),
        (("timer", timer::CH_HS), ("hs", hs::CH_TIMER)),
        (("timer", timer::CH_INGRESS), ("ingress", ingress::CH_TIMER)),
        (("pq", pq::CH_PQKEY), ("pqkey", pqkey::CH_PQ)),
        (("ingress", ingress::CH_PQ), ("pq", pq::CH_INGRESS)),
        (("pq", pq::CH_HS), ("hs", hs::CH_PQ)),
        (("timer", timer::CH_PQ), ("pq", pq::CH_TIMER)),
        (("pq", pq::CH_AUDIT), ("audit", audit::CH_PQ)),
        (("key", key::CH_TPM), ("tpm", tpm::CH_KEY)),
        (("pqkey", pqkey::CH_TPM), ("tpm", tpm::CH_PQKEY)),
        (("ingress", ingress::CH_TLS), ("tls", tls::CH_INGRESS)),
        (("tls", tls::CH_INNER), ("inner", inner::CH_TLS)),
        (("timer", timer::CH_TLS), ("tls", tls::CH_TIMER)),
        (("tls", tls::CH_TLSKEY), ("tlskey", tlskey::CH_TLS)),
        (("tlskey", tlskey::CH_TPM), ("tpm", tpm::CH_TLSKEY)),
        (("tls", tls::CH_AUDIT), ("audit", audit::CH_TLS)),
        (("hs", hs::CH_RNG), ("rng", rng::CH_HS)),
        (("pq", pq::CH_RNG), ("rng", rng::CH_PQ)),
        (("ingress", ingress::CH_RNG), ("rng", rng::CH_INGRESS)),
        (("tls", tls::CH_RNG), ("rng", rng::CH_TLS)),
        (("key", key::CH_RNG), ("rng", rng::CH_KEY)),
        (("pqkey", pqkey::CH_RNG), ("rng", rng::CH_PQKEY)),
        (("tlskey", tlskey::CH_RNG), ("rng", rng::CH_TLSKEY)),
    ];
    for (a, b) in expected {
        assert!(has_channel(a, b), "{a:?} <-> {b:?}");
    }
    assert_eq!(channel_ids().len(), expected.len(), "a channel not described by layout");
}

fn irqs_of(name: &str) -> std::vec::Vec<(usize, usize)> {
    let text = system_text();
    let doc = roxmltree::Document::parse(&text).expect("parse .system");
    let pd = doc
        .descendants()
        .find(|n| n.has_tag_name("protection_domain") && n.attribute("name") == Some(name))
        .expect("pd");
    let irqs: std::vec::Vec<(usize, usize)> = pd
        .children()
        .filter(|n| n.has_tag_name("irq"))
        .map(|n| (parse_num(n.attribute("irq").expect("irq")), parse_num(n.attribute("id").expect("id"))))
        .collect();
    irqs
}

#[test]
fn irqs_match_layout() {
    assert_eq!(irqs_of("eth_out"), [(ETH_OUT_IRQ, eth_out::CH_DEVICE)]);
    assert_eq!(irqs_of("eth_in"), [(ETH_IN_IRQ, eth_in::CH_DEVICE)]);
    assert_eq!(irqs_of("timer"), [(TIMER_IRQ, timer::CH_DEVICE)]);
}

fn pd_attribute(name: &str, attribute: &str) -> Option<String> {
    let text = system_text();
    let doc = roxmltree::Document::parse(&text).expect("parse .system");
    let pd = doc
        .descendants()
        .find(|n| n.has_tag_name("protection_domain") && n.attribute("name") == Some(name))
        .expect("pd");
    pd.attribute(attribute).map(String::from)
}

#[test]
fn data_stack_size_matches_layout() {
    assert_eq!(parse_num(&pd_attribute("data", "stack_size").expect("stack_size")), DATA_STACK_SIZE);
}

#[test]
fn tls_stack_size_matches_layout() {
    assert_eq!(parse_num(&pd_attribute("tls", "stack_size").expect("stack_size")), TLS_STACK_SIZE);
}

/// What one `<map>` of `pd` says: (vaddr, perms).
fn map_of(pd: &str, mr: &str) -> Option<(usize, String)> {
    let text = system_text();
    let doc = roxmltree::Document::parse(&text).expect("parse .system");
    let pd = doc
        .descendants()
        .find(|n| n.has_tag_name("protection_domain") && n.attribute("name") == Some(pd))
        .expect("pd");
    pd.children().find(|m| m.has_tag_name("map") && m.attribute("mr") == Some(mr)).map(|m| {
        (parse_num(m.attribute("vaddr").expect("vaddr")), String::from(m.attribute("perms").expect("perms")))
    })
}

/// The M6 links (plan C1): each consumer maps the data region read-only,
/// each producer read-write, and both ends map the used and free rings.
#[test]
fn tls_links_are_mapped_by_their_two_ends_only() {
    for (link, producer, consumer) in
        [("itl", "ingress", "tls"), ("tli", "tls", "ingress"), ("tln", "tls", "inner"), ("ntl", "inner", "tls")]
    {
        assert_eq!(map_of(producer, &std::format!("{link}_data")).map(|m| m.1).as_deref(), Some("rw"), "{link}");
        assert_eq!(map_of(consumer, &std::format!("{link}_data")).map(|m| m.1).as_deref(), Some("r"), "{link}");
        for side in ["used", "free"] {
            for pd in [producer, consumer] {
                assert!(map_of(pd, &std::format!("{link}_{side}")).is_some(), "{pd} {link}_{side}");
            }
        }
        for pd in ["eth_out", "eth_in", "timer", "tpm", "key", "pqkey", "tlskey", "hs", "pq", "data", "audit"] {
            assert!(map_of(pd, &std::format!("{link}_data")).is_none(), "{pd} maps {link}_data");
        }
    }
}

/// M6 plan C1, C12: `tls` is an ordinary scheduled PD with its own budget,
/// and a caller of `tlskey` exactly as `hs` is of `key`.
#[test]
fn tls_schedule_and_tlskey_channel_match_the_plan() {
    let attr = |a| pd_attribute("tls", a).expect(a);
    assert_eq!(parse_num(&attr("priority")), 100);
    assert_eq!(pd_attribute("tls", "passive"), None);
    let text = system_text();
    let doc = roxmltree::Document::parse(&text).expect("parse .system");
    let ends = |c: roxmltree::Node| -> std::vec::Vec<(String, Option<String>, Option<String>)> {
        c.children()
            .filter(|e| e.has_tag_name("end"))
            .map(|e| (e.attribute("pd").expect("pd").into(), e.attribute("pp").map(String::from), e.attribute("notify").map(String::from)))
            .collect()
    };
    let channel = |a: &str, b: &str| {
        doc.descendants()
            .filter(|n| n.has_tag_name("channel"))
            .map(ends)
            .find(|e| e.len() == 2 && e[0].0 == a && e[1].0 == b)
            .expect("channel")
    };
    let hs = channel("hs", "key");
    let tls = channel("tls", "tlskey");
    assert_eq!((&tls[0].1, &tls[0].2, &tls[1].1), (&hs[0].1, &hs[0].2, &hs[1].1));
    let key = channel("key", "tpm");
    let tlskey = channel("tlskey", "tpm");
    assert_eq!((&tlskey[0].1, &tlskey[0].2, &tlskey[1].1, &tlskey[1].2), (&key[0].1, &key[0].2, &key[1].1, &key[1].2));
}

/// M6 plan C12: `tlskey` is passive (every sign runs on `tls`'s scheduling
/// context), between `tls` and `tpm` in priority, with `key`'s stack, and
/// maps its own secrets region alone.
#[test]
fn tlskey_is_a_passive_key_pd_on_the_planned_schedule() {
    let attr = |a| pd_attribute("tlskey", a).expect(a);
    assert_eq!(attr("passive"), "true");
    assert_eq!(parse_num(&attr("priority")), 135);
    assert!(parse_num(&pd_attribute("tls", "priority").expect("tls")) < 135);
    assert!(parse_num(&pd_attribute("tpm", "priority").expect("tpm")) > 135);
    assert_eq!((parse_num(&attr("budget")), parse_num(&attr("period"))), (2000, 10_000));
    assert_eq!(parse_num(&attr("stack_size")), parse_num(&pd_attribute("key", "stack_size").expect("key")));
    assert_eq!(map_of("tlskey", "tls_secrets").map(|m| m.1).as_deref(), Some("r"));
    for pd in ["key", "pqkey", "tls", "tpm", "hs"] {
        assert!(map_of(pd, "tls_secrets").is_none(), "{pd} maps tls_secrets");
    }
}
