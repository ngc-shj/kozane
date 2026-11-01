//! `diff` (M8 plan C2, S8): a canonical, total text rendering of the
//! ledger head (or "none" at genesis) against a draft, approvers read
//! before approving. `diff_sha256` is what approval records bind, so it
//! must be a total function of the draft's body and change whenever any
//! single field of that body does.
//!
//! What an approver judges is shown item by item: the header fields, then
//! one line per peer (its `wg_pub` in base64 as `peers.toml` has it, the
//! BLAKE2s digest of its rp public key as `policy rp-digest` prints it,
//! its group indices and allowed IPs) and one line per group rule, each
//! marked `+` (added), `-` (removed) or ` ` (unchanged); a changed peer is
//! its old line removed and its new one added. The items come from
//! `policy_wire::contents`, the device's own structural walk, not a second
//! parser. The last line compares `body_sha256`, so a change no item line
//! shows still changes the diff.

use sha2::{Digest, Sha256};

use crate::wire_header::Header;

use std::collections::{BTreeMap, BTreeSet};

use policy_wire::{PROTO_ICMP, PROTO_TCP, PROTO_UDP, Prefix};

use crate::sig::hex;

fn field(name: &str, old: Option<String>, new: String) -> String {
    format!("{name}: {} -> {new}\n", old.unwrap_or_else(|| "none".to_string()))
}

/// Standard base64 with padding, the form `peers.toml` and `gateway.toml`
/// spell WireGuard keys in.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [0, 1, 2].map(|i| chunk.get(i).copied().unwrap_or(0));
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET.get(((n >> (18 - 6 * i)) & 63) as usize).map_or('=', |&c| char::from(c)));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn prefix(p: &Prefix) -> String {
    let [a, b, c, d] = p.addr;
    format!("{a}.{b}.{c}.{d}/{}", p.len)
}

fn proto(p: u8) -> String {
    match p {
        PROTO_TCP => "tcp".into(),
        PROTO_UDP => "udp".into(),
        PROTO_ICMP => "icmp".into(),
        other => format!("proto{other}"),
    }
}

/// A body's peers (keyed by raw `wg_pub`) and rules, one line each.
struct Items {
    peers: BTreeMap<[u8; 32], String>,
    rules: BTreeSet<String>,
}

fn items(body: &[u8]) -> Result<Items, String> {
    // The body is the slot up to its signatures; zero signatures and a zero
    // tail make it a slot again for the walk, which checks neither.
    let mut slot = body.to_vec();
    slot.resize(limits::BUNDLE_MAX, 0);
    let c = policy_wire::contents(&slot).map_err(|e| format!("diff: the body does not decode: {e:?}"))?;
    let mut peers = BTreeMap::new();
    for i in 0..c.peer_count() {
        let p = c.peer(i).ok_or("diff: internal: a walked peer is missing")?;
        let groups: Vec<String> = (0..8u8).filter(|&g| p.in_group(g)).map(|g| g.to_string()).collect();
        let allowed: Vec<String> = p.allowed().map(|a| prefix(&a)).collect();
        let line = format!(
            "peer {} rp={} groups={} allowed={}",
            base64(p.wg_pub()),
            hex(&crate::rp_digest(p.rp_pub())),
            if groups.is_empty() { "-".to_string() } else { groups.join(",") },
            allowed.join(",")
        );
        peers.insert(*p.wg_pub(), line);
    }
    let mut rules = BTreeSet::new();
    for g in 0..c.group_count() {
        let group = c.group(g).ok_or("diff: internal: a walked group is missing")?;
        let mut any = false;
        for r in group.rules() {
            any = true;
            rules.insert(format!("rule group={g} {} {} {}-{}", prefix(&r.dst), proto(r.proto), r.port_lo, r.port_hi));
        }
        if !any {
            rules.insert(format!("rule group={g} none"));
        }
    }
    Ok(Items { peers, rules })
}

fn changes<K: Ord + Clone>(old: &BTreeMap<K, String>, new: &BTreeMap<K, String>, out: &mut String) {
    let keys: BTreeSet<&K> = old.keys().chain(new.keys()).collect();
    for k in keys {
        match (old.get(k), new.get(k)) {
            (Some(a), Some(b)) if a == b => *out += &format!("  {b}\n"),
            (a, b) => {
                if let Some(a) = a {
                    *out += &format!("- {a}\n");
                }
                if let Some(b) = b {
                    *out += &format!("+ {b}\n");
                }
            }
        }
    }
}

/// `old` is `None` at genesis (an empty ledger). `new_header`/`new_body`
/// describe the draft. Refuses a body the walk refuses.
pub fn render(old: Option<(&Header, &[u8])>, new_header: &Header, new_body: &[u8]) -> Result<String, String> {
    let old_body_sha256 = old.map(|(_, b)| hex(&Sha256::digest(b)));
    let new_body_sha256 = hex(&Sha256::digest(new_body));
    let mut out = String::new();
    out += &field("fleet_id", old.map(|(h, _)| hex(&h.fleet_id)), hex(&new_header.fleet_id));
    out += &field("version", old.map(|(h, _)| h.version.to_string()), new_header.version.to_string());
    out += &field("min_release", old.map(|(h, _)| h.min_release.to_string()), new_header.min_release.to_string());
    out += &field("prev_sha256", old.map(|(h, _)| hex(&h.prev_sha256)), hex(&new_header.prev_sha256));
    out += &field("roster_sha256", old.map(|(h, _)| hex(&h.roster_sha256)), hex(&new_header.roster_sha256));
    out += &field("peer_count", old.map(|(h, _)| h.peer_count.to_string()), new_header.peer_count.to_string());
    out += &field("group_count", old.map(|(h, _)| h.group_count.to_string()), new_header.group_count.to_string());
    let old_items = old.map(|(_, b)| items(b)).transpose()?;
    let new_items = items(new_body)?;
    let empty = Items { peers: BTreeMap::new(), rules: BTreeSet::new() };
    let old_items = old_items.as_ref().unwrap_or(&empty);
    changes(&old_items.peers, &new_items.peers, &mut out);
    let as_map = |set: &BTreeSet<String>| set.iter().map(|l| (l.clone(), l.clone())).collect::<BTreeMap<String, String>>();
    changes(&as_map(&old_items.rules), &as_map(&new_items.rules), &mut out);
    out += &field("body_sha256", old_body_sha256, new_body_sha256);
    Ok(out)
}

pub fn sha256(diff_text: &str) -> [u8; 32] {
    Sha256::digest(diff_text.as_bytes()).into()
}
