//! `diff` (M8 plan C2): a canonical, total text rendering of the ledger
//! head (or "none" at genesis) against a draft, approvers read before
//! approving. `diff_sha256` is what approval records bind, so it must be a
//! total function of the draft's body and change whenever any single
//! field of that body does.
//!
//! Rather than decode the draft's peers and groups (which needs a
//! `NodeConfig` `policy_wire::parse` has no single one to validate
//! against, with no fleet file in `diff`'s own inputs), every field after
//! the header few is covered by one line comparing `body_sha256` — the
//! sha256 of `policy_wire::split`'s `body`, i.e. the whole signed message
//! minus the domain prefix. Any change anywhere in the body (a peer, an
//! allowed IP, a rule, a count) changes that line, which is what the
//! property test in `tests.rs` exercises; the header fields are shown
//! individually only for a human reader.

use sha2::{Digest, Sha256};

use crate::wire_header::Header;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn field(name: &str, old: Option<String>, new: String) -> String {
    format!("{name}: {} -> {new}\n", old.unwrap_or_else(|| "none".to_string()))
}

/// `old` is `None` at genesis (an empty ledger). `new_header`/`new_body`
/// describe the draft.
pub fn render(old: Option<(&Header, &[u8])>, new_header: &Header, new_body: &[u8]) -> String {
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
    out += &field("body_sha256", old_body_sha256, new_body_sha256);
    out
}

pub fn sha256(diff_text: &str) -> [u8; 32] {
    Sha256::digest(diff_text.as_bytes()).into()
}
