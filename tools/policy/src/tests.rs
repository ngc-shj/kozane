#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Unit tests for the pieces `tests/tools/test_policy.py` cannot reach as
//! cheaply from outside the binary: the wire-header round trip, the diff's
//! totality, the canonical record codec, roster integrity and the
//! approval/restore signature domains. The full C2 acceptance fixture list
//! (M8 plan) is end to end in `tests/tools/test_policy.py`, against the
//! built binary.

use policy_wire::render::{PlainBundle, PlainGroup, PlainPeer};
use policy_wire::{Prefix, Rule};

use crate::approval::{self, ApprovalFields, RestoreFields};
use crate::record;
use crate::roster::{Approver, Roster};
use crate::sig;
use crate::wire_header;

fn spk() -> Vec<u8> {
    vec![0xAB; limits::SPK_LEN]
}

fn sample_bundle(version: u32, min_release: u32, prev: [u8; 32], roster: [u8; 32]) -> Vec<u8> {
    let rp = spk();
    let rp: &[u8; limits::SPK_LEN] = rp.as_slice().try_into().unwrap();
    let peer = PlainPeer { wg_pub: [7; 32], rp_pub: rp, groups: 1, allowed: &[Prefix { addr: [10, 1, 0, 0], len: 24 }] };
    let peers = [peer];
    let rule = Rule { dst: Prefix { addr: [10, 2, 0, 0], len: 24 }, proto: policy_wire::PROTO_TCP, port_lo: 1, port_hi: 2 };
    let rules = [rule];
    let groups = [PlainGroup { rules: &rules }];
    let plain = PlainBundle {
        fleet_id: [9; 16],
        version,
        min_release,
        prev_sha256: prev,
        roster_sha256: roster,
        peers: &peers,
        groups: &groups,
        sig_ed25519: [0; 64],
        sig_mldsa65: [0; 3309],
    };
    policy_wire::render::render(&plain)
}

// --- wire_header ----------------------------------------------------------

#[test]
fn header_round_trips_through_render() {
    let slot = sample_bundle(5, 3, [1; 32], [2; 32]);
    let h = wire_header::read(&slot).unwrap();
    assert_eq!(h.version, 5);
    assert_eq!(h.min_release, 3);
    assert_eq!(h.prev_sha256, [1; 32]);
    assert_eq!(h.roster_sha256, [2; 32]);
    assert_eq!(h.fleet_id, [9; 16]);
    assert_eq!(h.peer_count, 1);
    assert_eq!(h.group_count, 1);
}

#[test]
fn header_rejects_wrong_length() {
    assert!(wire_header::read(&[0u8; 10]).is_err());
}

#[test]
fn header_rejects_bad_magic() {
    let mut slot = sample_bundle(0, 0, [0; 32], [0; 32]);
    slot[0] = b'X';
    assert!(wire_header::read(&slot).is_err());
}

// --- diff -------------------------------------------------------------

#[test]
fn diff_is_total_and_sensitive_to_every_field() {
    let base = sample_bundle(1, 0, [0; 32], [0; 32]);
    let base_header = wire_header::read(&base).unwrap();
    let base_body = policy_wire::split(&base).unwrap().body().to_vec();
    let base_diff = crate::diff::render(None, &base_header, &base_body).unwrap();

    // version
    let v = sample_bundle(2, 0, [0; 32], [0; 32]);
    assert_ne!(crate::diff::render(None, &wire_header::read(&v).unwrap(), policy_wire::split(&v).unwrap().body()).unwrap(), base_diff);
    // min_release
    let m = sample_bundle(1, 9, [0; 32], [0; 32]);
    assert_ne!(crate::diff::render(None, &wire_header::read(&m).unwrap(), policy_wire::split(&m).unwrap().body()).unwrap(), base_diff);
    // prev_sha256
    let p = sample_bundle(1, 0, [7; 32], [0; 32]);
    assert_ne!(crate::diff::render(None, &wire_header::read(&p).unwrap(), policy_wire::split(&p).unwrap().body()).unwrap(), base_diff);
    // roster_sha256
    let r = sample_bundle(1, 0, [0; 32], [7; 32]);
    assert_ne!(crate::diff::render(None, &wire_header::read(&r).unwrap(), policy_wire::split(&r).unwrap().body()).unwrap(), base_diff);

    // same inputs twice give the same diff (it is a pure function)
    assert_eq!(crate::diff::render(None, &base_header, &base_body).unwrap(), base_diff);
}

#[test]
fn diff_changes_when_a_rule_changes() {
    let rp = spk();
    let rp: &[u8; limits::SPK_LEN] = rp.as_slice().try_into().unwrap();
    let peer = PlainPeer { wg_pub: [7; 32], rp_pub: rp, groups: 1, allowed: &[Prefix { addr: [10, 1, 0, 0], len: 24 }] };
    let peers = [peer];
    let rule_a = [Rule { dst: Prefix { addr: [10, 2, 0, 0], len: 24 }, proto: policy_wire::PROTO_TCP, port_lo: 1, port_hi: 2 }];
    let rule_b = [Rule { dst: Prefix { addr: [10, 2, 0, 0], len: 24 }, proto: policy_wire::PROTO_TCP, port_lo: 1, port_hi: 3 }];
    let render_with = |rules: &[Rule]| {
        let groups = [PlainGroup { rules }];
        policy_wire::render::render(&PlainBundle {
            fleet_id: [9; 16],
            version: 1,
            min_release: 0,
            prev_sha256: [0; 32],
            roster_sha256: [0; 32],
            peers: &peers,
            groups: &groups,
            sig_ed25519: [0; 64],
            sig_mldsa65: [0; 3309],
        })
    };
    let a = render_with(&rule_a);
    let b = render_with(&rule_b);
    let da = crate::diff::render(None, &wire_header::read(&a).unwrap(), policy_wire::split(&a).unwrap().body()).unwrap();
    let db = crate::diff::render(None, &wire_header::read(&b).unwrap(), policy_wire::split(&b).unwrap().body()).unwrap();
    assert_ne!(da, db, "a single rule byte changed but the diff did not");
}

/// One peer and one rule, the knobs S8's diff must show an approver.
fn bundle_with(rp_byte: u8, port_hi: u16) -> Vec<u8> {
    let rp = vec![rp_byte; limits::SPK_LEN];
    let rp: &[u8; limits::SPK_LEN] = rp.as_slice().try_into().unwrap();
    let peers = [PlainPeer { wg_pub: [7; 32], rp_pub: rp, groups: 1, allowed: &[Prefix { addr: [10, 1, 0, 0], len: 24 }] }];
    let rules = [Rule { dst: Prefix { addr: [10, 2, 0, 0], len: 24 }, proto: policy_wire::PROTO_TCP, port_lo: 443, port_hi }];
    let groups = [PlainGroup { rules: &rules }];
    policy_wire::render::render(&PlainBundle {
        fleet_id: [9; 16],
        version: 1,
        min_release: 0,
        prev_sha256: [0; 32],
        roster_sha256: [0; 32],
        peers: &peers,
        groups: &groups,
        sig_ed25519: [0; 64],
        sig_mldsa65: [0; 3309],
    })
}

/// The diff of `new` against `old`, without its `body_sha256` line: what
/// the item lines alone tell an approver.
fn items_diff(old: &[u8], new: &[u8]) -> String {
    let old_header = wire_header::read(old).unwrap();
    let text = crate::diff::render(
        Some((&old_header, policy_wire::split(old).unwrap().body())),
        &wire_header::read(new).unwrap(),
        policy_wire::split(new).unwrap().body(),
    )
    .unwrap();
    text.lines().filter(|l| !l.starts_with("body_sha256:")).map(|l| format!("{l}\n")).collect()
}

#[test]
fn diff_shows_a_swapped_rp_key_as_its_peer_line() {
    let old = bundle_with(0xAB, 443);
    let d = items_diff(&old, &bundle_with(0xCD, 443));
    let removed = d.lines().filter(|l| l.starts_with("- peer BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=")).count();
    let added = d.lines().filter(|l| l.starts_with("+ peer BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=")).count();
    assert_eq!((removed, added), (1, 1), "{d}");
    assert!(d.contains(" allowed=10.1.0.0/24"), "{d}");
}

#[test]
fn diff_shows_a_widened_rule_as_its_rule_lines() {
    let old = bundle_with(0xAB, 443);
    let d = items_diff(&old, &bundle_with(0xAB, 65535));
    assert!(d.contains("- rule group=0 10.2.0.0/24 tcp 443-443\n"), "{d}");
    assert!(d.contains("+ rule group=0 10.2.0.0/24 tcp 443-65535\n"), "{d}");
}

/// The diff text byte for byte (diff.rs: approvals bind it, so a format
/// change breaks every existing ledger).
#[test]
fn diff_text_is_pinned() {
    let old = bundle_with(0xAB, 443);
    let new = bundle_with(0xCD, 65535);
    let text = crate::diff::render(
        Some((&wire_header::read(&old).unwrap(), policy_wire::split(&old).unwrap().body())),
        &wire_header::read(&new).unwrap(),
        policy_wire::split(&new).unwrap().body(),
    )
    .unwrap();
    assert_eq!(text, GOLDEN_DIFF);
}

const GOLDEN_DIFF: &str = concat!(
    "fleet_id: 09090909090909090909090909090909 -> 09090909090909090909090909090909\n",
    "version: 1 -> 1\n",
    "min_release: 0 -> 0\n",
    "prev_sha256: 0000000000000000000000000000000000000000000000000000000000000000 -> 0000000000000000000000000000000000000000000000000000000000000000\n",
    "roster_sha256: 0000000000000000000000000000000000000000000000000000000000000000 -> 0000000000000000000000000000000000000000000000000000000000000000\n",
    "peer_count: 1 -> 1\n",
    "group_count: 1 -> 1\n",
    "- peer BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc= rp=d43e5319f6a607b66d21ace48af21821ac176ca19a4e26c94b4d7dff51e56a53 groups=0 allowed=10.1.0.0/24\n",
    "+ peer BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc= rp=27b15da9990dadfddbe3b62b314d9e63204ec4cc30e870a1557be78b77c0056d groups=0 allowed=10.1.0.0/24\n",
    "- rule group=0 10.2.0.0/24 tcp 443-443\n",
    "+ rule group=0 10.2.0.0/24 tcp 443-65535\n",
    "body_sha256: 3f1193844b865d0c356c215390fb3dd095dab952a82251a20cd3cff31b1a8ba5 -> 93bedf4819dbabe298170984a6f82d895212ef8c2c0d080849510cd3cf0f38c3\n",
);

#[test]
fn diff_of_an_unchanged_body_marks_every_item_unchanged() {
    let old = bundle_with(0xAB, 443);
    let d = items_diff(&old, &old);
    assert!(d.lines().filter(|l| l.starts_with("  ")).count() == 2 && !d.lines().any(|l| l.starts_with(['+', '-'])), "{d}");
}

// --- restore approvals are fresh (S6-1) -------------------------------------

#[test]
fn restore_approval_freshness_boundaries() {
    let now = 1_000_000;
    let max = approval::RESTORE_APPROVAL_MAX_AGE_S;
    let skew = approval::RESTORE_APPROVAL_SKEW_S;
    assert!(approval::restore_approval_fresh(now - max, now).is_ok());
    assert!(approval::restore_approval_fresh(now - max - 1, now).is_err());
    assert!(approval::restore_approval_fresh(now + skew, now).is_ok());
    assert!(approval::restore_approval_fresh(now + skew + 1, now).is_err());
}

/// Two approvals of this head and fleet, signed at `ts`, as files.
fn restore_approvals_at(dir: &std::path::Path, ts: u64) -> (Roster, Vec<String>) {
    let mut rng = counter_rng();
    let mut approvers = Vec::new();
    let mut paths = Vec::new();
    for id in ["alice", "bob"] {
        let (sk, pk) = sig::approver_keygen(&mut rng).unwrap();
        approvers.push(Approver { id: id.into(), ed25519_pub: pk });
        let fields = RestoreFields { approver_id: id.into(), fleet_id: [3; 16], head_body_sha256: [4; 32], head_version: 7, ts };
        let path = dir.join(format!("{id}-{ts}.approval"));
        std::fs::write(&path, approval::sign_restore(&sk, &fields, &mut rng).unwrap()).unwrap();
        paths.push(path.to_string_lossy().into_owned());
    }
    (Roster { approvers }, paths)
}

#[test]
fn restore_refuses_approvals_older_than_a_day() {
    let dir = std::env::temp_dir().join(format!("policy-restore-age-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let now = 2_000_000;
    let (roster, fresh) = restore_approvals_at(&dir, now - 60);
    let (old_roster, stale) = restore_approvals_at(&dir, now - approval::RESTORE_APPROVAL_MAX_AGE_S - 1);
    let fresh_ok = crate::check_restore_approvals(&fresh, &roster, 7, &[4; 32], &[3; 16], now);
    let stale_err = crate::check_restore_approvals(&stale, &old_roster, 7, &[4; 32], &[3; 16], now);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(fresh_ok.map(|v| v.len()), Ok(2));
    assert!(stale_err.is_err_and(|e| e.contains("ago: approvals are for one recovery")));
}

// --- record ---------------------------------------------------------------

#[test]
fn record_round_trips() {
    let bytes = record::render(&[("b", "2"), ("a", "1")], &["a", "b"]);
    assert_eq!(bytes, b"a=1\nb=2\n");
    let parsed = record::parse(&bytes, &["a", "b"]).unwrap();
    assert_eq!(record::get(&parsed, "a"), Some("1"));
    assert_eq!(record::get(&parsed, "b"), Some("2"));
}

#[test]
fn record_rejects_unsorted() {
    assert!(record::parse(b"b=2\na=1\n", &["a", "b"]).is_err());
}

#[test]
fn record_rejects_missing_key() {
    assert!(record::parse(b"a=1\n", &["a", "b"]).is_err());
}

#[test]
fn record_rejects_duplicate_key() {
    assert!(record::parse(b"a=1\na=2\n", &["a"]).is_err());
}

#[test]
fn record_rejects_unknown_key() {
    assert!(record::parse(b"a=1\nz=2\n", &["a"]).is_err());
}

#[test]
fn record_rejects_no_final_newline() {
    assert!(record::parse(b"a=1", &["a"]).is_err());
}

// --- roster -----------------------------------------------------------

fn approver(id: &str, byte: u8) -> Approver {
    Approver { id: id.to_string(), ed25519_pub: [byte; 32] }
}

#[test]
fn roster_digest_is_order_independent_and_sensitive_to_membership() {
    let r1 = Roster { approvers: vec![approver("alice", 1), approver("bob", 2)] };
    let r2 = Roster { approvers: vec![approver("bob", 2), approver("alice", 1)] };
    assert_eq!(r1.digest(), r2.digest(), "digest must not depend on input order (canonical sort)");
    let r3 = Roster { approvers: vec![approver("alice", 1), approver("carol", 3)] };
    assert_ne!(r1.digest(), r3.digest());
}

#[test]
fn roster_rejects_duplicate_id() {
    let text = "[[approver]]\nid = \"alice\"\ned25519_pub = \"00\"\n";
    // bad hex length is also caught, but duplicate id is checked first in a
    // well-formed roster:
    let good = format!("[[approver]]\nid = \"alice\"\ned25519_pub = \"{}\"\n[[approver]]\nid = \"alice\"\ned25519_pub = \"{}\"\n", sig::hex(&[1; 32]), sig::hex(&[2; 32]));
    assert!(Roster::parse(&good).is_err());
    let _ = text;
}

#[test]
fn roster_rejects_one_key_under_two_ids() {
    let key = sig::hex(&[9; 32]);
    let text = format!("[[approver]]\nid = \"alice\"\ned25519_pub = \"{key}\"\n[[approver]]\nid = \"bob\"\ned25519_pub = \"{key}\"\n");
    let err = Roster::parse(&text).unwrap_err();
    assert!(err.contains("reuses another approver's key"), "{err}");
}

#[test]
fn roster_round_trips_through_render() {
    let r = Roster { approvers: vec![approver("alice", 1), approver("bob", 2)] };
    let text = r.render();
    let back = Roster::parse(&text).unwrap();
    assert_eq!(r.digest(), back.digest());
}

// --- approval / restore signatures --------------------------------------

fn counter_rng() -> impl FnMut(&mut [u8]) -> bool {
    let mut n = 1u8;
    move |buf: &mut [u8]| {
        for b in buf.iter_mut() {
            *b = n;
            n = n.wrapping_add(7);
        }
        true
    }
}

#[test]
fn an_approval_verifies_under_its_own_roster_entry() {
    let mut rng = counter_rng();
    let (sk, pk) = sig::approver_keygen(&mut rng).unwrap();
    let roster = Roster { approvers: vec![Approver { id: "alice".into(), ed25519_pub: pk }] };
    let fields = ApprovalFields {
        approver_id: "alice".into(),
        body_sha256: [1; 32],
        diff_sha256: [2; 32],
        fleet_id: [3; 16],
        prev_sha256: [4; 32],
        roster_sha256: [5; 32],
        ts: 123,
        version: 7,
    };
    let record = approval::sign(&sk, &fields, &mut rng).unwrap();
    let got = approval::parse_and_verify(&record, &roster).unwrap();
    assert_eq!(got, fields);
}

#[test]
fn a_forged_approval_signature_is_refused() {
    let mut rng = counter_rng();
    let (sk, pk) = sig::approver_keygen(&mut rng).unwrap();
    let roster = Roster { approvers: vec![Approver { id: "alice".into(), ed25519_pub: pk }] };
    let fields = ApprovalFields {
        approver_id: "alice".into(),
        body_sha256: [1; 32],
        diff_sha256: [2; 32],
        fleet_id: [3; 16],
        prev_sha256: [4; 32],
        roster_sha256: [5; 32],
        ts: 123,
        version: 7,
    };
    let mut record = approval::sign(&sk, &fields, &mut rng).unwrap();
    let at = record.len() - 5;
    record[at] ^= 1;
    assert!(approval::parse_and_verify(&record, &roster).is_err());
}

#[test]
fn an_approver_not_in_the_roster_is_refused() {
    let mut rng = counter_rng();
    let (sk, _pk) = sig::approver_keygen(&mut rng).unwrap();
    let roster = Roster { approvers: vec![Approver { id: "bob".into(), ed25519_pub: [9; 32] }] };
    let fields = ApprovalFields {
        approver_id: "alice".into(),
        body_sha256: [1; 32],
        diff_sha256: [2; 32],
        fleet_id: [3; 16],
        prev_sha256: [4; 32],
        roster_sha256: [5; 32],
        ts: 123,
        version: 7,
    };
    let record = approval::sign(&sk, &fields, &mut rng).unwrap();
    let err = approval::parse_and_verify(&record, &roster).unwrap_err();
    assert!(err.contains("is not in the roster"), "{err}");
}

/// An approval record signed under the restore domain must not verify as
/// a bundle approval, even with identical field *names*: each role has
/// its own domain and its own required key set (M8 plan D11).
#[test]
fn an_approval_record_is_not_a_restore_record_and_vice_versa() {
    let mut rng = counter_rng();
    let (sk, pk) = sig::approver_keygen(&mut rng).unwrap();
    let roster = Roster { approvers: vec![Approver { id: "alice".into(), ed25519_pub: pk }] };
    let restore_fields = RestoreFields { approver_id: "alice".into(), fleet_id: [3; 16], head_body_sha256: [4; 32], head_version: 7, ts: 1 };
    let record = approval::sign_restore(&sk, &restore_fields, &mut rng).unwrap();
    // Not parseable as a bundle approval: the required key set differs.
    assert!(approval::parse_and_verify(&record, &roster).is_err());
}

#[test]
fn a_restore_approval_verifies_and_a_forged_one_does_not() {
    let mut rng = counter_rng();
    let (sk, pk) = sig::approver_keygen(&mut rng).unwrap();
    let roster = Roster { approvers: vec![Approver { id: "alice".into(), ed25519_pub: pk }] };
    let fields = RestoreFields { approver_id: "alice".into(), fleet_id: [3; 16], head_body_sha256: [4; 32], head_version: 7, ts: 1 };
    let record = approval::sign_restore(&sk, &fields, &mut rng).unwrap();
    assert_eq!(approval::parse_and_verify_restore(&record, &roster).unwrap(), fields);

    let mut forged = record.clone();
    let at = forged.len() - 5;
    forged[at] ^= 1;
    assert!(approval::parse_and_verify_restore(&forged, &roster).is_err());
}

// --- bundle signing (D1) ------------------------------------------------

#[test]
fn a_bundle_signature_needs_both_halves() {
    let mut rng = counter_rng();
    let (sk, pk) = sig::bundle_keygen(&mut rng).unwrap();
    let body = b"the body of a draft bundle";
    let (ed, ml) = sig::bundle_sign(&sk, policy_wire::DOMAIN, body, &mut rng).unwrap();
    assert_eq!(sig::bundle_verify(&pk, policy_wire::DOMAIN, body, &ed, &ml), Ok(()));

    let mut bad_ed = ed;
    bad_ed[0] ^= 1;
    assert_eq!(sig::bundle_verify(&pk, policy_wire::DOMAIN, body, &bad_ed, &ml), Err(sig::SigError::Ed25519Invalid));

    let mut bad_ml = ml;
    bad_ml[0] ^= 1;
    assert_eq!(sig::bundle_verify(&pk, policy_wire::DOMAIN, body, &ed, &bad_ml), Err(sig::SigError::MlDsaInvalid));
}

#[test]
fn a_bundle_signature_is_bound_to_its_domain() {
    let mut rng = counter_rng();
    let (sk, pk) = sig::bundle_keygen(&mut rng).unwrap();
    let body = b"the body";
    let (ed, ml) = sig::bundle_sign(&sk, b"some-other-domain\0", body, &mut rng).unwrap();
    assert!(sig::bundle_verify(&pk, policy_wire::DOMAIN, body, &ed, &ml).is_err());
}

// --- fleet node digest ----------------------------------------------------

#[test]
fn a_fleet_node_digest_is_sensitive_to_every_field() {
    let base = crate::fleet::Node {
        name: "gw1".into(),
        fleet_id: [1; 16],
        inside_prefix: Prefix { addr: [10, 0, 0, 0], len: 24 },
        inside_ip: [10, 0, 0, 1],
        outside_ip: [192, 0, 2, 1],
        neighbors: vec![[10, 0, 0, 2]],
        gateway_wg_public: [2; 32],
        gateway_rp_digest: [3; 32],
    };
    let base_digest = crate::fleet::node_digest(&base);

    let mut changed = base.clone();
    changed.outside_ip = [192, 0, 2, 9];
    assert_ne!(crate::fleet::node_digest(&changed), base_digest);

    let mut changed = base.clone();
    changed.neighbors.push([10, 0, 0, 3]);
    assert_ne!(crate::fleet::node_digest(&changed), base_digest);

    let mut changed = base;
    changed.gateway_rp_digest = [4; 32];
    assert_ne!(crate::fleet::node_digest(&changed), base_digest);
}

fn node(name: &str, outside_ip: [u8; 4]) -> crate::fleet::Node {
    crate::fleet::Node {
        name: name.into(),
        fleet_id: [9; 16],
        inside_prefix: Prefix { addr: [10, 99, 0, 0], len: 24 },
        inside_ip: [10, 99, 0, 1],
        outside_ip,
        neighbors: vec![[10, 99, 0, 2]],
        gateway_wg_public: [1; 32],
        gateway_rp_digest: [2; 32],
    }
}

/// `verify --package-node` (M8 plan C2): a package's node digest names the
/// fleet node it equals, and a node differing in any field names none.
#[test]
fn a_package_node_digest_matches_only_its_own_fleet_node() {
    use crate::fleet::{Fleet, node_digest, node_for_digest};
    let fleet = Fleet { fleet_id: [9; 16], nodes: vec![node("gw1", [10, 0, 2, 15]), node("gw2", [10, 0, 3, 15])] };
    assert_eq!(node_for_digest(&fleet, &node_digest(&node("pkg", [10, 0, 3, 15]))), Some("gw2"));
    assert_eq!(node_for_digest(&fleet, &node_digest(&node("pkg", [10, 0, 4, 15]))), None);
    let mut other_fleet = node("pkg", [10, 0, 2, 15]);
    other_fleet.fleet_id = [8; 16];
    assert_eq!(node_for_digest(&fleet, &node_digest(&other_fleet)), None);
}

/// The roster digest's lengths are four big-endian bytes: an id of 256
/// bytes is prefixed `00 00 01 00`, where a one-byte length would have
/// written `00` and let another roster share the encoding.
#[test]
fn roster_digest_lengths_are_not_truncated() {
    use sha2::{Digest, Sha256};
    let key = [7u8; 32];
    let id = "x".repeat(256);
    let roster = Roster { approvers: vec![Approver { id: id.clone(), ed25519_pub: key }] };
    let mut h = Sha256::new();
    h.update(b"kozane-policy-roster-v1\0");
    h.update([0, 0, 0, 1]);
    h.update([0, 0, 1, 0]);
    h.update(id.as_bytes());
    h.update(key);
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(roster.digest(), expected);
}
