//! The peer-policy bundle format, parser and selector (M8 plan C1, D10):
//! peers, their keys, allowed IPs, group memberships and group rules,
//! signed by the fleet's two-person-approved tooling and loaded at boot
//! from A/B slots. Free of cryptography and of `limits`-only dependencies,
//! so Kani checks it without pulling in libcrux: the `policy` PD verifies
//! [`DOMAIN`] ‖ [`split`]'s `body` with the two signatures itself and then
//! calls [`parse`]; every other PD calls [`open`] with the [`Verified`]
//! witness `policy` hands it, never re-verifying or re-hashing the slot
//! (no PD maps a slot writable, M8 plan C11).
//!
//! Layout (big-endian integers), exactly `limits::BUNDLE_MAX` bytes:
//! `magic "KZPP" ‖ format u16 ‖ fleet_id [16] ‖ version u32 ‖ min_release
//! u32 ‖ prev_sha256 [32] ‖ roster_sha256 [32] ‖ peer_count (1..=MAX_PEERS)
//! ‖ group_count (0..=MAX_GROUPS) ‖ peers ‖ groups ‖ sig_ed25519 [64] ‖
//! sig_mldsa65 [3309] ‖ zero tail`. A peer is `wg_pub [32] ‖ rp_pub
//! [SPK_LEN] ‖ groups u8 ‖ allowed_count (1..=MAX_ALLOWED) ‖ prefixes`; a
//! group is `rule_count (1..=MAX_RULES) ‖ rules`; a rule is `dst prefix (5)
//! ‖ proto u8 ‖ port_lo u16 ‖ port_hi u16`. Canonical: peers strictly
//! ascending by raw `wg_pub`, rules within a group strictly ascending by
//! their encoded bytes, exact length from the counts, every tail byte
//! zero. Anything else is [`Reject::Malformed`].
//!
//! [`Bundle`] has no public fields and no public constructor besides
//! [`parse`] and [`open`]; [`Verified`] has none besides [`Verified::from_reply`]:
//!
//! ```compile_fail
//! let _ = policy_wire::Bundle { slot: &[] };
//! ```
//!
//! ```compile_fail
//! let _ = policy_wire::Verified { version: 0 };
//! ```
//!
//! Without the `verifier` feature a consumer reaches a `Bundle` only through
//! `open` and a `Verified` token; `parse` does not exist for it:
//!
//! ```compile_fail
//! # let node: policy_wire::NodeConfig = todo!();
//! let _ = policy_wire::parse(&[], &node, &|_| [0; 32]);
//! ```
//!
//! ```no_run
//! # let node: policy_wire::NodeConfig = todo!();
//! # let token = policy_wire::Verified::from_reply(&[0; 37]).unwrap();
//! let _ = policy_wire::open(&token, &[], &node, &|_| [0; 32]);
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::arithmetic_side_effects)]

#[cfg(any(test, feature = "render"))]
extern crate alloc;

use limits::{BUNDLE_MAX, MAX_ALLOWED, MAX_GROUPS, MAX_PEERS, MAX_RULES, SPK_LEN};

/// The verifier signs `DOMAIN ‖ body` (`body` from [`split`]).
pub const DOMAIN: &[u8] = b"kozane-peer-policy-v1\0";

const MAGIC: &[u8; 4] = b"KZPP";
const FORMAT_VERSION: u16 = 1;
/// ICMP as `Rule::proto` (echo only: both ports must be 0).
pub const PROTO_ICMP: u8 = 1;
/// TCP as `Rule::proto`.
pub const PROTO_TCP: u8 = 6;
/// UDP as `Rule::proto`.
pub const PROTO_UDP: u8 = 17;
const PREFIX_LEN: usize = 5;
const RULE_LEN: usize = PREFIX_LEN + 1 + 2 + 2;
const SIG_ED25519_LEN: usize = 64;
const SIG_MLDSA65_LEN: usize = 3309;
/// `magic ‖ format ‖ fleet_id ‖ version ‖ min_release ‖ prev_sha256 ‖
/// roster_sha256 ‖ peer_count ‖ group_count`.
const HEADER_LEN: usize = 4 + 2 + 16 + 4 + 4 + 32 + 32 + 1 + 1;
const FLEET_ID_AT: usize = 6;
const VERSION_AT: usize = 22;
const MIN_RELEASE_AT: usize = 26;
const PREV_SHA256_AT: usize = 30;
const ROSTER_SHA256_AT: usize = 62;
const PEER_COUNT_AT: usize = 94;
const GROUP_COUNT_AT: usize = 95;

/// An IPv4 prefix. `config` reuses this type for its own build-time checks
/// (M8 plan C1 R2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    pub addr: [u8; 4],
    pub len: u8,
}

impl Prefix {
    const fn mask(len: u8) -> u32 {
        let shift = 32u32.saturating_sub(len as u32);
        if shift >= 32 { 0 } else { u32::MAX << shift }
    }

    fn range(&self) -> (u32, u32) {
        let mask = Self::mask(self.len);
        let lo = u32::from_be_bytes(self.addr) & mask;
        (lo, lo | !mask)
    }

    /// True if `ip` lies in this prefix (inclusive at both ends).
    pub const fn contains(&self, ip: [u8; 4]) -> bool {
        let mask = Self::mask(self.len);
        (u32::from_be_bytes(ip) & mask) == (u32::from_be_bytes(self.addr) & mask)
    }

    /// True if the two prefixes' address ranges overlap at all (inclusive
    /// at both ends, as `config`'s validate.rs `range()` rule was).
    pub fn overlaps(&self, other: &Prefix) -> bool {
        let (a0, a1) = self.range();
        let (b0, b1) = other.range();
        a0 <= b1 && b0 <= a1
    }

    /// `None` if `len` is over 32 or `addr` has a bit set past `len`: a
    /// prefix with host bits set is malformed, in a bundle or a build-time
    /// configuration alike.
    pub fn checked(addr: [u8; 4], len: u8) -> Option<Prefix> {
        if len > 32 {
            return None;
        }
        let p = Prefix { addr, len };
        let (lo, _) = p.range();
        if lo != u32::from_be_bytes(addr) {
            return None;
        }
        Some(p)
    }
}

/// A traffic rule: `dst` is the LAN destination, `proto` one of
/// TCP/UDP/ICMP, `port_lo..=port_hi` the destination port range (both 0
/// for ICMP, which names echo only, M8 plan C8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub dst: Prefix,
    pub proto: u8,
    pub port_lo: u16,
    pub port_hi: u16,
}

/// The compiled, build-time facts `policy-wire` validates a bundle against
/// (M8 plan C1); `config` renders one. `neighbors` is the build's static
/// neighbor table.
#[derive(Debug, Clone, Copy)]
pub struct NodeConfig<'a> {
    pub fleet_id: [u8; 16],
    pub inside_prefix: Prefix,
    pub inside_ip: [u8; 4],
    pub outside_ip: [u8; 4],
    pub neighbors: &'a [[u8; 4]],
    pub gateway_wg_public: [u8; 32],
    pub gateway_rp_digest: [u8; 32],
}

/// Why a slot, or a bundle `select` or the init step machine considered,
/// was refused. `WrongFleet` and `Malformed` are [`parse`]'s only two;
/// the rest are `select`/the step machine's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reject {
    Malformed = 0,
    WrongFleet = 1,
    BadSignature = 2,
    RolledBack = 3,
    Skipped = 4,
    BelowFloor = 5,
    PrevMismatch = 6,
    Equivocation = 7,
    Empty = 8,
    MeasureMismatch = 9,
    AdvanceFailed = 10,
    StateRefused = 11,
}

impl Reject {
    /// A stable code for audit lines (M8 plan C9).
    pub const fn code(self) -> u8 {
        self as u8
    }
}

fn advance(pos: usize, n: usize) -> Result<usize, Reject> {
    pos.checked_add(n).ok_or(Reject::Malformed)
}

fn read_u16(slot: &[u8], pos: usize) -> Result<u16, Reject> {
    let end = advance(pos, 2)?;
    let b: [u8; 2] = slot.get(pos..end).ok_or(Reject::Malformed)?.try_into().map_err(|_| Reject::Malformed)?;
    Ok(u16::from_be_bytes(b))
}

fn read_u32(slot: &[u8], pos: usize) -> Result<u32, Reject> {
    let end = advance(pos, 4)?;
    let b: [u8; 4] = slot.get(pos..end).ok_or(Reject::Malformed)?.try_into().map_err(|_| Reject::Malformed)?;
    Ok(u32::from_be_bytes(b))
}

fn read_array<const N: usize>(slot: &[u8], pos: usize) -> Result<[u8; N], Reject> {
    let end = advance(pos, N)?;
    slot.get(pos..end).ok_or(Reject::Malformed)?.try_into().map_err(|_| Reject::Malformed)
}

/// Where each variable-length record starts within a slot, computed once
/// by [`walk_structure`] and reused by every accessor.
#[derive(Debug, Clone, Copy)]
struct Layout {
    peer_count: u8,
    group_count: u8,
    peer_offsets: [usize; MAX_PEERS + 1],
    group_offsets: [usize; MAX_GROUPS + 1],
    sig_start: usize,
}

/// The structural walk, generic over the rp public key length `K` so
/// Kani's I1.1 harness can prove totality at a small `K` instead of the
/// real `SPK_LEN` (M8 plan C1); [`walk`] fixes `K = SPK_LEN` for every
/// real caller. Checks every length, every count bound, canonical
/// ordering, every prefix's host bits, every rule's proto/ports, and
/// that the tail (after the signatures) is all zero. Does not look at
/// `NodeConfig`: that is [`parse`]'s job, once the structure is known
/// sound.
fn walk_structure<const K: usize>(slot: &[u8], total: usize) -> Result<Layout, Reject> {
    if slot.len() != total {
        return Err(Reject::Malformed);
    }
    if slot.get(0..4) != Some(MAGIC.as_slice()) {
        return Err(Reject::Malformed);
    }
    if read_u16(slot, 4)? != FORMAT_VERSION {
        return Err(Reject::Malformed);
    }
    let peer_count = *slot.get(PEER_COUNT_AT).ok_or(Reject::Malformed)?;
    let group_count = *slot.get(GROUP_COUNT_AT).ok_or(Reject::Malformed)?;
    if peer_count == 0 || usize::from(peer_count) > MAX_PEERS {
        return Err(Reject::Malformed);
    }
    if usize::from(group_count) > MAX_GROUPS {
        return Err(Reject::Malformed);
    }

    let mut pos = HEADER_LEN;
    let mut peer_offsets = [0usize; MAX_PEERS + 1];
    let mut prev_wg: Option<&[u8]> = None;
    for i in 0..usize::from(peer_count) {
        *peer_offsets.get_mut(i).ok_or(Reject::Malformed)? = pos;
        let (next, wg_pub) = walk_peer::<K>(slot, pos, group_count, prev_wg)?;
        prev_wg = Some(wg_pub);
        pos = next;
    }
    *peer_offsets.get_mut(usize::from(peer_count)).ok_or(Reject::Malformed)? = pos;

    let mut group_offsets = [0usize; MAX_GROUPS + 1];
    for i in 0..usize::from(group_count) {
        *group_offsets.get_mut(i).ok_or(Reject::Malformed)? = pos;
        pos = walk_group(slot, pos)?;
    }
    *group_offsets.get_mut(usize::from(group_count)).ok_or(Reject::Malformed)? = pos;

    let sig_start = pos;
    let sigs_end = advance(advance(sig_start, SIG_ED25519_LEN)?, SIG_MLDSA65_LEN)?;
    let tail = slot.get(sigs_end..).ok_or(Reject::Malformed)?;
    if tail.iter().any(|&b| b != 0) {
        return Err(Reject::Malformed);
    }

    Ok(Layout { peer_count, group_count, peer_offsets, group_offsets, sig_start })
}

/// One peer entry at `pos` (I1.1 step): on `Ok((next, wg_pub))`,
/// `pos < next <= slot.len()` and `wg_pub` lies inside the entry. The loop
/// in [`walk_structure`] runs it at most `MAX_PEERS` times, so the walk is
/// in bounds by induction over these steps.
fn walk_peer<'a, const K: usize>(slot: &'a [u8], start: usize, group_count: u8, prev_wg: Option<&[u8]>) -> Result<(usize, &'a [u8]), Reject> {
    let wg_end = advance(start, 32)?;
    let wg_pub = slot.get(start..wg_end).ok_or(Reject::Malformed)?;
    if let Some(prev) = prev_wg
        && wg_pub <= prev
    {
        return Err(Reject::Malformed);
    }
    let mut pos = advance(wg_end, K)?;
    let groups_mask = *slot.get(pos).ok_or(Reject::Malformed)?;
    for bit in 0..8u8 {
        if (groups_mask >> bit) & 1 == 1 && u32::from(bit) >= u32::from(group_count) {
            return Err(Reject::Malformed);
        }
    }
    pos = advance(pos, 1)?;
    let allowed_count = *slot.get(pos).ok_or(Reject::Malformed)?;
    pos = advance(pos, 1)?;
    if allowed_count == 0 || usize::from(allowed_count) > MAX_ALLOWED {
        return Err(Reject::Malformed);
    }
    for _ in 0..allowed_count {
        let addr_end = advance(pos, 4)?;
        let addr: [u8; 4] = slot.get(pos..addr_end).ok_or(Reject::Malformed)?.try_into().map_err(|_| Reject::Malformed)?;
        let len = *slot.get(addr_end).ok_or(Reject::Malformed)?;
        if Prefix::checked(addr, len).is_none() {
            return Err(Reject::Malformed);
        }
        pos = advance(addr_end, 1)?;
    }
    Ok((pos, wg_pub))
}

/// One group entry at `pos` (I1.1 step): on `Ok(next)`, `pos < next <=
/// slot.len()`.
fn walk_group(slot: &[u8], start: usize) -> Result<usize, Reject> {
    let rule_count = *slot.get(start).ok_or(Reject::Malformed)?;
    let mut pos = advance(start, 1)?;
    if rule_count == 0 || usize::from(rule_count) > MAX_RULES {
        return Err(Reject::Malformed);
    }
    let mut prev_rule: Option<&[u8]> = None;
    for _ in 0..rule_count {
        let rule_end = advance(pos, RULE_LEN)?;
        let rule = slot.get(pos..rule_end).ok_or(Reject::Malformed)?;
        if let Some(prev) = prev_rule
            && rule <= prev
        {
            return Err(Reject::Malformed);
        }
        prev_rule = Some(rule);
        let addr: [u8; 4] = rule.get(0..4).ok_or(Reject::Malformed)?.try_into().map_err(|_| Reject::Malformed)?;
        let len = *rule.get(4).ok_or(Reject::Malformed)?;
        if Prefix::checked(addr, len).is_none() {
            return Err(Reject::Malformed);
        }
        let proto = *rule.get(5).ok_or(Reject::Malformed)?;
        if proto != PROTO_ICMP && proto != PROTO_TCP && proto != PROTO_UDP {
            return Err(Reject::Malformed);
        }
        let port_lo = u16::from_be_bytes(rule.get(6..8).ok_or(Reject::Malformed)?.try_into().map_err(|_| Reject::Malformed)?);
        let port_hi = u16::from_be_bytes(rule.get(8..10).ok_or(Reject::Malformed)?.try_into().map_err(|_| Reject::Malformed)?);
        if port_lo > port_hi {
            return Err(Reject::Malformed);
        }
        if proto == PROTO_ICMP && (port_lo != 0 || port_hi != 0) {
            return Err(Reject::Malformed);
        }
        pos = rule_end;
    }
    Ok(pos)
}

/// A slot's fixed header, after the whole structure has been walked (no
/// node check, no signatures). For bookkeeping across a fleet, as
/// `tools/policy`'s ledger does; it authorizes nothing (C2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub fleet_id: [u8; 16],
    pub version: u32,
    pub min_release: u32,
    pub prev_sha256: [u8; 32],
    pub roster_sha256: [u8; 32],
    pub peer_count: u8,
    pub group_count: u8,
}

pub fn header(slot: &[u8]) -> Result<Header, Reject> {
    let layout = walk(slot)?;
    Ok(Header {
        fleet_id: read_array(slot, FLEET_ID_AT)?,
        version: u32::from_be_bytes(read_array(slot, VERSION_AT)?),
        min_release: u32::from_be_bytes(read_array(slot, MIN_RELEASE_AT)?),
        prev_sha256: read_array(slot, PREV_SHA256_AT)?,
        roster_sha256: read_array(slot, ROSTER_SHA256_AT)?,
        peer_count: layout.peer_count,
        group_count: layout.group_count,
    })
}

/// The shipped instantiation of [`walk_structure`] (I1.1): the real `K =
/// SPK_LEN`, never a hand-written duplicate of the generic code Kani
/// proves at a small `K`.
fn walk(slot: &[u8]) -> Result<Layout, Reject> {
    walk_structure::<SPK_LEN>(slot, BUNDLE_MAX)
}

/// A borrowed view of one peer's bundle entry.
#[derive(Clone, Copy)]
pub struct PeerView<'a> {
    wg_pub: &'a [u8; 32],
    rp_pub: &'a [u8; SPK_LEN],
    groups: u8,
    allowed: &'a [u8],
}

impl<'a> PeerView<'a> {
    pub fn wg_pub(&self) -> &'a [u8; 32] {
        self.wg_pub
    }

    pub fn rp_pub(&self) -> &'a [u8; SPK_LEN] {
        self.rp_pub
    }

    /// The group-membership bitmask (bit `g` set means a member of group `g`).
    pub fn groups(&self) -> u8 {
        self.groups
    }

    pub fn in_group(&self, g: u8) -> bool {
        g < 8 && (self.groups >> g) & 1 == 1
    }

    pub fn allowed(&self) -> PrefixIter<'a> {
        PrefixIter { bytes: self.allowed }
    }
}

fn peer_at<'a>(slot: &'a [u8], layout: &Layout, i: usize) -> Option<PeerView<'a>> {
    let start = *layout.peer_offsets.get(i)?;
    let end = *layout.peer_offsets.get(i.checked_add(1)?)?;
    let wg_pub: &[u8; 32] = slot.get(start..start.checked_add(32)?)?.try_into().ok()?;
    let rp_start = start.checked_add(32)?;
    let rp_pub: &[u8; SPK_LEN] = slot.get(rp_start..rp_start.checked_add(SPK_LEN)?)?.try_into().ok()?;
    let groups_pos = rp_start.checked_add(SPK_LEN)?;
    let groups = *slot.get(groups_pos)?;
    let allowed_start = groups_pos.checked_add(2)?;
    Some(PeerView { wg_pub, rp_pub, groups, allowed: slot.get(allowed_start..end)? })
}

/// An iterator over one peer's allowed-IP prefixes.
pub struct PrefixIter<'a> {
    bytes: &'a [u8],
}

impl Iterator for PrefixIter<'_> {
    type Item = Prefix;

    fn next(&mut self) -> Option<Prefix> {
        let addr: [u8; 4] = self.bytes.get(0..4)?.try_into().ok()?;
        let len = *self.bytes.get(4)?;
        self.bytes = self.bytes.get(PREFIX_LEN..)?;
        Some(Prefix { addr, len })
    }
}

/// A borrowed view of one group's rules.
#[derive(Clone, Copy)]
pub struct GroupView<'a> {
    rules: &'a [u8],
}

impl<'a> GroupView<'a> {
    pub fn rules(&self) -> RuleIter<'a> {
        RuleIter { bytes: self.rules }
    }
}

fn group_at<'a>(slot: &'a [u8], layout: &Layout, i: usize) -> Option<GroupView<'a>> {
    let start = *layout.group_offsets.get(i)?;
    let end = *layout.group_offsets.get(i.checked_add(1)?)?;
    let rules_start = start.checked_add(1)?;
    Some(GroupView { rules: slot.get(rules_start..end)? })
}

/// An iterator over one group's rules.
pub struct RuleIter<'a> {
    bytes: &'a [u8],
}

impl Iterator for RuleIter<'_> {
    type Item = Rule;

    fn next(&mut self) -> Option<Rule> {
        let addr: [u8; 4] = self.bytes.get(0..4)?.try_into().ok()?;
        let len = *self.bytes.get(4)?;
        let proto = *self.bytes.get(5)?;
        let port_lo = u16::from_be_bytes(self.bytes.get(6..8)?.try_into().ok()?);
        let port_hi = u16::from_be_bytes(self.bytes.get(8..10)?.try_into().ok()?);
        self.bytes = self.bytes.get(RULE_LEN..)?;
        Some(Rule { dst: Prefix { addr, len }, proto, port_lo, port_hi })
    }
}

/// A parsed, validated bundle borrowed from its slot. No public fields and
/// no public constructor besides [`parse`] and [`open`] (I1.2).
#[derive(Debug)]
pub struct Bundle<'a> {
    slot: &'a [u8],
    version: u32,
    min_release: u32,
    prev_sha256: [u8; 32],
    roster_sha256: [u8; 32],
    layout: Layout,
}

impl<'a> Bundle<'a> {
    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn min_release(&self) -> u32 {
        self.min_release
    }

    pub fn prev_sha256(&self) -> &[u8; 32] {
        &self.prev_sha256
    }

    pub fn roster_sha256(&self) -> &[u8; 32] {
        &self.roster_sha256
    }

    pub fn peer_count(&self) -> u8 {
        self.layout.peer_count
    }

    pub fn group_count(&self) -> u8 {
        self.layout.group_count
    }

    pub fn peer(&self, i: u8) -> Option<PeerView<'a>> {
        if usize::from(i) >= usize::from(self.layout.peer_count) {
            return None;
        }
        peer_at(self.slot, &self.layout, usize::from(i))
    }

    pub fn group(&self, i: u8) -> Option<GroupView<'a>> {
        if usize::from(i) >= usize::from(self.layout.group_count) {
            return None;
        }
        group_at(self.slot, &self.layout, usize::from(i))
    }

    /// The peer whose allowed IPs contain `ip` (allowed IPs never overlap).
    pub fn owner_of(&self, ip: [u8; 4]) -> Option<u8> {
        (0..self.layout.peer_count).find(|&i| self.peer(i).is_some_and(|p| p.allowed().any(|pre| pre.contains(ip))))
    }
}

/// The body and the two signatures of a slot, split out by structure alone
/// (D10: no signature verification here). The verifier (the `policy` PD)
/// checks both signatures over `DOMAIN ‖ body` and, only then, calls
/// [`parse`].
pub struct Unverified<'a> {
    body: &'a [u8],
    sig_ed25519: &'a [u8; SIG_ED25519_LEN],
    sig_mldsa65: &'a [u8; SIG_MLDSA65_LEN],
}

impl<'a> Unverified<'a> {
    pub fn body(&self) -> &'a [u8] {
        self.body
    }

    pub fn sig_ed25519(&self) -> &'a [u8; SIG_ED25519_LEN] {
        self.sig_ed25519
    }

    pub fn sig_mldsa65(&self) -> &'a [u8; SIG_MLDSA65_LEN] {
        self.sig_mldsa65
    }
}

/// Splits a slot into its signed body and its two signatures, checking
/// enough of the structure to find the boundary. Never verifies a
/// signature (D10).
pub fn split(slot: &[u8]) -> Result<Unverified<'_>, Reject> {
    let layout = walk(slot)?;
    let body = slot.get(..layout.sig_start).ok_or(Reject::Malformed)?;
    let ed_end = advance(layout.sig_start, SIG_ED25519_LEN)?;
    let ml_end = advance(ed_end, SIG_MLDSA65_LEN)?;
    let sig_ed25519: &[u8; SIG_ED25519_LEN] =
        slot.get(layout.sig_start..ed_end).ok_or(Reject::Malformed)?.try_into().map_err(|_| Reject::Malformed)?;
    let sig_mldsa65: &[u8; SIG_MLDSA65_LEN] = slot.get(ed_end..ml_end).ok_or(Reject::Malformed)?.try_into().map_err(|_| Reject::Malformed)?;
    Ok(Unverified { body, sig_ed25519, sig_mldsa65 })
}

/// Parses and validates a slot's bundle against `node`. Intended to be
/// called only after the caller (the `policy` PD) has verified both
/// signatures over `DOMAIN ‖ split(slot)?.body()` (D10 does not make that
/// structural: verification lives outside this crate entirely). `rp_digest`
/// hashes a peer's rp public key the same way `node.gateway_rp_digest` was
/// computed, so this crate takes no hash dependency.
///
/// Validates: `fleet_id` equals `node.fleet_id`; no duplicate `wg_pub` (the
/// canonical ascending order already forbids it) or `rp_pub`; no peer uses
/// the gateway's `wg_pub` or `rp_pub`; every peer's allowed IPs are
/// non-empty (structural), pairwise disjoint across all peers, and none
/// contains `node.inside_ip`/`node.outside_ip`/a neighbor or overlaps
/// `node.inside_prefix`.
///
/// Only the verifier side (`policy` and `tools/policy`) enables `verifier`;
/// a consumer gets a `Bundle` through `open` and its token alone (C1, I1.2).
#[cfg(any(test, kani, feature = "verifier"))]
pub fn parse<'a>(slot: &'a [u8], node: &NodeConfig<'_>, rp_digest: &dyn Fn(&[u8; SPK_LEN]) -> [u8; 32]) -> Result<Bundle<'a>, Reject> {
    parse_unchecked(slot, node, rp_digest)
}

fn parse_unchecked<'a>(slot: &'a [u8], node: &NodeConfig<'_>, rp_digest: &dyn Fn(&[u8; SPK_LEN]) -> [u8; 32]) -> Result<Bundle<'a>, Reject> {
    let layout = walk(slot)?;

    let fleet_id: [u8; 16] = read_array(slot, FLEET_ID_AT)?;
    if fleet_id != node.fleet_id {
        return Err(Reject::WrongFleet);
    }
    let version = read_u32(slot, VERSION_AT)?;
    let min_release = read_u32(slot, MIN_RELEASE_AT)?;
    let prev_sha256: [u8; 32] = read_array(slot, PREV_SHA256_AT)?;
    let roster_sha256: [u8; 32] = read_array(slot, ROSTER_SHA256_AT)?;

    let mut rp_pubs: [Option<&[u8; SPK_LEN]>; MAX_PEERS] = [None; MAX_PEERS];
    let mut all_prefixes: [Prefix; MAX_PEERS * MAX_ALLOWED] = [Prefix { addr: [0; 4], len: 0 }; MAX_PEERS * MAX_ALLOWED];
    let mut prefix_count = 0usize;

    for i in 0..usize::from(layout.peer_count) {
        let p = peer_at(slot, &layout, i).ok_or(Reject::Malformed)?;
        if *p.wg_pub() == node.gateway_wg_public {
            return Err(Reject::Malformed);
        }
        if rp_digest(p.rp_pub()) == node.gateway_rp_digest {
            return Err(Reject::Malformed);
        }
        if rp_pubs.iter().take(i).any(|prev| prev.is_some_and(|prev| prev == p.rp_pub())) {
            return Err(Reject::Malformed);
        }
        *rp_pubs.get_mut(i).ok_or(Reject::Malformed)? = Some(p.rp_pub());

        for pre in p.allowed() {
            if pre.contains(node.inside_ip) || pre.contains(node.outside_ip) {
                return Err(Reject::Malformed);
            }
            if node.neighbors.iter().any(|n| pre.contains(*n)) {
                return Err(Reject::Malformed);
            }
            if pre.overlaps(&node.inside_prefix) {
                return Err(Reject::Malformed);
            }
            let slot_ref = all_prefixes.get_mut(prefix_count).ok_or(Reject::Malformed)?;
            *slot_ref = pre;
            prefix_count = prefix_count.checked_add(1).ok_or(Reject::Malformed)?;
        }
    }

    for i in 0..prefix_count {
        for j in i.checked_add(1).ok_or(Reject::Malformed)?..prefix_count {
            let a = all_prefixes.get(i).ok_or(Reject::Malformed)?;
            let b = all_prefixes.get(j).ok_or(Reject::Malformed)?;
            if a.overlaps(b) {
                return Err(Reject::Malformed);
            }
        }
    }

    Ok(Bundle { slot, version, min_release, prev_sha256, roster_sha256, layout })
}

/// Which slot ("A" or "B") the loader's descriptor names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

/// Proof that `policy` has already verified and selected a slot's bundle
/// (M8 plan C5/C6): no public fields and no public constructor besides
/// [`Verified::from_reply`] (I1.2), so [`open`] is reachable only through
/// one. `version` and `body_sha256` are carried for audit only (M8 plan
/// "Consumer-flow walkthroughs"); `open` does not re-hash the slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    slot: Slot,
    version: u32,
    body_sha256: [u8; 32],
}

/// `Verified`'s wire form in the `policy` PD's `Await` reply: `slot (0=A,
/// 1=B) ‖ version (u32 BE) ‖ body_sha256 [32]`.
const VERIFIED_REPLY_LEN: usize = 1 + 4 + 32;

impl Verified {
    pub fn slot(&self) -> Slot {
        self.slot
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn body_sha256(&self) -> &[u8; 32] {
        &self.body_sha256
    }

    /// Decodes the `policy` PD's `Await` reply. `None` for any length or
    /// slot byte other than the ones the reply ever carries.
    pub fn from_reply(reply: &[u8]) -> Option<Verified> {
        if reply.len() != VERIFIED_REPLY_LEN {
            return None;
        }
        let slot = match *reply.first()? {
            0 => Slot::A,
            1 => Slot::B,
            _ => return None,
        };
        let version = u32::from_be_bytes(reply.get(1..5)?.try_into().ok()?);
        let body_sha256: [u8; 32] = reply.get(5..VERIFIED_REPLY_LEN)?.try_into().ok()?;
        Some(Verified { slot, version, body_sha256 })
    }
}

/// Parses and validates `slot` the same way [`parse`] does, for a
/// consumer (a barrier PD) holding a [`Verified`] witness for it. The
/// witness proves `policy` already verified a slot's signatures and
/// selected it this boot; `open` checks that the parsed bundle's version
/// still matches, but does not re-verify a signature or re-hash the slot
/// (M8 plan C1: no PD maps the slot writable, so the bytes cannot change
/// between `policy`'s `parse` and this `open`).
pub fn open<'a>(token: &Verified, slot: &'a [u8], node: &NodeConfig<'_>, rp_digest: &dyn Fn(&[u8; SPK_LEN]) -> [u8; 32]) -> Result<Bundle<'a>, Reject> {
    let bundle = parse_unchecked(slot, node, rp_digest)?;
    if bundle.version() != token.version {
        return Err(Reject::Malformed);
    }
    Ok(bundle)
}

/// One slot's state as `policy`'s `init` sees it (M8 plan C5 step 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotView {
    Empty,
    Malformed,
    BadSignature,
    Valid { version: u32, min_release: u32, prev_sha256: [u8; 32], body_sha256: [u8; 32] },
}

/// `select`'s outcome (M8 plan C5 step 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Use { slot: Slot },
    Advance { slot: Slot },
    Refuse { reason: Reject },
}

#[derive(Debug, Clone, Copy)]
enum Classification {
    Candidate { version: u32, prev_sha256: [u8; 32], body_sha256: [u8; 32], is_next: bool },
    NotCandidate(Reject),
}

/// A slot is a candidate iff its version is `current` or `current + 1`
/// (`checked_add`) and its floor is at or below `release_seq`; otherwise
/// it is rejected for a reason fixed by its version alone.
fn classify(current: u32, release_seq: u32, view: SlotView) -> Classification {
    match view {
        SlotView::Empty => Classification::NotCandidate(Reject::Empty),
        SlotView::Malformed => Classification::NotCandidate(Reject::Malformed),
        SlotView::BadSignature => Classification::NotCandidate(Reject::BadSignature),
        SlotView::Valid { version, min_release, prev_sha256, body_sha256 } => {
            let is_next = current.checked_add(1) == Some(version);
            if version == current || is_next {
                if min_release > release_seq {
                    Classification::NotCandidate(Reject::BelowFloor)
                } else {
                    Classification::Candidate { version, prev_sha256, body_sha256, is_next }
                }
            } else if version < current {
                Classification::NotCandidate(Reject::RolledBack)
            } else {
                Classification::NotCandidate(Reject::Skipped)
            }
        }
    }
}

/// True if `view` is a signature-verified bundle at exactly `version`,
/// whatever its own floor (the anchor condition, M8 plan C5 step 4):
/// returns its body digest.
fn anchor_body_at(view: SlotView, version: u32) -> Option<[u8; 32]> {
    if let SlotView::Valid { version: v, body_sha256, .. } = view
        && v == version
    {
        return Some(body_sha256);
    }
    None
}

fn resolve_candidate(current: u32, slot: Slot, prev_sha256: [u8; 32], is_next: bool, other: SlotView) -> Decision {
    if is_next {
        match anchor_body_at(other, current) {
            Some(anchor_body) if anchor_body == prev_sha256 => Decision::Advance { slot },
            _ => Decision::Refuse { reason: Reject::PrevMismatch },
        }
    } else {
        Decision::Use { slot }
    }
}

/// The fixed precedence when neither slot is a candidate: `BelowFloor >
/// Skipped > PrevMismatch > RolledBack > BadSignature > Malformed > Empty`
/// (M8 plan C5 step 4). `PrevMismatch` and `Equivocation` never reach this
/// function (they are decided immediately, not by precedence), but are
/// ranked for completeness.
fn rank(r: Reject) -> u8 {
    match r {
        Reject::BelowFloor => 0,
        Reject::Skipped => 1,
        Reject::PrevMismatch => 2,
        Reject::RolledBack => 3,
        Reject::BadSignature => 4,
        Reject::Malformed => 5,
        Reject::Empty => 6,
        Reject::WrongFleet | Reject::Equivocation | Reject::AdvanceFailed | Reject::StateRefused | Reject::MeasureMismatch => 7,
    }
}

fn worse(a: Reject, b: Reject) -> Reject {
    if rank(a) <= rank(b) { a } else { b }
}

/// `policy`'s `init` step 4 (M8 plan C5): a pure function of both slots'
/// views, `current` and `release_seq`. Proved correct over every small
/// symbolic input by I5.3.
pub fn select(current: u32, release_seq: u32, a: SlotView, b: SlotView) -> Decision {
    match (classify(current, release_seq, a), classify(current, release_seq, b)) {
        (Classification::Candidate { version: va, prev_sha256: pa, body_sha256: ba, is_next: na }, Classification::Candidate { version: vb, body_sha256: bb, .. }) if va == vb => {
            if ba == bb {
                resolve_candidate(current, Slot::A, pa, na, b)
            } else {
                Decision::Refuse { reason: Reject::Equivocation }
            }
        }
        (Classification::Candidate { prev_sha256: pa, is_next: na, .. }, Classification::Candidate { prev_sha256: pb, .. }) => {
            // The versions differ here (the same-version arm above already
            // matched otherwise): exactly one of them is the current+1
            // candidate, since both lie in {current, current+1}.
            if na {
                resolve_candidate(current, Slot::A, pa, true, b)
            } else {
                resolve_candidate(current, Slot::B, pb, true, a)
            }
        }
        (Classification::Candidate { prev_sha256, is_next, .. }, Classification::NotCandidate(_)) => resolve_candidate(current, Slot::A, prev_sha256, is_next, b),
        (Classification::NotCandidate(_), Classification::Candidate { prev_sha256, is_next, .. }) => resolve_candidate(current, Slot::B, prev_sha256, is_next, a),
        (Classification::NotCandidate(ra), Classification::NotCandidate(rb)) => Decision::Refuse { reason: worse(ra, rb) },
    }
}

/// The `policy` PD's `REQ_POLICY_STATE` reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateReply {
    Ok { current: u32, pcr9: [u8; 32] },
    Refused,
}

/// The `policy` PD's `REQ_POLICY_ADVANCE` reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvanceReply {
    Ok(u32),
    Refused,
}

/// The init step machine's final result (M8 plan C5 "Central invariant
/// I5.1"): a usable, signature-verified slot, or why none is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Verified { slot: Slot, version: u32, body_sha256: [u8; 32] },
    Unavailable { reason: Reject },
}

/// `select` decided `Advance`: the caller must send `ADVANCE{current}`
/// and pass the reply to [`after_advance`] before a final [`Outcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingAdvance {
    slot: Slot,
    current: u32,
    body_sha256: [u8; 32],
}

/// Either a final outcome, or an ADVANCE request pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Done(Outcome),
    Advance(PendingAdvance),
}

fn body_sha256_of(slot: Slot, a: SlotView, b: SlotView) -> Option<[u8; 32]> {
    let view = match slot {
        Slot::A => a,
        Slot::B => b,
    };
    if let SlotView::Valid { body_sha256, .. } = view { Some(body_sha256) } else { None }
}

/// `policy`'s `init` steps 1-4 (M8 plan C5): the STATE reply, the PCR 9
/// check and both slots' views. A pure function with no I/O of its own;
/// the `policy` PD performs the actual STATE/ADVANCE requests and drives
/// this machine with their replies.
pub fn after_state(reply: StateReply, expected_pcr9: &[u8; 32], release_seq: u32, a: SlotView, b: SlotView) -> Step {
    let (current, pcr9) = match reply {
        StateReply::Refused => return Step::Done(Outcome::Unavailable { reason: Reject::StateRefused }),
        StateReply::Ok { current, pcr9 } => (current, pcr9),
    };
    if &pcr9 != expected_pcr9 {
        return Step::Done(Outcome::Unavailable { reason: Reject::MeasureMismatch });
    }
    match select(current, release_seq, a, b) {
        Decision::Use { slot } => match body_sha256_of(slot, a, b) {
            Some(body_sha256) => Step::Done(Outcome::Verified { slot, version: current, body_sha256 }),
            None => Step::Done(Outcome::Unavailable { reason: Reject::Malformed }),
        },
        Decision::Advance { slot } => match body_sha256_of(slot, a, b) {
            Some(body_sha256) => Step::Advance(PendingAdvance { slot, current, body_sha256 }),
            None => Step::Done(Outcome::Unavailable { reason: Reject::Malformed }),
        },
        Decision::Refuse { reason } => Step::Done(Outcome::Unavailable { reason }),
    }
}

/// `policy`'s `init` step 5 (M8 plan C5): the ADVANCE reply, after
/// [`after_state`] returned [`Step::Advance`]. `Verified{version =
/// current+1}` only if the reply equals `current+1`; no fallback to the
/// older slot on any other reply.
pub fn after_advance(pending: PendingAdvance, reply: AdvanceReply) -> Outcome {
    let expected = match pending.current.checked_add(1) {
        Some(v) => v,
        None => return Outcome::Unavailable { reason: Reject::AdvanceFailed },
    };
    match reply {
        AdvanceReply::Ok(new_value) if new_value == expected => {
            Outcome::Verified { slot: pending.slot, version: expected, body_sha256: pending.body_sha256 }
        }
        _ => Outcome::Unavailable { reason: Reject::AdvanceFailed },
    }
}

/// A plain-struct encoder for tests and `tools/policy`: produces the
/// canonical slot bytes (exactly `BUNDLE_MAX`, zero tail) from already-
/// canonical fields. Signatures are supplied by the caller (placeholder
/// zeros allowed; `tools/policy sign` fills them for real).
#[cfg(any(test, feature = "render"))]
pub mod render {
    use alloc::vec::Vec;

    use super::{BUNDLE_MAX, Prefix, Rule};

    pub struct PlainPeer<'a> {
        pub wg_pub: [u8; 32],
        pub rp_pub: &'a [u8; limits::SPK_LEN],
        pub groups: u8,
        pub allowed: &'a [Prefix],
    }

    pub struct PlainGroup<'a> {
        pub rules: &'a [Rule],
    }

    pub struct PlainBundle<'a> {
        pub fleet_id: [u8; 16],
        pub version: u32,
        pub min_release: u32,
        pub prev_sha256: [u8; 32],
        pub roster_sha256: [u8; 32],
        pub peers: &'a [PlainPeer<'a>],
        pub groups: &'a [PlainGroup<'a>],
        pub sig_ed25519: [u8; 64],
        pub sig_mldsa65: [u8; 3309],
    }

    /// Renders `b` to exactly `BUNDLE_MAX` bytes. Does not sort or
    /// deduplicate: the caller supplies already-canonical peers and rules.
    pub fn render(b: &PlainBundle<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"KZPP");
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&b.fleet_id);
        out.extend_from_slice(&b.version.to_be_bytes());
        out.extend_from_slice(&b.min_release.to_be_bytes());
        out.extend_from_slice(&b.prev_sha256);
        out.extend_from_slice(&b.roster_sha256);
        out.push(b.peers.len() as u8);
        out.push(b.groups.len() as u8);
        for p in b.peers {
            out.extend_from_slice(&p.wg_pub);
            out.extend_from_slice(p.rp_pub.as_slice());
            out.push(p.groups);
            out.push(p.allowed.len() as u8);
            for a in p.allowed {
                out.extend_from_slice(&a.addr);
                out.push(a.len);
            }
        }
        for g in b.groups {
            out.push(g.rules.len() as u8);
            for r in g.rules {
                out.extend_from_slice(&r.dst.addr);
                out.push(r.dst.len);
                out.push(r.proto);
                out.extend_from_slice(&r.port_lo.to_be_bytes());
                out.extend_from_slice(&r.port_hi.to_be_bytes());
            }
        }
        out.extend_from_slice(&b.sig_ed25519);
        out.extend_from_slice(&b.sig_mldsa65);
        out.resize(BUNDLE_MAX, 0);
        out
    }
}

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod proofs;
