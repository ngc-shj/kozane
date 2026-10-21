//! Ethernet / ARP / IPv4 / UDP parsing and emission for untrusted frames.
//!
//! `parse_frame` is total: every input yields either a `Frame` or a
//! `DropReason`, and it never panics (proved by the Kani harnesses in
//! `proofs`, and unbounded by Verus, M4 plan C5). It accepts only the narrow
//! subset `ingress` needs: no VLANs, no IPv4 options, no fragments.
//! `parse_frame_ip` is the inside-NIC variant: same rules, but any IPv4
//! protocol, kept verbatim for forwarding.
//!
//! Verus proves (M4 plan C5): each entry point accepts exactly the frames
//! described above; `parse(emit(f))` is semantically `f` (not byte
//! identical — `emit` rewrites the IPv4 ID, sets TTL 64 and DF, and drops
//! Ethernet padding); `Body::Ipv4` is emitted verbatim under its
//! precondition; `forward_ipv4` decrements the TTL, refuses TTL <= 1, and
//! recomputes the header checksum (RFC 1812 section 5.3.1). The Internet
//! checksum itself is specified as the ones'-complement sum of 16-bit words
//! (`spec_sum16`/`spec_fold16`), and the exec `csum_add`/`csum_fold` are
//! proved equal to it, not assumed.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use vstd::prelude::*;

verus! {

pub type Mac = [u8; 6];
pub type Ipv4 = [u8; 4];

pub const ETH_HDR: usize = 14;
pub const ARP_LEN: usize = 28;
pub const IPV4_HDR: usize = 20;
pub const UDP_HDR: usize = 8;
/// Largest frame we emit or accept (no jumbo frames, no FCS).
pub const MAX_FRAME: usize = 1514;
pub const MAX_UDP_PAYLOAD: usize = MAX_FRAME - ETH_HDR - IPV4_HDR - UDP_HDR;

// `pub`, not `const` private to the module: a public spec fn cannot name a
// private const (same gap msgs' V2 deviation hit for `EP_LEN`).
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const IPPROTO_UDP: u8 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthAddrs {
    pub src: Mac,
    pub dst: Mac,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOp {
    Request,
    Reply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    pub op: ArpOp,
    pub sha: Mac,
    pub spa: Ipv4,
    pub tha: Mac,
    pub tpa: Ipv4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Udp4<'a> {
    pub src: Ipv4,
    pub dst: Ipv4,
    pub sport: u16,
    pub dport: u16,
    pub payload: &'a [u8],
}

/// A validated IPv4 datagram of any protocol. `packet` is the datagram
/// exactly as received (header included, Ethernet padding removed), so it
/// can be forwarded without re-encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ip4Packet<'a> {
    pub src: Ipv4,
    pub dst: Ipv4,
    pub proto: u8,
    pub packet: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body<'a> {
    Arp(ArpPacket),
    Udp4(Udp4<'a>),
    /// Only from `parse_frame_ip`.
    Ipv4(Ip4Packet<'a>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub eth: EthAddrs,
    pub body: Body<'a>,
}

/// Why a frame was dropped. Values are stable: they appear in audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DropReason {
    TooShort = 1,
    TooLong = 2,
    EthBadSrc = 3,
    UnknownEtherType = 4,
    ArpMalformed = 5,
    ArpBadSender = 6,
    Ipv4Version = 7,
    Ipv4Options = 8,
    Ipv4Fragment = 9,
    Ipv4BadLength = 10,
    Ipv4BadChecksum = 11,
    Ipv4BadSrc = 12,
    NotUdp = 13,
    UdpBadLength = 14,
    UdpBadChecksum = 15,
    // Forwarding only: TTL would reach zero (never from the parsers).
    TtlExpired = 16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitError {
    TooSmall,
    /// The frame would not be accepted by `parse_frame` (bad source address,
    /// oversized payload), so it is refused rather than emitted.
    Invalid,
}

// --- Source-address validity, as a spec and as the matching exec code. ---

/// Group bit clear and not all-zero (not multicast/broadcast, not unassigned).
pub open spec fn mac_valid(m: Seq<u8>) -> bool {
    &&& m.len() == 6
    &&& m[0] & 1 == 0
    &&& !(m[0] == 0 && m[1] == 0 && m[2] == 0 && m[3] == 0 && m[4] == 0 && m[5] == 0)
}

/// Not unspecified, broadcast, multicast (224/4) or loopback (127/8).
pub open spec fn ipv4_valid(a: Seq<u8>) -> bool {
    &&& a.len() == 4
    &&& !(a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0)
    &&& !(a[0] == 255 && a[1] == 255 && a[2] == 255 && a[3] == 255)
    &&& (a[0] & 0xf0) != 0xe0
    &&& a[0] != 127
}

#[inline]
fn mac_is_valid_src(m: &Mac) -> (r: bool)
    ensures
        r == mac_valid(m@),
{
    m[0] & 1 == 0
        && (m[0] != 0 || m[1] != 0 || m[2] != 0 || m[3] != 0 || m[4] != 0 || m[5] != 0)
}

#[inline]
fn ipv4_is_valid_src(a: &Ipv4) -> (r: bool)
    ensures
        r == ipv4_valid(a@),
{
    (a[0] != 0 || a[1] != 0 || a[2] != 0 || a[3] != 0)
        && (a[0] != 255 || a[1] != 255 || a[2] != 255 || a[3] != 255)
        && (a[0] & 0xf0) != 0xe0
        && a[0] != 127
}

/// Reads `N` bytes at `start`: `get` on a literal range has a vstd spec
/// (V0 probe, M4 plan C1); `try_into` for `&[u8] -> [u8; N]` does not.
#[inline]
fn read_array<const N: usize>(bytes: &[u8], start: usize) -> (r: Option<[u8; N]>)
    ensures
        r is Some <==> start as int + N as int <= bytes@.len(),
        r is Some ==> r->Some_0@ == bytes@.subrange(start as int, start as int + N as int),
{
    assert(bytes@.len() == bytes.len() as int);
    assert(bytes.len() <= usize::MAX);
    match start.checked_add(N) {
        None => None,
        Some(end) => match bytes.get(start..end) {
            None => None,
            Some(src) => {
                assert(src@ == bytes@.subrange(start as int, end as int));
                let mut out = [0u8; N];
                out.copy_from_slice(src);
                assert(out@ == src@);
                Some(out)
            },
        },
    }
}

/// Writes `bytes` at `start`: `get_mut` on a literal range has a vstd spec
/// (V0 probe, M4 plan C1), unlike `split_at_mut_checked`/`mem::take`.
#[inline]
fn write_at(out: &mut [u8], start: usize, bytes: &[u8]) -> (r: Option<()>)
    ensures
        r is Some <==> start as int + bytes@.len() as int <= old(out)@.len(),
        r is Some ==> {
            &&& final(out)@.len() == old(out)@.len()
            &&& final(out)@.subrange(start as int, start as int + bytes@.len() as int) == bytes@
            &&& (forall|i: int|
                0 <= i < old(out)@.len() && !(start as int <= i < start as int + bytes@.len()
                    as int) ==> #[trigger] final(out)@[i] == old(out)@[i])
        },
        r is None ==> final(out)@ == old(out)@,
{
    assert(out@.len() == out.len() as int);
    assert(out.len() <= usize::MAX);
    assert(bytes@.len() == bytes.len() as int);
    assert(bytes.len() <= usize::MAX);
    match start.checked_add(bytes.len()) {
        None => None,
        Some(end) => match out.get_mut(start..end) {
            None => None,
            Some(dst) => {
                dst.copy_from_slice(bytes);
                proof {
                    assert forall|i: int|
                        0 <= i < old(out)@.len() && !(start as int <= i < end as int)
                            implies #[trigger] out@[i] == old(out)@[i] by {
                        if i < start as int {
                            assert(out@.subrange(0, start as int)[i] == out@[i]);
                            assert(old(out)@.subrange(0, start as int)[i] == old(out)@[i]);
                        } else {
                            assert(out@.subrange(end as int, old(out)@.len() as int)[i - end as int]
                                == out@[i]);
                            assert(old(out)@.subrange(end as int, old(out)@.len() as int)[i
                                - end as int] == old(out)@[i]);
                        }
                    };
                }
                Some(())
            },
        },
    }
}

// --- Big-endian byte layout for `u16`, as a spec and as the matching exec
// code (`from_be_bytes`/`to_be_bytes` have no vstd spec, M4 plan C1/C5). ---

pub open spec fn u16_from_be(b: Seq<u8>) -> u16
    recommends
        b.len() == 2,
{
    ((b[0] as u16) << 8) | (b[1] as u16)
}

pub open spec fn u16_to_be(x: u16) -> Seq<u8> {
    seq![((x >> 8) & 0xff) as u8, (x & 0xff) as u8]
}

proof fn lemma_u16_be_roundtrip(x: u16)
    ensures
        u16_from_be(u16_to_be(x)) == x,
{
    let b = u16_to_be(x);
    assert(b.len() == 2);
    assert(b[0] == ((x >> 8) & 0xff) as u8);
    assert(b[1] == (x & 0xff) as u8);
    assert(u16_from_be(b) == ((b[0] as u16) << 8) | (b[1] as u16));
    assert(((((x >> 8) & 0xff) as u8 as u16) << 8) | (((x & 0xff) as u8) as u16) == x) by (
    bit_vector);
}

proof fn lemma_u16_be_inverse(b: Seq<u8>)
    requires
        b.len() == 2,
    ensures
        u16_to_be(u16_from_be(b)) == b,
{
    let b0 = b[0];
    let b1 = b[1];
    let x = u16_from_be(b);
    assert(x == ((b0 as u16) << 8) | (b1 as u16));
    assert({
        let v = ((b0 as u16) << 8) | (b1 as u16);
        &&& ((v >> 8) & 0xff) as u8 == b0
        &&& (v & 0xff) as u8 == b1
    }) by (bit_vector);
    assert(u16_to_be(x).len() == 2);
    assert(u16_to_be(x) =~= b);
}

#[inline]
fn u16_from_be_arr(b: [u8; 2]) -> (x: u16)
    ensures
        x == u16_from_be(b@),
{
    ((b[0] as u16) << 8) | (b[1] as u16)
}

#[inline]
fn u16_to_be_arr(x: u16) -> (b: [u8; 2])
    ensures
        b@ == u16_to_be(x),
{
    [((x >> 8) & 0xff) as u8, (x & 0xff) as u8]
}

/// Reads a big-endian `u16` at `at`.
#[inline]
fn be16(b: &[u8], at: usize) -> (r: Option<u16>)
    ensures
        r is Some <==> at as int + 2 <= b@.len(),
        r is Some ==> r->Some_0 == u16_from_be(b@.subrange(at as int, at as int + 2)),
{
    read_array::<2>(b, at).map(u16_from_be_arr)
}

// --- The Internet checksum (RFC 1071): the ones'-complement sum of
// 16-bit big-endian words, folded to 16 bits and complemented. Specified
// here as a pure function of the bytes; `csum_add`/`csum_fold` below are
// proved equal to it, not assumed (M4 plan C5). ---

/// The big-endian 16-bit word at `data[i..i+2]`, as a value (`nat`, so the
/// running sum below never needs a bound to stay well defined).
pub open spec fn spec_word_be16(data: Seq<u8>, i: int) -> nat
    recommends
        0 <= i,
        i + 1 < data.len(),
{
    (data[i] as nat) * 0x100 + (data[i + 1] as nat)
}

/// The ones'-complement sum of 16-bit big-endian words over `data` (a
/// trailing odd byte counts as its high byte, as RFC 1071 and `csum_add`
/// both do). Unbounded: defined for any length, any value.
pub open spec fn spec_sum16(data: Seq<u8>) -> nat
    decreases data.len(),
{
    if data.len() < 2 {
        if data.len() == 1 {
            (data[0] as nat) * 0x100
        } else {
            0
        }
    } else {
        spec_word_be16(data, 0) + spec_sum16(data.subrange(2, data.len() as int))
    }
}

/// `spec_sum16` is additive over a concatenation split at an even length:
/// the pairing never crosses the join.
proof fn lemma_sum16_concat(a: Seq<u8>, b: Seq<u8>)
    requires
        a.len() % 2 == 0,
    ensures
        spec_sum16(a + b) == spec_sum16(a) + spec_sum16(b),
    decreases a.len(),
{
    if a.len() == 0 {
        assert((a + b) =~= b);
    } else {
        let a2 = a.subrange(2, a.len() as int);
        assert(a2.len() % 2 == 0);
        assert((a + b).subrange(2, (a + b).len() as int) =~= a2 + b);
        assert((a + b)[0] == a[0]);
        assert((a + b)[1] == a[1]);
        lemma_sum16_concat(a2, b);
    }
}

/// A coarse bound: no 16-bit word contributes more than `0x10000`, so
/// `data.len()` bytes contribute at most that many times `0x10000`. Used
/// to show `csum_add`'s accumulator never wraps for this crate's buffers
/// (bounded by `MAX_FRAME`).
proof fn lemma_mul_0x10000_le(a: nat, b: nat)
    requires
        a <= b,
    ensures
        a * 0x10000 <= b * 0x10000,
{
}

proof fn lemma_sum16_bound(data: Seq<u8>)
    ensures
        spec_sum16(data) <= (data.len() as nat) * 0x10000,
    decreases data.len(),
{
    if data.len() < 2 {
    } else {
        lemma_sum16_bound(data.subrange(2, data.len() as int));
    }
}

/// One folding step: add the high and low 16 bits together. Two steps
/// always suffice to bring any `u32`-range sum down to 16 bits (proved by
/// `spec_fold16`'s callers, not assumed structurally here).
pub open spec fn spec_fold_step(x: nat) -> nat {
    if x <= 0xffff {
        x
    } else {
        x % 0x10000 + x / 0x10000
    }
}

/// The Internet checksum's carry fold, exactly two steps unrolled (see
/// `lemma_fold16_le_0xffff` for why two steps are always enough for any
/// value below `2^32`, which `spec_sum16` of an `MAX_FRAME`-bounded buffer
/// always is).
pub open spec fn spec_fold16(x: nat) -> nat {
    spec_fold_step(spec_fold_step(x))
}

proof fn lemma_u16_be_word_eq_sum16_word(b0: u8, b1: u8)
    ensures
        (((b0 as u16) << 8) | (b1 as u16)) as nat == (b0 as nat) * 0x100 + (b1 as nat),
{
    assert((((b0 as u16) << 8) | (b1 as u16)) as nat == (b0 as nat) * 0x100 + (b1 as nat)) by (
    bit_vector);
}

proof fn lemma_fold_step_le_0x1fffe(x: nat)
    requires
        x < 0x1_0000_0000,
    ensures
        spec_fold_step(x) <= 0x1fffe,
{
    if x <= 0xffff {
    } else {
        assert(x % 0x10000 <= 0xffff) by (nonlinear_arith)
            requires
                x < 0x1_0000_0000,
        {}
        assert(x / 0x10000 <= 0xffff) by (nonlinear_arith)
            requires
                x < 0x1_0000_0000,
        {}
    }
}

proof fn lemma_fold_step_le_0xffff(x: nat)
    requires
        x <= 0x1fffe,
    ensures
        spec_fold_step(x) <= 0xffff,
{
    if x <= 0xffff {
    } else {
        assert(x / 0x10000 <= 1) by (nonlinear_arith)
            requires
                x <= 0x1fffe,
        {}
        assert(x % 0x10000 <= 0xfffe) by (nonlinear_arith)
            requires
                x <= 0x1fffe,
                x > 0xffff,
        {}
    }
}

/// For any `x` representable in a `u32` (in particular any value
/// `csum_add` can ever return), two folding steps bring it to at most
/// `0xffff`: the domain `spec_fold16` is actually exact on, matching
/// `csum_fold`'s own `u32` input type (not an artificial bound).
proof fn lemma_fold16_le_0xffff(x: nat)
    requires
        x < 0x1_0000_0000,
    ensures
        spec_fold16(x) <= 0xffff,
{
    lemma_fold_step_le_0x1fffe(x);
    lemma_fold_step_le_0xffff(spec_fold_step(x));
}

/// `0xffff - spec_fold16(sum0)`, as a `u16`: what `csum_fold` computes from
/// any running sum `sum0` (an initial seed, as for the UDP pseudo-header,
/// plus the bytes actually checksummed).
pub open spec fn spec_fold_checksum(sum0: nat) -> u16
    recommends
        sum0 < 0x1_0000_0000,
{
    (0xffff - spec_fold16(sum0)) as u16
}

/// `spec_fold_checksum(spec_sum16(data))`: the value `csum_add`+`csum_fold`
/// compute over `data` alone (no initial seed). A checksum is valid
/// exactly when this is `0`.
pub open spec fn spec_checksum16(data: Seq<u8>) -> u16
    recommends
        spec_sum16(data) < 0x1_0000_0000,
{
    spec_fold_checksum(spec_sum16(data))
}

/// `data` with its 2-byte big-endian checksum field at `off` overwritten:
/// the shape every emitter uses to patch in a computed checksum.
pub open spec fn spec_patch16(data: Seq<u8>, off: int, v: u16) -> Seq<u8>
    recommends
        0 <= off,
        off + 2 <= data.len(),
{
    data.subrange(0, off) + u16_to_be(v) + data.subrange(off + 2, data.len() as int)
}

/// `data` with its byte at `off` overwritten: the shape `forward_ipv4` uses
/// to patch in the decremented TTL.
pub open spec fn spec_patch_byte(data: Seq<u8>, off: int, v: u8) -> Seq<u8>
    recommends
        0 <= off < data.len(),
{
    data.subrange(0, off) + seq![v] + data.subrange(off + 1, data.len() as int)
}

/// `spec_patch16` leaves every byte outside `[off, off + 2)` unchanged.
proof fn lemma_patch16_preserves_outside(data: Seq<u8>, off: int, v: u16, i: int)
    requires
        0 <= off,
        off + 2 <= data.len(),
        0 <= i < data.len(),
        !(off <= i < off + 2),
    ensures
        spec_patch16(data, off, v)[i] == data[i],
{
    let patched = spec_patch16(data, off, v);
    if i < off {
        assert(patched.subrange(0, off)[i] == patched[i]);
        assert(data.subrange(0, off)[i] == data[i]);
    } else {
        assert(patched.subrange(off + 2, data.len() as int)[i - off - 2] == patched[i]);
        assert(data.subrange(off + 2, data.len() as int)[i - off - 2] == data[i]);
    }
}

/// `spec_patch16` leaves a subrange disjoint from `[off, off + 2)`
/// unchanged.
proof fn lemma_patch16_preserves_subrange(data: Seq<u8>, off: int, v: u16, a: int, b: int)
    requires
        0 <= off,
        off + 2 <= data.len(),
        0 <= a <= b <= data.len(),
        b <= off || a >= off + 2,
    ensures
        spec_patch16(data, off, v).subrange(a, b) =~= data.subrange(a, b),
{
    assert forall|i: int| a <= i < b implies spec_patch16(data, off, v)[i] == data[i] by {
        lemma_patch16_preserves_outside(data, off, v, i);
    }
}

/// Writing `spec_fold_checksum(seed + spec_sum16(data))` into `data`'s own
/// (zeroed) checksum field at an even offset makes the result's checksum
/// (with the same `seed`, e.g. a UDP pseudo-header sum, or `0` for a plain
/// header) valid. This is the one fact every "compute a checksum, then
/// embed it" step in `emit` and `forward_ipv4` relies on; it is proved
/// here from `spec_sum16`'s additivity, not assumed.
proof fn lemma_checksum_embed(seed: nat, data0: Seq<u8>, off: int)
    requires
        0 <= off,
        off % 2 == 0,
        off + 2 <= data0.len(),
        data0[off] == 0,
        data0[off + 1] == 0,
        seed + spec_sum16(data0) < 0x1000_0000,
    ensures
        spec_fold_checksum(
            seed + spec_sum16(
                spec_patch16(data0, off, spec_fold_checksum(seed + spec_sum16(data0))),
            ),
        ) == 0,
{
    let p = data0.subrange(0, off);
    let z = data0.subrange(off, off + 2);
    let s = data0.subrange(off + 2, data0.len() as int);
    assert(p.len() % 2 == 0);
    assert(z.len() == 2);
    assert(z[0] == 0 && z[1] == 0);
    assert(p + (z + s) =~= data0);
    lemma_sum16_concat(p, z + s);
    lemma_sum16_concat(z, s);
    assert(spec_sum16(z) == spec_word_be16(z, 0) + spec_sum16(z.subrange(2, z.len() as int)));
    assert(z.subrange(2, z.len() as int) =~= Seq::<u8>::empty());
    assert(spec_sum16(Seq::<u8>::empty()) == 0);
    assert(spec_word_be16(z, 0) == 0);
    assert(spec_sum16(z) == 0);
    let s0 = seed + spec_sum16(data0);
    assert(s0 == seed + spec_sum16(p) + spec_sum16(s));

    let c = spec_fold_checksum(s0);
    let cb = u16_to_be(c);
    let data1 = spec_patch16(data0, off, c);
    assert(data1 =~= p + (cb + s));
    lemma_sum16_concat(p, cb + s);
    lemma_sum16_concat(cb, s);
    assert(cb.len() == 2);
    assert(spec_sum16(cb) == spec_word_be16(cb, 0) + spec_sum16(cb.subrange(2, cb.len() as int)));
    assert(cb.subrange(2, cb.len() as int) =~= Seq::<u8>::empty());
    lemma_u16_be_word_eq_sum16_word(cb[0], cb[1]);
    assert(spec_word_be16(cb, 0) == u16_from_be(cb) as nat);
    lemma_u16_be_roundtrip(c);
    assert(u16_from_be(cb) == c);
    assert(spec_sum16(cb) == c as nat);
    let s1 = seed + spec_sum16(data1);
    assert(s1 == seed + spec_sum16(p) + (spec_sum16(cb) + spec_sum16(s)));
    assert(s1 as int == s0 as int + c as int);

    lemma_fold16_le_0xffff(s0);
    let f0 = spec_fold16(s0);
    assert(f0 <= 0xffff);
    assert(c as int == 0xffff - f0 as int);
    assert(s1 as int == s0 as int + 0xffff - f0 as int);

    lemma_fold_embeds_to_0xffff(s0);
    assert(s1 == (s0 + 0xffff - f0) as nat);
    assert(spec_fold16(s1) == 0xffff);
    assert(spec_fold_checksum(s1) == (0xffff - spec_fold16(s1)) as u16);
}

/// Adding another whole `0xffff` to a sum that already folds to `0xffff`
/// keeps it at `0xffff`: the RFC 768 "send 0xffff instead of a computed
/// all-zero checksum" trick doesn't need its own embedding proof, just
/// this.
proof fn lemma_fold16_add_0xffff_preserves(s0: nat)
    requires
        s0 < 0x1000_0000,
        spec_fold16(s0) == 0xffff,
    ensures
        spec_fold16(s0 + 0xffff) == 0xffff,
{
    lemma_fold16_congruent(s0);
    lemma_fold16_congruent((s0 + 0xffff) as nat);
    lemma_fold16_le_0xffff((s0 + 0xffff) as nat);
    let f1 = spec_fold16((s0 + 0xffff) as nat);
    assert(f1 <= 0xffff);
    assert(f1 != 0) by {
        lemma_fold16_zero_iff_zero((s0 + 0xffff) as nat);
    }
    let k0 = (s0 / 0x10000) as int + (spec_fold_step(s0) / 0x10000) as int;
    let k1 = ((s0 + 0xffff) / 0x10000) as int + (spec_fold_step((s0 + 0xffff) as nat) / 0x10000)
        as int;
    assert(s0 as int - 0xffff == k0 * 0xffff);
    assert((s0 + 0xffff) as int - f1 as int == k1 * 0xffff);
    assert(f1 == 0xffff) by (nonlinear_arith)
        requires
            s0 as int - 0xffff == k0 * 0xffff,
            (s0 as int + 0xffff) - f1 as int == k1 * 0xffff,
            0 < f1 <= 0xffff,
    {}
}

/// Writing `0xffff` (rather than the embedded `spec_fold_checksum`) into a
/// zeroed checksum field also validates, when the natural embedded value
/// would have been `0` (RFC 768: a UDP checksum of `0` means "not
/// computed", so an all-zero result is sent as `0xffff` instead).
proof fn lemma_checksum_force_ffff(seed: nat, data0: Seq<u8>, off: int)
    requires
        0 <= off,
        off % 2 == 0,
        off + 2 <= data0.len(),
        data0[off] == 0,
        data0[off + 1] == 0,
        seed + spec_sum16(data0) < 0x1000_0000,
        spec_fold_checksum(seed + spec_sum16(data0)) == 0,
    ensures
        spec_fold_checksum(seed + spec_sum16(spec_patch16(data0, off, 0xffff))) == 0,
{
    let p = data0.subrange(0, off);
    let z = data0.subrange(off, off + 2);
    let s = data0.subrange(off + 2, data0.len() as int);
    assert(p.len() % 2 == 0);
    assert(z.len() == 2);
    assert(z[0] == 0 && z[1] == 0);
    assert(p + (z + s) =~= data0);
    lemma_sum16_concat(p, z + s);
    lemma_sum16_concat(z, s);
    assert(spec_sum16(z) == spec_word_be16(z, 0) + spec_sum16(z.subrange(2, z.len() as int)));
    assert(z.subrange(2, z.len() as int) =~= Seq::<u8>::empty());
    assert(spec_sum16(Seq::<u8>::empty()) == 0);
    assert(spec_word_be16(z, 0) == 0);
    assert(spec_sum16(z) == 0);
    let s0 = seed + spec_sum16(data0);
    assert(s0 == seed + spec_sum16(p) + spec_sum16(s));
    assert(spec_fold16(s0) == 0xffff);

    let cb = u16_to_be(0xffffu16);
    let data1 = spec_patch16(data0, off, 0xffff);
    assert(data1 =~= p + (cb + s));
    lemma_sum16_concat(p, cb + s);
    lemma_sum16_concat(cb, s);
    assert(cb.len() == 2);
    assert(spec_sum16(cb) == spec_word_be16(cb, 0) + spec_sum16(cb.subrange(2, cb.len() as int)));
    assert(cb.subrange(2, cb.len() as int) =~= Seq::<u8>::empty());
    lemma_u16_be_word_eq_sum16_word(cb[0], cb[1]);
    assert(spec_word_be16(cb, 0) == u16_from_be(cb) as nat);
    lemma_u16_be_roundtrip(0xffffu16);
    assert(u16_from_be(cb) == 0xffffu16);
    assert(spec_sum16(cb) == 0xffff);
    let s1 = seed + spec_sum16(data1);
    assert(s1 == seed + spec_sum16(p) + (spec_sum16(cb) + spec_sum16(s)));
    assert(s1 as int == s0 as int + 0xffff);
    assert(s1 == (s0 + 0xffff) as nat);

    lemma_fold16_add_0xffff_preserves(s0);
    assert(spec_fold16(s1) == 0xffff);
    assert(spec_fold_checksum(s1) == (0xffff - spec_fold16(s1)) as u16);
}

/// `x` and `spec_fold_step(x)` differ by an exact multiple of `0xffff`:
/// `x == (x / 0x10000) * 0xffff + spec_fold_step(x)`. This is what makes
/// the fold a reduction modulo `0xffff` (RFC 1071's ones'-complement
/// arithmetic): `2^16 == 0x10000 == 0xffff + 1`, so every carry the step
/// folds back in moves the value by a whole multiple of `0xffff`.
proof fn lemma_fold_step_congruent(x: nat)
    ensures
        x as int - spec_fold_step(x) as int == (x / 0x10000) as int * 0xffff,
{
    if x <= 0xffff {
        assert(x / 0x10000 == 0) by (nonlinear_arith)
            requires
                x <= 0xffff,
        {}
    } else {
        assert(x == (x / 0x10000) * 0x10000 + x % 0x10000) by (nonlinear_arith);
    }
}

/// `spec_fold_step(x) == 0` exactly when `x == 0` (folding never turns a
/// positive sum into zero — the Internet checksum's only all-zero result
/// comes from an all-zero input).
proof fn lemma_fold_step_zero_iff_zero(x: nat)
    ensures
        spec_fold_step(x) == 0 <==> x == 0,
{
    if x > 0xffff {
        assert(x / 0x10000 >= 1) by (nonlinear_arith)
            requires
                x > 0xffff,
        {}
    }
}

/// `spec_fold16(x) == 0` exactly when `x == 0`.
proof fn lemma_fold16_zero_iff_zero(x: nat)
    ensures
        spec_fold16(x) == 0 <==> x == 0,
{
    lemma_fold_step_zero_iff_zero(x);
    lemma_fold_step_zero_iff_zero(spec_fold_step(x));
}

/// `x` and `spec_fold16(x)` (two folding steps) also differ by an exact
/// multiple of `0xffff`, by adding the two steps' congruences.
proof fn lemma_fold16_congruent(x: nat)
    ensures
        x as int - spec_fold16(x) as int == ((x / 0x10000) as int + (
        spec_fold_step(x) / 0x10000) as int) * 0xffff,
{
    lemma_fold_step_congruent(x);
    lemma_fold_step_congruent(spec_fold_step(x));
}

/// The numeric core of `lemma_checksum_embed`: folding `s0`'s own
/// complement back into it always lands exactly on `0xffff` (the
/// ones'-complement "negative zero"), for any `s0` small enough that
/// `s0 + 0xffff` cannot itself overflow a `u32` (always true in this
/// crate: `s0` is at most `MAX_FRAME * 0x10000`, far below the bound
/// below).
proof fn lemma_fold_embeds_to_0xffff(s0: nat)
    requires
        s0 < 0x1000_0000,
    ensures
        spec_fold16((s0 + 0xffff - spec_fold16(s0)) as nat) == 0xffff,
{
    lemma_fold16_le_0xffff(s0);
    let f0 = spec_fold16(s0);
    assert(f0 <= 0xffff);
    assert(s0 as int + 0xffff - f0 as int >= 0);
    let t: nat = (s0 + 0xffff - f0) as nat;
    assert(t as int == s0 as int + 0xffff - f0 as int);
    assert(t < 0x1_0000_0000);
    // t is not 0: if it were, s0 + 0xffff == f0 <= 0xffff, forcing s0 == 0
    // and f0 == 0xffff; but s0 == 0 makes f0 == spec_fold16(0) == 0 (by
    // lemma_fold16_zero_iff_zero), a contradiction.
    if t == 0 {
        assert(s0 == 0);
        lemma_fold16_zero_iff_zero(s0);
        assert(f0 == 0);
    }
    assert(t > 0);
    // t - spec_fold16(t) is a multiple of 0xffff (lemma_fold16_congruent at
    // t), and so is s0 - f0 (same lemma at s0); t - 0xffff == s0 - f0, so
    // spec_fold16(t) is also a multiple of 0xffff.
    lemma_fold16_congruent(s0);
    lemma_fold16_congruent(t);
    lemma_fold16_le_0xffff(t);
    let ft = spec_fold16(t);
    assert(ft <= 0xffff);
    let k_s0 = (s0 / 0x10000) as int + (spec_fold_step(s0) / 0x10000) as int;
    let k_t = (t / 0x10000) as int + (spec_fold_step(t) / 0x10000) as int;
    assert(s0 as int - f0 as int == k_s0 * 0xffff);
    assert(t as int - ft as int == k_t * 0xffff);
    assert(t as int == s0 as int + 0xffff - f0 as int);
    assert(ft as int == (k_t - k_s0 - 1) * (-0xffff));
    assert((k_t - k_s0 - 1) * (-0xffff) >= 0 && (k_t - k_s0 - 1) * (-0xffff) <= 0xffff) by (
    nonlinear_arith)
        requires
            ft as int == (k_t - k_s0 - 1) * (-0xffff),
            0 <= ft <= 0xffff,
    {}
    // The only multiple of 0xffff in [0, 0xffff] besides 0 is 0xffff
    // itself, and ft != 0 since t != 0.
    lemma_fold16_zero_iff_zero(t);
    assert(ft != 0);
    assert(ft == 0xffff) by (nonlinear_arith)
        requires
            ft as int == (k_t - k_s0 - 1) * (-0xffff),
            0 < ft <= 0xffff,
    {}
}

/// One's-complement sum folded to 16 bits, over `data` plus an initial
/// sum. `data.len()` is bounded by `MAX_FRAME`, the largest buffer this
/// crate ever checksums, so the `u32` accumulator never wraps.
fn csum_add(sum0: u32, data: &[u8]) -> (sum: u32)
    requires
        data.len() <= MAX_FRAME,
        sum0 as nat <= 0x1000_0000,
    ensures
        sum as nat == sum0 as nat + spec_sum16(data@),
{
    proof {
        lemma_sum16_bound(data@);
    }
    let mut sum: u32 = sum0;
    let mut i: usize = 0;
    assert(data@.subrange(0, data@.len() as int) =~= data@);
    while i.saturating_add(1) < data.len()
        invariant
            i <= data.len(),
            data.len() <= MAX_FRAME,
            sum0 as nat <= 0x1000_0000,
            sum0 as nat + spec_sum16(data@) == sum as nat + spec_sum16(
                data@.subrange(i as int, data@.len() as int),
            ),
        decreases data.len() - i,
    {
        proof {
            lemma_sum16_bound(data@.subrange(i as int, data@.len() as int));
            lemma_sum16_bound(data@);
        }
        let pair = read_array::<2>(data, i);
        let pair = match pair {
            Some(p) => p,
            None => {
                proof {
                    assert(false);
                }
                return sum;
            },
        };
        let p0 = pair[0];
        let p1 = pair[1];
        assert(((p0 as u32) << 8) | (p1 as u32) == (p0 as u32) * 0x100 + (p1 as u32)) by (
        bit_vector);
        let word: u32 = ((p0 as u32) << 8) | (p1 as u32);
        proof {
            let suffix = data@.subrange(i as int, data@.len() as int);
            assert(suffix.len() >= 2);
            assert(suffix[0] == data@[i as int]);
            assert(suffix[1] == data@[i as int + 1]);
            assert(pair@[0] == data@[i as int]);
            assert(pair@[1] == data@[i as int + 1]);
            assert(p0 == data@[i as int]);
            assert(p1 == data@[i as int + 1]);
            assert(spec_sum16(suffix) == spec_word_be16(suffix, 0) + spec_sum16(
                suffix.subrange(2, suffix.len() as int),
            ));
            assert(suffix.subrange(2, suffix.len() as int) =~= data@.subrange(
                i as int + 2,
                data@.len() as int,
            ));
            assert((word as nat) == (p0 as nat) * 0x100 + (p1 as nat));
            assert(spec_word_be16(suffix, 0) == (p0 as nat) * 0x100 + (p1 as nat));
            assert(word as nat <= spec_sum16(suffix));
            assert(sum as nat + word as nat <= sum0 as nat + spec_sum16(data@));
            assert(spec_sum16(data@) <= (data@.len() as nat) * 0x10000);
            assert(data@.len() <= MAX_FRAME);
            lemma_mul_0x10000_le(data@.len() as nat, MAX_FRAME as nat);
            assert(sum0 as nat <= 0x1000_0000);
            assert(sum0 as nat + spec_sum16(data@) <= 0x1000_0000 + (MAX_FRAME as nat) * 0x10000);
            assert(0x1000_0000 + (MAX_FRAME as nat) * 0x10000 < 0x1_0000_0000) by (compute_only);
        }
        sum = sum.wrapping_add(word);
        i = i.saturating_add(2);
    }
    if i < data.len() {
        if let Some(b1) = read_array::<1>(data, i) {
            let b0 = b1[0];
            assert(((b0 as u32) << 8) as nat == (b0 as nat) * 0x100) by (bit_vector);
            proof {
                let suffix = data@.subrange(i as int, data@.len() as int);
                assert(suffix.len() == 1);
                assert(suffix[0] == data@[i as int]);
                assert(b1@[0] == data@[i as int]);
                assert(b0 == data@[i as int]);
                assert(spec_sum16(suffix) == (b0 as nat) * 0x100);
                assert(sum as nat + (b0 as nat) * 0x100 == sum0 as nat + spec_sum16(data@));
                assert(sum as nat + (((b0 as u32) << 8) as nat) < 0x1_0000_0000);
            }
            sum = sum.wrapping_add((b0 as u32) << 8);
            assert(sum as nat == sum0 as nat + spec_sum16(data@));
        }
    } else {
        assert(data@.subrange(i as int, data@.len() as int) =~= Seq::<u8>::empty());
        assert(sum as nat == sum0 as nat + spec_sum16(data@));
    }
    sum
}

/// Folds a 32-bit running sum to 16 bits and complements it (RFC 1071).
/// Two steps always suffice for a `u32` input (`lemma_fold16_le_0xffff`).
fn csum_fold(sum0: u32) -> (r: u16)
    ensures
        r == spec_fold_checksum(sum0 as nat),
        (r as nat) + spec_fold16(sum0 as nat) == 0xffff,
{
    let mut sum = sum0;
    if sum > 0xffff {
        assert((sum & 0xffff) as nat == sum as nat % 0x10000 && (sum >> 16) as nat == sum as nat
            / 0x10000) by (bit_vector);
        let lo = sum & 0xffff;
        let hi = sum >> 16;
        sum = lo.wrapping_add(hi);
    }
    if sum > 0xffff {
        assert((sum & 0xffff) as nat == sum as nat % 0x10000 && (sum >> 16) as nat == sum as nat
            / 0x10000) by (bit_vector);
        let lo = sum & 0xffff;
        let hi = sum >> 16;
        sum = lo.wrapping_add(hi);
    }
    assert(sum as nat == spec_fold16(sum0 as nat));
    let lo16 = sum as u16;
    assert((!lo16) as nat + lo16 as nat == 0xffff) by (bit_vector);
    !lo16
}

fn udp_pseudo_sum(src: &Ipv4, dst: &Ipv4, udp_len: u16) -> (sum: u32)
    ensures
        sum as nat == spec_sum16(src@) + spec_sum16(dst@) + (IPPROTO_UDP as nat) + (
        udp_len as nat),
{
    proof {
        lemma_sum16_bound(src@);
        lemma_sum16_bound(dst@);
    }
    let sum = csum_add(0, src);
    assert(sum as nat <= 0x1000_0000);
    let sum = csum_add(sum, dst);
    let sum = sum.wrapping_add(IPPROTO_UDP as u32);
    sum.wrapping_add(udp_len as u32)
}

// --- ARP: accepted iff `b` describes an Ethernet/IPv4 ARP request or
// reply with a valid sender (M4 plan C5). ---

pub open spec fn arp_accept(b: Seq<u8>) -> bool {
    &&& b.len() >= ARP_LEN
    &&& u16_from_be(b.subrange(0, 2)) == 1
    &&& u16_from_be(b.subrange(2, 4)) == ETHERTYPE_IPV4
    &&& b[4] == 6
    &&& b[5] == 4
    &&& (u16_from_be(b.subrange(6, 8)) == 1 || u16_from_be(b.subrange(6, 8)) == 2)
    &&& mac_valid(b.subrange(8, 14))
    &&& ipv4_valid(b.subrange(14, 18))
}

fn parse_arp(b: &[u8]) -> (r: Result<ArpPacket, DropReason>)
    ensures
        r is Ok <==> arp_accept(b@),
        r is Ok ==> {
            let m = r->Ok_0;
            &&& (u16_from_be(b@.subrange(6, 8)) == 1 ==> m.op is Request)
            &&& (u16_from_be(b@.subrange(6, 8)) == 2 ==> m.op is Reply)
            &&& m.sha@ == b@.subrange(8, 14)
            &&& m.spa@ == b@.subrange(14, 18)
            &&& m.tha@ == b@.subrange(18, 24)
            &&& m.tpa@ == b@.subrange(24, 28)
        },
{
    if b.len() < ARP_LEN {
        return Err(DropReason::TooShort);
    }
    let htype = match be16(b, 0) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    let ptype = match be16(b, 2) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    let hlen_plen = match read_array::<2>(b, 4) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    let hlen = hlen_plen[0];
    let plen = hlen_plen[1];
    let op_raw = match be16(b, 6) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    let op = if op_raw == 1 {
        ArpOp::Request
    } else if op_raw == 2 {
        ArpOp::Reply
    } else {
        return Err(DropReason::ArpMalformed);
    };
    if htype != 1 || ptype != ETHERTYPE_IPV4 || hlen != 6 || plen != 4 {
        return Err(DropReason::ArpMalformed);
    }
    let sha = match read_array::<6>(b, 8) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    let spa = match read_array::<4>(b, 14) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    let tha = match read_array::<6>(b, 18) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    let tpa = match read_array::<4>(b, 24) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    if !mac_is_valid_src(&sha) || !ipv4_is_valid_src(&spa) {
        return Err(DropReason::ArpBadSender);
    }
    Ok(ArpPacket { op, sha, spa, tha, tpa })
}

/// The bytes an Ethernet/ARP frame's `emit` describes, as a pure function
/// of the fields.
pub open spec fn spec_emit_arp(
    dst: Seq<u8>,
    src: Seq<u8>,
    op: u16,
    sha: Seq<u8>,
    spa: Seq<u8>,
    tha: Seq<u8>,
    tpa: Seq<u8>,
) -> Seq<u8> {
    dst + src + u16_to_be(ETHERTYPE_ARP) + u16_to_be(1) + u16_to_be(ETHERTYPE_IPV4) + seq![
        6u8,
        4u8,
    ] + u16_to_be(op) + sha + spa + tha + tpa
}

/// `spec_emit_arp`'s result always parses back to its own fields, under
/// an ARP body's acceptance conditions (valid sender, `op` 1 or 2).
proof fn lemma_spec_emit_arp_parses(
    dst: Seq<u8>,
    src: Seq<u8>,
    op: u16,
    sha: Seq<u8>,
    spa: Seq<u8>,
    tha: Seq<u8>,
    tpa: Seq<u8>,
)
    requires
        dst.len() == 6,
        src.len() == 6,
        sha.len() == 6,
        spa.len() == 4,
        tha.len() == 6,
        tpa.len() == 4,
        mac_valid(src),
        mac_valid(sha),
        ipv4_valid(spa),
        op == 1 || op == 2,
    ensures
        ({
            let bytes = spec_emit_arp(dst, src, op, sha, spa, tha, tpa);
            let rest = bytes.subrange(14, 42);
            &&& bytes.len() == 42
            &&& u16_from_be(bytes.subrange(12, 14)) == ETHERTYPE_ARP
            &&& eth_frame_ok(bytes, false)
            &&& eth_frame_ok(bytes, true)
            &&& bytes.subrange(0, 6) =~= dst
            &&& bytes.subrange(6, 12) =~= src
            &&& u16_from_be(rest.subrange(6, 8)) == op
            &&& rest.subrange(8, 14) =~= sha
            &&& rest.subrange(14, 18) =~= spa
            &&& rest.subrange(18, 24) =~= tha
            &&& rest.subrange(24, 28) =~= tpa
        }),
{
    let bytes = spec_emit_arp(dst, src, op, sha, spa, tha, tpa);
    assert(bytes.len() == 42);
    assert(bytes.subrange(0, 6) =~= dst);
    assert(bytes.subrange(6, 12) =~= src);
    assert(bytes.subrange(12, 14) =~= u16_to_be(ETHERTYPE_ARP));
    lemma_u16_be_roundtrip(ETHERTYPE_ARP);
    assert(u16_from_be(bytes.subrange(12, 14)) == ETHERTYPE_ARP);
    let rest = bytes.subrange(14, 42);
    assert(rest.subrange(0, 2) =~= u16_to_be(1));
    lemma_u16_be_roundtrip(1);
    assert(u16_from_be(rest.subrange(0, 2)) == 1);
    assert(rest.subrange(2, 4) =~= u16_to_be(ETHERTYPE_IPV4));
    lemma_u16_be_roundtrip(ETHERTYPE_IPV4);
    assert(u16_from_be(rest.subrange(2, 4)) == ETHERTYPE_IPV4);
    assert(rest[4] == 6);
    assert(rest[5] == 4);
    assert(rest.subrange(6, 8) =~= u16_to_be(op));
    lemma_u16_be_roundtrip(op);
    assert(u16_from_be(rest.subrange(6, 8)) == op);
    assert(rest.subrange(8, 14) =~= sha);
    assert(rest.subrange(14, 18) =~= spa);
    assert(rest.subrange(18, 24) =~= tha);
    assert(rest.subrange(24, 28) =~= tpa);
    assert(arp_accept(rest));
}

// --- IPv4 header: accepted iff version 4, no options, no fragments, the
// header checksum is valid, the source address is sane, and the total
// length fits inside the buffer (M4 plan C5: lengths, IHL, total length,
// the checksum rule, no fragments). ---

pub open spec fn ipv4_total_len(b: Seq<u8>) -> int {
    u16_from_be(b.subrange(2, 4)) as int
}

pub open spec fn ipv4_header_ok(b: Seq<u8>) -> bool {
    &&& b.len() >= IPV4_HDR
    &&& (b[0] >> 4) == 4
    &&& (b[0] & 0x0f) == 5
    &&& (u16_from_be(b.subrange(6, 8)) & 0xbfff) == 0
    &&& ipv4_total_len(b) >= IPV4_HDR
    &&& ipv4_total_len(b) <= b.len()
    &&& spec_checksum16(b.subrange(0, IPV4_HDR as int)) == 0
    &&& ipv4_valid(b.subrange(12, 16))
}

/// Shared IPv4 checks; returns `(header, datagram up to total_len)`.
fn ipv4_header(b: &[u8]) -> (r: Result<(&[u8], &[u8]), DropReason>)
    requires
        b.len() <= MAX_FRAME,
    ensures
        r is Ok <==> ipv4_header_ok(b@),
        r is Ok ==> {
            let (hdr, packet) = r->Ok_0;
            &&& hdr@ == b@.subrange(0, IPV4_HDR as int)
            &&& packet@ == b@.subrange(0, ipv4_total_len(b@))
        },
{
    let hdr = match b.get(..IPV4_HDR) {
        Some(h) => h,
        None => return Err(DropReason::TooShort),
    };
    let ver_ihl_arr = match read_array::<1>(hdr, 0) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    let ver_ihl = ver_ihl_arr[0];
    let total_len_raw = match be16(hdr, 2) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    let frag = match be16(hdr, 6) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    if ver_ihl >> 4 != 4 {
        return Err(DropReason::Ipv4Version);
    }
    if ver_ihl & 0x0f != 5 {
        return Err(DropReason::Ipv4Options);
    }
    // Reserved bit, MF, and fragment offset must all be zero; DF is allowed.
    if frag & 0xbfff != 0 {
        return Err(DropReason::Ipv4Fragment);
    }
    let total_len = total_len_raw as usize;
    // Trailing bytes beyond total_len are Ethernet padding and are ignored.
    if total_len < IPV4_HDR || total_len > b.len() {
        return Err(DropReason::Ipv4BadLength);
    }
    proof {
        lemma_sum16_bound(hdr@);
    }
    let c = csum_add(0, hdr);
    let folded = csum_fold(c);
    assert(folded == spec_checksum16(hdr@));
    if folded != 0 {
        return Err(DropReason::Ipv4BadChecksum);
    }
    let src = match read_array::<4>(hdr, 12) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    if !ipv4_is_valid_src(&src) {
        return Err(DropReason::Ipv4BadSrc);
    }
    match b.get(..total_len) {
        Some(packet) => Ok((hdr, packet)),
        None => Err(DropReason::Ipv4BadLength),
    }
}

/// Validates an IPv4 header (no options, no fragments, checksum, sane
/// source) and returns the datagram trimmed to its total length. Also the
/// entry point for decrypted tunnel payloads.
pub fn parse_ipv4_packet(b: &[u8]) -> (r: Result<Ip4Packet<'_>, DropReason>)
    requires
        b.len() <= MAX_FRAME,
    ensures
        r is Ok <==> ipv4_header_ok(b@),
        r is Ok ==> {
            let p = r->Ok_0;
            &&& p.src@ == b@.subrange(12, 16)
            &&& p.dst@ == b@.subrange(16, 20)
            &&& p.proto == b@[9]
            &&& p.packet@ == b@.subrange(0, ipv4_total_len(b@))
        },
{
    let (hdr, packet) = ipv4_header(b)?;
    let src = match read_array::<4>(hdr, 12) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    let dst = match read_array::<4>(hdr, 16) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    let proto_arr = match read_array::<1>(hdr, 9) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    let proto = proto_arr[0];
    Ok(Ip4Packet { src, dst, proto, packet })
}

// --- UDP over IPv4: accepted iff the IPv4 header is accepted, the
// protocol is UDP, the UDP length matches the datagram exactly, and the
// checksum (over the pseudo-header, RFC 768) is valid or zero ("not
// computed"). ---

pub open spec fn udp4_accept(packet: Seq<u8>) -> bool {
    &&& packet.len() >= IPV4_HDR + UDP_HDR
    &&& packet[9] == IPPROTO_UDP
    &&& {
        let udp = packet.subrange(IPV4_HDR as int, packet.len() as int);
        let udp_len = u16_from_be(udp.subrange(4, 6));
        let udp_csum = u16_from_be(udp.subrange(6, 8));
        &&& udp_len as int == udp.len()
        &&& udp.len() >= UDP_HDR
        &&& (udp_csum == 0 || spec_fold_checksum(
            spec_sum16(packet.subrange(12, 16)) + spec_sum16(packet.subrange(16, 20)) + (
            IPPROTO_UDP as nat) + (udp_len as nat) + spec_sum16(udp),
        ) == 0)
    }
}

fn parse_ipv4_udp(b: &[u8]) -> (r: Result<Udp4<'_>, DropReason>)
    requires
        b.len() <= MAX_FRAME,
    ensures
        r is Ok <==> (ipv4_header_ok(b@) && udp4_accept(
            b@.subrange(0, ipv4_total_len(b@)),
        )),
        r is Ok ==> {
            let u = r->Ok_0;
            let packet = b@.subrange(0, ipv4_total_len(b@));
            let udp = packet.subrange(IPV4_HDR as int, packet.len() as int);
            &&& u.src@ == packet.subrange(12, 16)
            &&& u.dst@ == packet.subrange(16, 20)
            &&& u.sport == u16_from_be(udp.subrange(0, 2))
            &&& u.dport == u16_from_be(udp.subrange(2, 4))
            &&& u.payload@ == udp.subrange(UDP_HDR as int, udp.len() as int)
        },
{
    let p = parse_ipv4_packet(b)?;
    let ghost packet = b@.subrange(0, ipv4_total_len(b@));
    assert(p.packet@ == packet);
    assert(packet[9] == b@[9]);
    assert(packet.subrange(12, 16) =~= b@.subrange(12, 16));
    assert(packet.subrange(16, 20) =~= b@.subrange(16, 20));
    if p.proto != IPPROTO_UDP {
        return Err(DropReason::NotUdp);
    }
    let udp = match p.packet.get(IPV4_HDR..) {
        Some(u) => u,
        None => return Err(DropReason::Ipv4BadLength),
    };
    assert(udp@ == packet.subrange(IPV4_HDR as int, packet.len() as int));
    let sport = match be16(udp, 0) {
        Some(v) => v,
        None => return Err(DropReason::UdpBadLength),
    };
    let dport = match be16(udp, 2) {
        Some(v) => v,
        None => return Err(DropReason::UdpBadLength),
    };
    let udp_len = match be16(udp, 4) {
        Some(v) => v,
        None => return Err(DropReason::UdpBadLength),
    };
    let udp_csum = match be16(udp, 6) {
        Some(v) => v,
        None => return Err(DropReason::UdpBadLength),
    };
    if udp_len as usize != udp.len() || udp.len() < UDP_HDR {
        return Err(DropReason::UdpBadLength);
    }
    // A zero checksum means "not computed" in IPv4.
    if udp_csum != 0 {
        proof {
            lemma_sum16_bound(p.src@);
            lemma_sum16_bound(p.dst@);
            lemma_sum16_bound(udp@);
        }
        let pseudo = udp_pseudo_sum(&p.src, &p.dst, udp_len);
        assert(pseudo as nat <= 0x1000_0000);
        assert(udp.len() <= MAX_FRAME);
        let c = csum_add(pseudo, udp);
        let folded = csum_fold(c);
        assert(folded == spec_fold_checksum(
            spec_sum16(p.src@) + spec_sum16(p.dst@) + (IPPROTO_UDP as nat) + (udp_len as nat)
                + spec_sum16(udp@),
        ));
        if folded != 0 {
            return Err(DropReason::UdpBadChecksum);
        }
    }
    let payload = match udp.get(UDP_HDR..) {
        Some(pl) => pl,
        None => return Err(DropReason::UdpBadLength),
    };
    Ok(Udp4 { src: p.src, dst: p.dst, sport, dport, payload })
}

/// The bytes `emit`'s IPv4/UDP body describes, as a pure function of the
/// fields: the IPv4 header (checksummed) followed by the UDP header
/// (pseudo-header checksummed, RFC 768) and the payload.
pub open spec fn spec_emit_ip_udp(
    ip_src: Seq<u8>,
    ip_dst: Seq<u8>,
    sport: u16,
    dport: u16,
    payload: Seq<u8>,
) -> Seq<u8>
    recommends
        ip_src.len() == 4,
        ip_dst.len() == 4,
        payload.len() <= MAX_UDP_PAYLOAD,
{
    let udp_len = (UDP_HDR + payload.len()) as u16;
    let total_len = (IPV4_HDR + UDP_HDR + payload.len()) as u16;
    let ip_pre = seq![0x45u8, 0u8] + u16_to_be(total_len) + seq![
        0u8,
        0u8,
        0x40u8,
        0u8,
        64u8,
        IPPROTO_UDP,
        0u8,
        0u8,
    ] + ip_src + ip_dst;
    let ip_csum = spec_checksum16(ip_pre);
    let ip_hdr = spec_patch16(ip_pre, 10, ip_csum);
    let udp_pre = u16_to_be(sport) + u16_to_be(dport) + u16_to_be(udp_len) + seq![0u8, 0u8]
        + payload;
    let seed = spec_sum16(ip_src) + spec_sum16(ip_dst) + (IPPROTO_UDP as nat) + (udp_len as nat);
    let udp_csum0 = spec_fold_checksum(seed + spec_sum16(udp_pre));
    let udp_hdr = if udp_csum0 == 0 {
        spec_patch16(udp_pre, 6, 0xffff)
    } else {
        spec_patch16(udp_pre, 6, udp_csum0)
    };
    ip_hdr + udp_hdr
}

/// `spec_emit_ip_udp`'s result always parses back to its own fields,
/// under a UDP body's acceptance conditions (valid IPv4 source, payload
/// within the MTU).
proof fn lemma_spec_emit_ip_udp_parses(
    ip_src: Seq<u8>,
    ip_dst: Seq<u8>,
    sport: u16,
    dport: u16,
    payload: Seq<u8>,
)
    requires
        ip_src.len() == 4,
        ip_dst.len() == 4,
        ipv4_valid(ip_src),
        payload.len() <= MAX_UDP_PAYLOAD,
    ensures
        ({
            let rest = spec_emit_ip_udp(ip_src, ip_dst, sport, dport, payload);
            let total_len = (IPV4_HDR + UDP_HDR + payload.len()) as int;
            &&& rest.len() == total_len
            &&& ipv4_header_ok(rest)
            &&& ipv4_total_len(rest) == total_len
            &&& udp4_accept(rest)
            &&& rest.subrange(12, 16) =~= ip_src
            &&& rest.subrange(16, 20) =~= ip_dst
            &&& u16_from_be(rest.subrange(20, 22)) == sport
            &&& u16_from_be(rest.subrange(22, 24)) == dport
            &&& rest.subrange(28, total_len) =~= payload
        }),
{
    let udp_len = (UDP_HDR + payload.len()) as u16;
    let total_len_u16 = (IPV4_HDR + UDP_HDR + payload.len()) as u16;
    let total_len = (IPV4_HDR + UDP_HDR + payload.len()) as int;
    assert(udp_len as int == UDP_HDR + payload.len());
    assert(total_len_u16 as int == total_len);

    let ip_pre = seq![0x45u8, 0u8] + u16_to_be(total_len_u16) + seq![
        0u8,
        0u8,
        0x40u8,
        0u8,
        64u8,
        IPPROTO_UDP,
        0u8,
        0u8,
    ] + ip_src + ip_dst;
    assert(ip_pre.len() == 20);
    lemma_sum16_bound(ip_pre);
    assert(ip_pre[10] == 0 && ip_pre[11] == 0);
    let ip_csum = spec_checksum16(ip_pre);
    lemma_checksum_embed(0, ip_pre, 10);
    let ip_hdr = spec_patch16(ip_pre, 10, ip_csum);
    assert(spec_checksum16(ip_hdr) == 0);
    assert(ip_hdr.len() == 20);

    let udp_pre = u16_to_be(sport) + u16_to_be(dport) + u16_to_be(udp_len) + seq![0u8, 0u8]
        + payload;
    assert(udp_pre.len() == UDP_HDR + payload.len());
    assert(udp_pre[6] == 0 && udp_pre[7] == 0);
    let seed = spec_sum16(ip_src) + spec_sum16(ip_dst) + (IPPROTO_UDP as nat) + (udp_len as nat);
    lemma_sum16_bound(ip_src);
    lemma_sum16_bound(ip_dst);
    lemma_sum16_bound(udp_pre);
    assert(seed + spec_sum16(udp_pre) < 0x1000_0000);
    let udp_csum0 = spec_fold_checksum(seed + spec_sum16(udp_pre));
    let udp_hdr = if udp_csum0 == 0 {
        lemma_checksum_force_ffff(seed, udp_pre, 6);
        spec_patch16(udp_pre, 6, 0xffff)
    } else {
        lemma_checksum_embed(seed, udp_pre, 6);
        spec_patch16(udp_pre, 6, udp_csum0)
    };
    assert(spec_fold_checksum(seed + spec_sum16(udp_hdr)) == 0);
    assert(udp_hdr.len() == UDP_HDR + payload.len());

    let rest = ip_hdr + udp_hdr;
    assert(rest =~= spec_emit_ip_udp(ip_src, ip_dst, sport, dport, payload));
    assert(rest.len() == total_len);
    assert(rest.subrange(0, 20) =~= ip_hdr);
    assert(rest.subrange(20, total_len) =~= udp_hdr);

    // --- IPv4 header ---
    lemma_patch16_preserves_outside(ip_pre, 10, ip_csum, 0);
    assert(ip_pre[0] == 0x45);
    assert(rest[0] == ip_hdr[0]);
    let ghost b0: u8 = rest[0];
    assert(b0 == 0x45);
    assert((b0 >> 4) == 4) by (bit_vector)
        requires
            b0 == 0x45,
    ;
    assert((b0 & 0x0f) == 5) by (bit_vector)
        requires
            b0 == 0x45,
    ;

    lemma_patch16_preserves_outside(ip_pre, 10, ip_csum, 6);
    lemma_patch16_preserves_outside(ip_pre, 10, ip_csum, 7);
    assert(ip_pre.subrange(4, 12) =~= seq![0u8, 0u8, 0x40u8, 0u8, 64u8, IPPROTO_UDP, 0u8, 0u8]);
    assert(ip_pre[6] == ip_pre.subrange(4, 12)[2]);
    assert(ip_pre[7] == ip_pre.subrange(4, 12)[3]);
    assert(ip_pre[6] == 0x40);
    assert(ip_pre[7] == 0);
    assert(ip_hdr[6] == ip_pre[6]);
    assert(ip_hdr[7] == ip_pre[7]);
    assert(rest.subrange(0, 20) =~= ip_hdr);
    assert(rest[6] == ip_hdr[6]);
    assert(rest[7] == ip_hdr[7]);
    assert(rest.subrange(6, 8)[0] == rest[6]);
    assert(rest.subrange(6, 8)[1] == rest[7]);
    assert(u16_from_be(rest.subrange(6, 8)) == ((rest[6] as u16) << 8) | (rest[7] as u16));
    assert((((0x40u8) as u16) << 8) | ((0u8) as u16) == 0x4000) by (bit_vector);
    assert(u16_from_be(rest.subrange(6, 8)) == 0x4000);
    assert((0x4000u16 & 0xbfff) == 0) by (bit_vector);

    lemma_patch16_preserves_subrange(ip_pre, 10, ip_csum, 2, 4);
    assert(rest.subrange(2, 4) =~= ip_hdr.subrange(2, 4));
    assert(ip_hdr.subrange(2, 4) =~= ip_pre.subrange(2, 4));
    assert(ip_pre.subrange(2, 4) =~= u16_to_be(total_len_u16));
    lemma_u16_be_roundtrip(total_len_u16);
    assert(ipv4_total_len(rest) == total_len_u16 as int);

    assert(spec_checksum16(rest.subrange(0, IPV4_HDR as int)) == 0);

    lemma_patch16_preserves_subrange(ip_pre, 10, ip_csum, 12, 20);
    assert(rest.subrange(12, 20) =~= ip_hdr.subrange(12, 20));
    assert(ip_hdr.subrange(12, 20) =~= ip_pre.subrange(12, 20));
    assert(ip_pre.subrange(12, 16) =~= ip_src);
    assert(ip_pre.subrange(16, 20) =~= ip_dst);
    assert(rest.subrange(12, 16) =~= ip_src);
    assert(rest.subrange(16, 20) =~= ip_dst);

    assert(ipv4_header_ok(rest));

    // --- UDP ---
    lemma_patch16_preserves_outside(ip_pre, 10, ip_csum, 9);
    assert(ip_pre[9] == IPPROTO_UDP);
    assert(rest[9] == IPPROTO_UDP);

    let ghost udp = rest.subrange(IPV4_HDR as int, rest.len() as int);
    assert(udp =~= udp_hdr);

    let udp_csum_field = if udp_csum0 == 0 {
        0xffffu16
    } else {
        udp_csum0
    };
    lemma_patch16_preserves_subrange(udp_pre, 6, udp_csum_field, 0, 6);
    assert(udp.subrange(0, 6) =~= udp_hdr.subrange(0, 6));
    assert(udp_hdr.subrange(0, 6) =~= udp_pre.subrange(0, 6));
    assert(udp_pre.subrange(0, 2) =~= u16_to_be(sport));
    assert(udp_pre.subrange(2, 4) =~= u16_to_be(dport));
    assert(udp_pre.subrange(4, 6) =~= u16_to_be(udp_len));
    lemma_u16_be_roundtrip(sport);
    lemma_u16_be_roundtrip(dport);
    lemma_u16_be_roundtrip(udp_len);
    assert(u16_from_be(udp.subrange(0, 2)) == sport);
    assert(u16_from_be(udp.subrange(2, 4)) == dport);
    assert(u16_from_be(udp.subrange(4, 6)) == udp_len);
    assert(udp_len as int == udp.len());
    assert(udp.len() >= UDP_HDR);

    assert(rest.subrange(20, 22) =~= udp.subrange(0, 2));
    assert(rest.subrange(22, 24) =~= udp.subrange(2, 4));
    assert(u16_from_be(rest.subrange(20, 22)) == sport);
    assert(u16_from_be(rest.subrange(22, 24)) == dport);

    assert(spec_sum16(rest.subrange(12, 16)) == spec_sum16(ip_src));
    assert(spec_sum16(rest.subrange(16, 20)) == spec_sum16(ip_dst));
    assert(spec_fold_checksum(
        spec_sum16(rest.subrange(12, 16)) + spec_sum16(rest.subrange(16, 20)) + (
        IPPROTO_UDP as nat) + (u16_from_be(udp.subrange(4, 6)) as nat) + spec_sum16(udp),
    ) == 0);

    assert(udp4_accept(rest));

    lemma_patch16_preserves_subrange(
        udp_pre,
        6,
        udp_csum_field,
        UDP_HDR as int,
        udp_pre.len() as int,
    );
    assert(udp.subrange(UDP_HDR as int, udp.len() as int) =~= udp_hdr.subrange(
        UDP_HDR as int,
        udp_hdr.len() as int,
    ));
    assert(udp_hdr.subrange(UDP_HDR as int, udp_hdr.len() as int) =~= udp_pre.subrange(
        UDP_HDR as int,
        udp_pre.len() as int,
    ));
    assert(udp_pre.subrange(UDP_HDR as int, udp_pre.len() as int) =~= payload);
    assert(rest.subrange(28, total_len) =~= udp.subrange(UDP_HDR as int, udp.len() as int));
}

// --- Ethernet: ARP, or IPv4/UDP (outside NIC) / any IPv4 (inside NIC).
// Accepted iff the header is readable, the source address is sane, and
// the ethertype's own body is accepted (M4 plan C5). ---

pub open spec fn eth_frame_ok(b: Seq<u8>, any_ip: bool) -> bool {
    &&& b.len() <= MAX_FRAME
    &&& b.len() >= ETH_HDR
    &&& mac_valid(b.subrange(6, 12))
    &&& {
        let ethertype = u16_from_be(b.subrange(12, 14));
        let rest = b.subrange(ETH_HDR as int, b.len() as int);
        if ethertype == ETHERTYPE_ARP {
            arp_accept(rest)
        } else if ethertype == ETHERTYPE_IPV4 {
            if any_ip {
                ipv4_header_ok(rest)
            } else {
                ipv4_header_ok(rest) && udp4_accept(rest.subrange(0, ipv4_total_len(rest)))
            }
        } else {
            false
        }
    }
}

fn parse_eth(b: &[u8], any_ip: bool) -> (r: Result<Frame<'_>, DropReason>)
    ensures
        r is Ok <==> eth_frame_ok(b@, any_ip),
        r is Ok ==> {
            let f = r->Ok_0;
            let ethertype = u16_from_be(b@.subrange(12, 14));
            let rest = b@.subrange(ETH_HDR as int, b@.len() as int);
            &&& f.eth.dst@ == b@.subrange(0, 6)
            &&& f.eth.src@ == b@.subrange(6, 12)
            &&& (ethertype == ETHERTYPE_ARP ==> {
                &&& f.body is Arp
                &&& (u16_from_be(rest.subrange(6, 8)) == 1 ==> f.body->Arp_0.op is Request)
                &&& (u16_from_be(rest.subrange(6, 8)) == 2 ==> f.body->Arp_0.op is Reply)
                &&& f.body->Arp_0.sha@ == rest.subrange(8, 14)
                &&& f.body->Arp_0.spa@ == rest.subrange(14, 18)
                &&& f.body->Arp_0.tha@ == rest.subrange(18, 24)
                &&& f.body->Arp_0.tpa@ == rest.subrange(24, 28)
            })
            &&& (ethertype == ETHERTYPE_IPV4 && any_ip ==> {
                &&& f.body is Ipv4
                &&& f.body->Ipv4_0.src@ == rest.subrange(12, 16)
                &&& f.body->Ipv4_0.dst@ == rest.subrange(16, 20)
                &&& f.body->Ipv4_0.proto == rest[9]
                &&& f.body->Ipv4_0.packet@ == rest.subrange(0, ipv4_total_len(rest))
            })
            &&& (ethertype == ETHERTYPE_IPV4 && !any_ip ==> {
                let packet = rest.subrange(0, ipv4_total_len(rest));
                let udp = packet.subrange(IPV4_HDR as int, packet.len() as int);
                &&& f.body is Udp4
                &&& f.body->Udp4_0.src@ == packet.subrange(12, 16)
                &&& f.body->Udp4_0.dst@ == packet.subrange(16, 20)
                &&& f.body->Udp4_0.sport == u16_from_be(udp.subrange(0, 2))
                &&& f.body->Udp4_0.dport == u16_from_be(udp.subrange(2, 4))
                &&& f.body->Udp4_0.payload@ == udp.subrange(UDP_HDR as int, udp.len() as int)
            })
        },
{
    if b.len() > MAX_FRAME {
        return Err(DropReason::TooLong);
    }
    let dst = match read_array::<6>(b, 0) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    let src = match read_array::<6>(b, 6) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    let ethertype = match be16(b, 12) {
        Some(v) => v,
        None => return Err(DropReason::TooShort),
    };
    if !mac_is_valid_src(&src) {
        return Err(DropReason::EthBadSrc);
    }
    let eth = EthAddrs { src, dst };
    let rest = match b.get(ETH_HDR..) {
        Some(r) => r,
        None => return Err(DropReason::TooShort),
    };
    assert(rest.len() <= MAX_FRAME);
    let body = if ethertype == ETHERTYPE_ARP {
        Body::Arp(parse_arp(rest)?)
    } else if ethertype == ETHERTYPE_IPV4 {
        if any_ip {
            Body::Ipv4(parse_ipv4_packet(rest)?)
        } else {
            Body::Udp4(parse_ipv4_udp(rest)?)
        }
    } else {
        return Err(DropReason::UnknownEtherType);
    };
    Ok(Frame { eth, body })
}

/// Outside NIC: ARP or IPv4/UDP.
pub fn parse_frame(b: &[u8]) -> (r: Result<Frame<'_>, DropReason>)
    ensures
        r is Ok <==> eth_frame_ok(b@, false),
        r is Ok ==> {
            let f = r->Ok_0;
            let ethertype = u16_from_be(b@.subrange(12, 14));
            let rest = b@.subrange(ETH_HDR as int, b@.len() as int);
            &&& f.eth.dst@ == b@.subrange(0, 6)
            &&& f.eth.src@ == b@.subrange(6, 12)
            &&& (ethertype == ETHERTYPE_ARP ==> {
                &&& f.body is Arp
                &&& (u16_from_be(rest.subrange(6, 8)) == 1 ==> f.body->Arp_0.op is Request)
                &&& (u16_from_be(rest.subrange(6, 8)) == 2 ==> f.body->Arp_0.op is Reply)
                &&& f.body->Arp_0.sha@ == rest.subrange(8, 14)
                &&& f.body->Arp_0.spa@ == rest.subrange(14, 18)
                &&& f.body->Arp_0.tha@ == rest.subrange(18, 24)
                &&& f.body->Arp_0.tpa@ == rest.subrange(24, 28)
            })
            &&& (ethertype == ETHERTYPE_IPV4 ==> {
                let packet = rest.subrange(0, ipv4_total_len(rest));
                let udp = packet.subrange(IPV4_HDR as int, packet.len() as int);
                &&& f.body is Udp4
                &&& f.body->Udp4_0.src@ == packet.subrange(12, 16)
                &&& f.body->Udp4_0.dst@ == packet.subrange(16, 20)
                &&& f.body->Udp4_0.sport == u16_from_be(udp.subrange(0, 2))
                &&& f.body->Udp4_0.dport == u16_from_be(udp.subrange(2, 4))
                &&& f.body->Udp4_0.payload@ == udp.subrange(UDP_HDR as int, udp.len() as int)
            })
        },
{
    parse_eth(b, false)
}

/// Inside NIC: ARP or IPv4 of any protocol (as `Body::Ipv4`).
pub fn parse_frame_ip(b: &[u8]) -> (r: Result<Frame<'_>, DropReason>)
    ensures
        r is Ok <==> eth_frame_ok(b@, true),
        r is Ok ==> {
            let f = r->Ok_0;
            let ethertype = u16_from_be(b@.subrange(12, 14));
            let rest = b@.subrange(ETH_HDR as int, b@.len() as int);
            &&& f.eth.dst@ == b@.subrange(0, 6)
            &&& f.eth.src@ == b@.subrange(6, 12)
            &&& (ethertype == ETHERTYPE_ARP ==> {
                &&& f.body is Arp
                &&& (u16_from_be(rest.subrange(6, 8)) == 1 ==> f.body->Arp_0.op is Request)
                &&& (u16_from_be(rest.subrange(6, 8)) == 2 ==> f.body->Arp_0.op is Reply)
                &&& f.body->Arp_0.sha@ == rest.subrange(8, 14)
                &&& f.body->Arp_0.spa@ == rest.subrange(14, 18)
                &&& f.body->Arp_0.tha@ == rest.subrange(18, 24)
                &&& f.body->Arp_0.tpa@ == rest.subrange(24, 28)
            })
            &&& (ethertype == ETHERTYPE_IPV4 ==> {
                &&& f.body is Ipv4
                &&& f.body->Ipv4_0.src@ == rest.subrange(12, 16)
                &&& f.body->Ipv4_0.dst@ == rest.subrange(16, 20)
                &&& f.body->Ipv4_0.proto == rest[9]
                &&& f.body->Ipv4_0.packet@ == rest.subrange(0, ipv4_total_len(rest))
            })
        },
{
    parse_eth(b, true)
}

// --- Forwarding: decrement the TTL, refuse TTL <= 1, recompute the
// header checksum (RFC 1812 section 5.3.1, M4 plan C5). ---

/// The bytes `forward_ipv4` writes, as a pure function of the input.
pub open spec fn spec_forward_ipv4(packet: Seq<u8>) -> Seq<u8>
    recommends
        ipv4_header_ok(packet),
        packet[8] > 1,
{
    let trimmed = packet.subrange(0, ipv4_total_len(packet));
    let new_ttl = (trimmed[8] - 1) as u8;
    let with_ttl = spec_patch_byte(trimmed, 8, new_ttl);
    let zeroed = spec_patch16(with_ttl, 10, 0);
    let csum = spec_checksum16(zeroed.subrange(0, IPV4_HDR as int));
    spec_patch16(zeroed, 10, csum)
}

/// Copies a datagram accepted by `parse_ipv4_packet` into `out` with its
/// TTL decremented and the header checksum recomputed, as a router must
/// before forwarding (RFC 1812 section 5.3.1). TTL 0 or 1 is refused, so a
/// routing loop through the gateway dies out. Returns the length written.
pub fn forward_ipv4(packet: &[u8], out: &mut [u8]) -> (r: Result<usize, DropReason>)
    requires
        packet.len() <= MAX_FRAME,
    ensures
        r is Ok <==> (ipv4_header_ok(packet@) && packet@[8] > 1 && old(out)@.len()
            >= ipv4_total_len(packet@)),
        r is Ok ==> {
            let n = r->Ok_0;
            &&& n == ipv4_total_len(packet@)
            &&& final(out)@.subrange(0, n as int) == spec_forward_ipv4(packet@)
        },
{
    let p = parse_ipv4_packet(packet)?;
    let len = p.packet.len();
    let ghost trimmed = packet@.subrange(0, ipv4_total_len(packet@));
    assert(p.packet@ == trimmed);
    assert(len == trimmed.len());
    if write_at(out, 0, p.packet).is_none() {
        return Err(DropReason::TooLong);
    }
    assert(out@.subrange(0, len as int) =~= trimmed);
    let ttl = match read_array::<1>(out, 8) {
        Some(v) => v[0],
        None => return Err(DropReason::TooShort),
    };
    assert(ttl == trimmed[8]);
    if ttl <= 1 {
        return Err(DropReason::TtlExpired);
    }
    let new_ttl = ttl.saturating_sub(1);
    if write_at(out, 8, &[new_ttl]).is_none() {
        return Err(DropReason::TooShort);
    }
    let ghost with_ttl = spec_patch_byte(trimmed, 8, new_ttl);
    assert(out@.subrange(0, len as int) =~= with_ttl);
    if write_at(out, 10, &u16_to_be_arr(0)).is_none() {
        return Err(DropReason::TooShort);
    }
    let ghost zeroed = spec_patch16(with_ttl, 10, 0);
    assert(out@.subrange(0, len as int) =~= zeroed);
    proof {
        lemma_sum16_bound(out@.subrange(0, IPV4_HDR as int));
    }
    let hdr = match out.get(..IPV4_HDR) {
        Some(h) => h,
        None => return Err(DropReason::TooShort),
    };
    assert(hdr@ == zeroed.subrange(0, IPV4_HDR as int));
    let c = csum_add(0, hdr);
    let csum = csum_fold(c);
    assert(csum == spec_checksum16(zeroed.subrange(0, IPV4_HDR as int)));
    if write_at(out, 10, &u16_to_be_arr(csum)).is_none() {
        return Err(DropReason::TooShort);
    }
    assert(out@.subrange(0, len as int) =~= spec_patch16(zeroed, 10, csum));
    assert(out@.subrange(0, len as int) =~= spec_forward_ipv4(packet@));
    Ok(len)
}

// --- emit: the inverse of `parse_frame`/`parse_frame_ip` (M4 plan C5).
// `Body::Ipv4` is emitted verbatim, under the precondition that it is
// exactly what `parse_ipv4_packet` would itself produce. ---

/// Writes `f` into `out` and returns the frame length. Checksums are
/// computed.
pub fn emit(f: &Frame<'_>, out: &mut [u8]) -> (r: Result<usize, EmitError>)
    ensures
        final(out)@.len() == old(out)@.len(),
        f.body is Arp ==> {
            let a = f.body->Arp_0;
            let op: u16 = if a.op is Request {
                1
            } else {
                2
            };
            &&& r is Ok <==> (mac_valid(f.eth.src@) && mac_valid(a.sha@) && ipv4_valid(a.spa@)
                && old(out)@.len() >= ETH_HDR + ARP_LEN)
            &&& r is Ok ==> {
                &&& r->Ok_0 == ETH_HDR + ARP_LEN
                &&& final(out)@.subrange(0, r->Ok_0 as int) == spec_emit_arp(
                    f.eth.dst@,
                    f.eth.src@,
                    op,
                    a.sha@,
                    a.spa@,
                    a.tha@,
                    a.tpa@,
                )
            }
        },
        f.body is Udp4 ==> {
            let u = f.body->Udp4_0;
            &&& r is Ok <==> (mac_valid(f.eth.src@) && ipv4_valid(u.src@) && u.payload@.len()
                <= MAX_UDP_PAYLOAD && old(out)@.len() >= (ETH_HDR + IPV4_HDR + UDP_HDR)
                + u.payload@.len())
            &&& r is Ok ==> {
                &&& r->Ok_0 == (ETH_HDR + IPV4_HDR + UDP_HDR) + u.payload@.len()
                &&& final(out)@.subrange(0, r->Ok_0 as int) == f.eth.dst@ + f.eth.src@
                    + u16_to_be(ETHERTYPE_IPV4) + spec_emit_ip_udp(
                    u.src@,
                    u.dst@,
                    u.sport,
                    u.dport,
                    u.payload@,
                )
            }
        },
        f.body is Ipv4 ==> {
            let p = f.body->Ipv4_0;
            &&& r is Ok <==> (mac_valid(f.eth.src@) && p.packet@.len() <= MAX_FRAME - ETH_HDR
                && ipv4_header_ok(p.packet@) && p.src@ == p.packet@.subrange(12, 16) && p.dst@
                == p.packet@.subrange(16, 20) && p.proto == p.packet@[9] && p.packet@
                == p.packet@.subrange(0, ipv4_total_len(p.packet@)) && old(out)@.len()
                >= ETH_HDR + p.packet@.len())
            &&& r is Ok ==> {
                &&& r->Ok_0 == ETH_HDR + p.packet@.len()
                &&& final(out)@.subrange(0, r->Ok_0 as int) == f.eth.dst@ + f.eth.src@
                    + u16_to_be(ETHERTYPE_IPV4) + p.packet@
            }
        },
{
    if !mac_is_valid_src(&f.eth.src) {
        return Err(EmitError::Invalid);
    }
    match &f.body {
        Body::Arp(a) => {
            if !mac_is_valid_src(&a.sha) || !ipv4_is_valid_src(&a.spa) {
                return Err(EmitError::Invalid);
            }
            let len = ETH_HDR + ARP_LEN;
            let op: u16 = match a.op {
                ArpOp::Request => 1,
                ArpOp::Reply => 2,
            };
            if write_at(out, 0, &f.eth.dst).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 6, &f.eth.src).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 12, &u16_to_be_arr(ETHERTYPE_ARP)).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 14, &u16_to_be_arr(1)).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 16, &u16_to_be_arr(ETHERTYPE_IPV4)).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 18, &[6, 4]).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 20, &u16_to_be_arr(op)).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 22, &a.sha).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 28, &a.spa).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 32, &a.tha).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 38, &a.tpa).is_none() {
                return Err(EmitError::TooSmall);
            }
            assert(out@.subrange(0, len as int) =~= spec_emit_arp(
                f.eth.dst@,
                f.eth.src@,
                op,
                a.sha@,
                a.spa@,
                a.tha@,
                a.tpa@,
            ));
            Ok(len)
        },
        Body::Udp4(u) => {
            if !ipv4_is_valid_src(&u.src) || u.payload.len() > MAX_UDP_PAYLOAD {
                return Err(EmitError::Invalid);
            }
            let udp_len = UDP_HDR.saturating_add(u.payload.len()) as u16;
            let total_len = (IPV4_HDR + UDP_HDR).saturating_add(u.payload.len()) as u16;
            let len = (ETH_HDR + IPV4_HDR + UDP_HDR).saturating_add(u.payload.len());
            if write_at(out, 0, &f.eth.dst).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 6, &f.eth.src).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 12, &u16_to_be_arr(ETHERTYPE_IPV4)).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 14, &[0x45, 0]).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 16, &u16_to_be_arr(total_len)).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 18, &[0, 0, 0x40, 0, 64, IPPROTO_UDP, 0, 0]).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 26, &u.src).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 30, &u.dst).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 34, &u16_to_be_arr(u.sport)).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 36, &u16_to_be_arr(u.dport)).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 38, &u16_to_be_arr(udp_len)).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 40, &[0, 0]).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 42, u.payload).is_none() {
                return Err(EmitError::TooSmall);
            }
            let ghost ip_pre: Seq<u8> = seq![0x45u8, 0u8] + u16_to_be(total_len) + seq![
                0u8,
                0u8,
                0x40u8,
                0u8,
                64u8,
                IPPROTO_UDP,
                0u8,
                0u8,
            ] + u.src@ + u.dst@;
            assert(out@.subrange(14, 34) =~= ip_pre);
            assert(ip_pre.len() == 20);
            proof {
                lemma_sum16_bound(ip_pre);
            }
            let ip_hdr_slice = match out.get(14..34) {
                Some(h) => h,
                None => return Err(EmitError::TooSmall),
            };
            assert(ip_hdr_slice@ == ip_pre);
            let ip_c = csum_add(0, ip_hdr_slice);
            let ip_csum = csum_fold(ip_c);
            assert(ip_csum == spec_checksum16(ip_pre));
            if write_at(out, 24, &u16_to_be_arr(ip_csum)).is_none() {
                return Err(EmitError::TooSmall);
            }
            assert(out@.subrange(14, 34) =~= spec_patch16(ip_pre, 10, ip_csum));

            let ghost udp_pre: Seq<u8> = u16_to_be(u.sport) + u16_to_be(u.dport) + u16_to_be(
                udp_len,
            ) + seq![0u8, 0u8] + u.payload@;
            assert(out@.subrange(34, len as int) =~= udp_pre);
            assert(udp_pre.len() == UDP_HDR + u.payload@.len());
            proof {
                lemma_sum16_bound(u.src@);
                lemma_sum16_bound(u.dst@);
                lemma_sum16_bound(udp_pre);
            }
            let pseudo = udp_pseudo_sum(&u.src, &u.dst, udp_len);
            assert(pseudo as nat <= 0x1000_0000);
            assert(udp_pre.len() <= MAX_FRAME);
            let udp_region = match out.get(34..len) {
                Some(r) => r,
                None => return Err(EmitError::TooSmall),
            };
            assert(udp_region@ == udp_pre);
            let udp_c = csum_add(pseudo, udp_region);
            let udp_csum0 = csum_fold(udp_c);
            assert(udp_csum0 == spec_fold_checksum(
                spec_sum16(u.src@) + spec_sum16(u.dst@) + (IPPROTO_UDP as nat) + (udp_len as nat)
                    + spec_sum16(udp_pre),
            ));
            let udp_csum = if udp_csum0 == 0 {
                0xffffu16
            } else {
                udp_csum0
            };
            if write_at(out, 40, &u16_to_be_arr(udp_csum)).is_none() {
                return Err(EmitError::TooSmall);
            }
            assert(out@.subrange(34, len as int) =~= spec_patch16(udp_pre, 6, udp_csum));
            assert(out@.subrange(0, 14) =~= f.eth.dst@ + f.eth.src@ + u16_to_be(ETHERTYPE_IPV4));
            assert(out@.subrange(0, len as int) =~= out@.subrange(0, 14) + out@.subrange(
                14,
                34,
            ) + out@.subrange(34, len as int));
            assert(out@.subrange(0, len as int) =~= f.eth.dst@ + f.eth.src@ + u16_to_be(
                ETHERTYPE_IPV4,
            ) + spec_emit_ip_udp(u.src@, u.dst@, u.sport, u.dport, u.payload@));
            Ok(len)
        },
        Body::Ipv4(p) => {
            // Emitted verbatim, so it must be exactly what the parser yields.
            if p.packet.len() > MAX_FRAME - ETH_HDR {
                return Err(EmitError::Invalid);
            }
            // Compared field by field, not as one struct `!=`, so Verus can
            // use the array/slice equality spec on each field directly.
            let (result_src, result_dst, result_proto, result_packet) = match parse_ipv4_packet(
                p.packet,
            ) {
                Ok(result) => (result.src, result.dst, result.proto, result.packet),
                Err(_) => return Err(EmitError::Invalid),
            };
            if result_src != p.src {
                return Err(EmitError::Invalid);
            }
            if result_dst != p.dst {
                return Err(EmitError::Invalid);
            }
            if result_proto != p.proto {
                return Err(EmitError::Invalid);
            }
            if result_packet != p.packet {
                return Err(EmitError::Invalid);
            }
            assert(ipv4_header_ok(p.packet@));
            assert(p.src@ == p.packet@.subrange(12, 16));
            assert(p.dst@ == p.packet@.subrange(16, 20));
            assert(p.proto == p.packet@[9]);
            assert(p.packet@ == p.packet@.subrange(0, ipv4_total_len(p.packet@)));
            let len = ETH_HDR.saturating_add(p.packet.len());
            if write_at(out, 0, &f.eth.dst).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 6, &f.eth.src).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 12, &u16_to_be_arr(ETHERTYPE_IPV4)).is_none() {
                return Err(EmitError::TooSmall);
            }
            if write_at(out, 14, p.packet).is_none() {
                return Err(EmitError::TooSmall);
            }
            assert(out@.subrange(0, len as int) =~= f.eth.dst@ + f.eth.src@ + u16_to_be(
                ETHERTYPE_IPV4,
            ) + p.packet@);
            Ok(len)
        },
    }
}

/// Property shared by the Kani harness and the bolero target: parsing never
/// panics, and anything accepted re-emits to an equal frame.
///
/// Not Verus-checked: `#[cfg(any(test, kani))]` means Verus's own
/// verification pass (which sets neither `test` nor `kani`) never compiles
/// this function or `check_into`/`check_ip_into` below, so no `ensures`
/// on them would ever actually be checked here (see the M4 plan C5
/// deviation note on `check_into`/`check_ip_into`).
#[cfg(any(test, kani))]
pub fn check(bytes: &[u8]) {
    let mut out = [0u8; MAX_FRAME];
    let _ = check_into(bytes, &mut out);
    let _ = check_ip_into(bytes, &mut out);
}

/// `check` with a caller-supplied output buffer (the Kani harness uses a
/// small one to keep the problem tractable). Returns the parse result.
#[cfg(any(test, kani))]
#[allow(clippy::panic)]
pub fn check_into<'a>(bytes: &'a [u8], out: &mut [u8]) -> Result<Frame<'a>, DropReason> {
    let r = parse_frame(bytes);
    if let Ok(f) = r {
        match emit(&f, out) {
            Ok(n) => assert!(out.get(..n).map(parse_frame) == Some(Ok(f))),
            Err(_) => panic!("accepted frames must be emittable"),
        }
    }
    r
}

/// `check_into` for the inside-NIC parser.
#[cfg(any(test, kani))]
#[allow(clippy::panic)]
pub fn check_ip_into<'a>(bytes: &'a [u8], out: &mut [u8]) -> Result<Frame<'a>, DropReason> {
    let r = parse_frame_ip(bytes);
    if let Ok(f) = r {
        match emit(&f, out) {
            Ok(n) => assert!(out.get(..n).map(parse_frame_ip) == Some(Ok(f))),
            Err(_) => panic!("accepted frames must be emittable"),
        }
    }
    r
}

} // verus!

// Plain Rust, not inside verus!{}: a `&'static [DropReason]` array-to-slice
// coercion in a const hits an unsupported vstd::array::array_as_slice call
// in exec mode inside verus! (V0 probe territory), so this one impl block
// stays outside it, same as the rest of the crate once did.
impl DropReason {
    pub const ALL: &'static [DropReason] = &[
        DropReason::TooShort,
        DropReason::TooLong,
        DropReason::EthBadSrc,
        DropReason::UnknownEtherType,
        DropReason::ArpMalformed,
        DropReason::ArpBadSender,
        DropReason::Ipv4Version,
        DropReason::Ipv4Options,
        DropReason::Ipv4Fragment,
        DropReason::Ipv4BadLength,
        DropReason::Ipv4BadChecksum,
        DropReason::Ipv4BadSrc,
        DropReason::NotUdp,
        DropReason::UdpBadLength,
        DropReason::UdpBadChecksum,
        DropReason::TtlExpired,
    ];
}

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests;
