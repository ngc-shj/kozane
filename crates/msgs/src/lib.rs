//! Byte layouts of the messages PDs exchange over `ring::link` buffers
//! (plan C11/C12/C14). Every sender is untrusted by its receiver, so each
//! `decode` is total: exact sizes, closed tags, no trailing bytes.
//!
//! | link            | message                                             |
//! |-----------------|-----------------------------------------------------|
//! | ingress → hs    | `Initiation`: src ip[4] port[2] msg[148]            |
//! | hs → ingress    | `Response`: dst ip[4] port[2] msg[92]               |
//! | hs → data       | `Install`: session keys and indices (secret)        |
//! | ingress → data  | `Transport`: src ip[4] port[2] msg[..]              |
//! | data → ingress  | tag 1 `Outbound` peer[2] msg[..]; tag 2 `EndpointUpdate` peer[2] ip[4] port[2] |
//! | data ↔ inner    | a bare IPv4 datagram (validated by `wire`)          |
//! | ingress → pq    | `RpDatagram`: peer ip[4] port[2] msg[176 or 1092]   |
//! | pq → ingress    | `RpReply`, one per input: tag 1 `Reply` index[1] msg[1132 or 64]; tag 2 `NoReply` |
//! | pq → hs         | `PskInstall`: peer[2] osk[32] (secret)              |
//!
//! Integers are little-endian.
//!
//! Verus (M4 plan C3) proves every `pub fn decode` unbounded: totality
//! and, at `exact()` sites, acceptance and the round trip. `Initiation`,
//! `Response`, `Install` and `PskInstall` each keep a zero-copy
//! `&'a [u8; N]` field read from the middle of the input
//! (`msg`/`send`/`recv`/`osk`) via `chunk_ref`, below: the crate's one
//! trusted function, since vstd has no spec for
//! `TryFrom<&[u8]> for &[u8; N]`.

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
use wg_wire::{INITIATION_LEN, RESPONSE_LEN};

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub ip: [u8; 4],
    pub port: u16,
}

pub const EP_LEN: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed;

// --- Little-endian byte layout for `u16`, as a spec and as the matching
// exec code (`std`'s `from_le_bytes`/`to_le_bytes` have no vstd spec, M4
// plan C1/C3). ---

pub open spec fn u16_from_le(b: Seq<u8>) -> u16
    recommends
        b.len() == 2,
{
    (b[0] as u16) | (b[1] as u16) << 8
}

pub open spec fn u16_to_le(x: u16) -> Seq<u8> {
    seq![(x & 0xff) as u8, ((x >> 8) & 0xff) as u8]
}

proof fn lemma_u16_le_roundtrip(x: u16)
    ensures
        u16_from_le(u16_to_le(x)) == x,
{
    let b = u16_to_le(x);
    assert(b.len() == 2);
    assert(b[0] == (x & 0xff) as u8);
    assert(b[1] == ((x >> 8) & 0xff) as u8);
    assert(u16_from_le(b) == (b[0] as u16) | (b[1] as u16) << 8);
    assert(((((x & 0xff) as u8) as u16) | ((((x >> 8) & 0xff) as u8) as u16) << 8) == x) by (
    bit_vector);
}

proof fn lemma_u16_le_inverse(b: Seq<u8>)
    requires
        b.len() == 2,
    ensures
        u16_to_le(u16_from_le(b)) == b,
{
    let b0 = b[0];
    let b1 = b[1];
    let x = u16_from_le(b);
    assert(x == (b0 as u16) | (b1 as u16) << 8);
    assert({
        let v = (b0 as u16) | (b1 as u16) << 8;
        &&& (v & 0xff) as u8 == b0
        &&& (v >> 8 & 0xff) as u8 == b1
    }) by (bit_vector);
    assert(u16_to_le(x).len() == 2);
    assert(u16_to_le(x) =~= b);
}

#[inline]
fn u16_from_le_arr(b: [u8; 2]) -> (x: u16)
    ensures
        x == u16_from_le(b@),
{
    (b[0] as u16) | ((b[1] as u16) << 8)
}

#[inline]
fn u16_to_le_arr(x: u16) -> (b: [u8; 2])
    ensures
        b@ == u16_to_le(x),
{
    [(x & 0xff) as u8, ((x >> 8) & 0xff) as u8]
}

// --- Little-endian byte layout for `u32`, the same shape as `u16` above
// (`Install`'s `local_index`/`remote_index`). ---

pub open spec fn u32_from_le(b: Seq<u8>) -> u32
    recommends
        b.len() == 4,
{
    (b[0] as u32) | (b[1] as u32) << 8 | (b[2] as u32) << 16 | (b[3] as u32) << 24
}

pub open spec fn u32_to_le(x: u32) -> Seq<u8> {
    seq![
        (x & 0xff) as u8,
        ((x >> 8) & 0xff) as u8,
        ((x >> 16) & 0xff) as u8,
        ((x >> 24) & 0xff) as u8,
    ]
}

proof fn lemma_u32_le_roundtrip(x: u32)
    ensures
        u32_from_le(u32_to_le(x)) == x,
{
    let b = u32_to_le(x);
    assert(b.len() == 4);
    assert(b[0] == (x & 0xff) as u8);
    assert(b[1] == ((x >> 8) & 0xff) as u8);
    assert(b[2] == ((x >> 16) & 0xff) as u8);
    assert(b[3] == ((x >> 24) & 0xff) as u8);
    assert(u32_from_le(b) == (b[0] as u32) | (b[1] as u32) << 8 | (b[2] as u32) << 16 | (b[3]
        as u32) << 24);
    assert((((x & 0xff) as u8) as u32) | ((((x >> 8) & 0xff) as u8) as u32) << 8 | ((((x >> 16)
        & 0xff) as u8) as u32) << 16 | ((((x >> 24) & 0xff) as u8) as u32) << 24 == x) by (
    bit_vector);
}

proof fn lemma_u32_le_inverse(b: Seq<u8>)
    requires
        b.len() == 4,
    ensures
        u32_to_le(u32_from_le(b)) == b,
{
    let b0 = b[0];
    let b1 = b[1];
    let b2 = b[2];
    let b3 = b[3];
    let x = u32_from_le(b);
    assert(x == (b0 as u32) | (b1 as u32) << 8 | (b2 as u32) << 16 | (b3 as u32) << 24);
    assert(((((b0 as u32) | (b1 as u32) << 8 | (b2 as u32) << 16 | (b3 as u32) << 24) & 0xff)
        as u8 == b0) && ((((b0 as u32) | (b1 as u32) << 8 | (b2 as u32) << 16 | (b3 as u32)
        << 24) >> 8 & 0xff) as u8 == b1) && ((((b0 as u32) | (b1 as u32) << 8 | (b2 as u32)
        << 16 | (b3 as u32) << 24) >> 16 & 0xff) as u8 == b2) && ((((b0 as u32) | (b1 as u32)
        << 8 | (b2 as u32) << 16 | (b3 as u32) << 24) >> 24 & 0xff) as u8 == b3)) by (bit_vector);
    assert(u32_to_le(x).len() == 4);
    assert(u32_to_le(x) =~= b);
}

#[inline]
fn u32_from_le_arr(b: [u8; 4]) -> (x: u32)
    ensures
        x == u32_from_le(b@),
{
    (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16) | ((b[3] as u32) << 24)
}

#[inline]
fn u32_to_le_arr(x: u32) -> (b: [u8; 4])
    ensures
        b@ == u32_to_le(x),
{
    [
        (x & 0xff) as u8,
        ((x >> 8) & 0xff) as u8,
        ((x >> 16) & 0xff) as u8,
        ((x >> 24) & 0xff) as u8,
    ]
}

/// Reads `N` bytes at `start` into an owned array: the verified
/// replacement for `take`'s `.try_into()` (no vstd spec, M4 plan C3).
/// `get` on a literal range has one (wg-wire's `read_array`, M4 plan C1).
#[inline]
fn read_array<const N: usize>(bytes: &[u8], start: usize) -> (r: Result<[u8; N], Malformed>)
    ensures
        r is Ok <==> start as int + N as int <= bytes@.len(),
        r is Ok ==> r->Ok_0@ == bytes@.subrange(start as int, start as int + N as int),
        r is Err ==> r == Err(Malformed),
{
    assert(bytes@.len() == bytes.len() as int);
    assert(bytes.len() <= usize::MAX);
    match start.checked_add(N) {
        None => Err(Malformed),
        Some(end) => match bytes.get(start..end) {
            None => Err(Malformed),
            Some(src) => {
                let mut out = [0u8; N];
                out.copy_from_slice(src);
                Ok(out)
            },
        },
    }
}

/// Writes `bytes` at `start`: the verified replacement for `put`'s
/// `at: &mut usize` accumulator, in wg-wire's `write_at` style (literal
/// offsets, `get_mut` on a literal range, `checked_add`).
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

/// The rest of `b` from `at`, for the variants that take a trailing
/// payload (`RpDatagram`, `ToIngress::Outbound`); shared with the
/// unverified decoders below.
fn rest(b: &[u8], at: usize) -> (r: Result<&[u8], Malformed>)
    ensures
        r is Ok <==> at as int <= b@.len(),
        r is Ok ==> r->Ok_0@ == b@.subrange(at as int, b@.len() as int),
        r is Err ==> r == Err(Malformed),
{
    match b.get(at..) {
        None => Err(Malformed),
        Some(s) => Ok(s),
    }
}

/// `at` must be exactly the end of `b`: no trailing bytes.
fn exact(b: &[u8], at: usize) -> (r: Result<(), Malformed>)
    ensures
        r is Ok <==> at == b@.len(),
        r is Err ==> r == Err(Malformed),
{
    if at == b.len() {
        Ok(())
    } else {
        Err(Malformed)
    }
}

/// The `N` bytes of `b` at `at`, borrowed in place: the zero-copy fields
/// (`send`, `recv`, `osk`, `msg`) must not leave a copy of a secret behind.
/// vstd has no spec for `TryFrom<&[u8]> for &[u8; N]`, so this is the
/// crate's one trusted function (policy/verus-trusted.toml). Its contract is
/// checked by Kani for every `N` the decoders use (`proofs::chunk_ref_*`).
#[verifier::external_body]
#[inline]
fn chunk_ref<const N: usize>(b: &[u8], at: usize) -> (r: Option<&[u8; N]>)
    ensures
        r is Some <==> at as int + N as int <= b@.len(),
        r is Some ==> r->Some_0@ == b@.subrange(at as int, at as int + N as int),
{
    let end = at.checked_add(N)?;
    b.get(at..end)?.try_into().ok()
}

/// ingress → hs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Initiation<'a> {
    pub src: Endpoint,
    pub msg: &'a [u8; INITIATION_LEN],
}

pub const INITIATION_MSG_LEN: usize = EP_LEN + INITIATION_LEN;

/// The bytes `Initiation::encode` describes, as a pure function of the
/// fields.
pub open spec fn spec_encode_initiation(ip: Seq<u8>, port: u16, msg: Seq<u8>) -> Seq<u8>
    recommends
        ip.len() == 4,
        msg.len() == INITIATION_LEN,
{
    ip + u16_to_le(port) + msg
}

proof fn lemma_spec_encode_initiation_decodes(ip: Seq<u8>, port: u16, msg: Seq<u8>)
    requires
        ip.len() == 4,
        msg.len() == INITIATION_LEN,
    ensures
        ({
            let bytes = spec_encode_initiation(ip, port, msg);
            &&& bytes.len() == INITIATION_MSG_LEN
            &&& bytes.subrange(0, 4) =~= ip
            &&& u16_from_le(bytes.subrange(4, 6)) == port
            &&& bytes.subrange(EP_LEN as int, INITIATION_MSG_LEN as int) =~= msg
        }),
{
    let bytes = spec_encode_initiation(ip, port, msg);
    assert(bytes.subrange(0, 4) =~= ip);
    assert(bytes.subrange(4, 6) =~= u16_to_le(port));
    lemma_u16_le_roundtrip(port);
    assert(bytes.subrange(EP_LEN as int, INITIATION_MSG_LEN as int) =~= msg);
}

proof fn lemma_spec_encode_initiation_inverse(bytes: Seq<u8>)
    requires
        bytes.len() == INITIATION_MSG_LEN,
    ensures
        spec_encode_initiation(
            bytes.subrange(0, 4),
            u16_from_le(bytes.subrange(4, 6)),
            bytes.subrange(EP_LEN as int, INITIATION_MSG_LEN as int),
        ) =~= bytes,
{
    lemma_u16_le_inverse(bytes.subrange(4, 6));
}

impl<'a> Initiation<'a> {
    pub fn encode(&self, out: &mut [u8]) -> (r: Option<usize>)
        ensures
            r is Some <==> old(out)@.len() >= INITIATION_MSG_LEN as int,
            r is Some ==> {
                &&& r->Some_0 == INITIATION_MSG_LEN
                &&& final(out)@.subrange(0, INITIATION_MSG_LEN as int) == spec_encode_initiation(
                    self.src.ip@,
                    self.src.port,
                    self.msg@,
                )
            },
    {
        write_at(out, 0, &self.src.ip)?;
        write_at(out, 4, &u16_to_le_arr(self.src.port))?;
        write_at(out, EP_LEN, self.msg)?;
        assert(out@.subrange(0, INITIATION_MSG_LEN as int) =~= spec_encode_initiation(
            self.src.ip@,
            self.src.port,
            self.msg@,
        ));
        Some(INITIATION_MSG_LEN)
    }

    pub fn decode(b: &'a [u8]) -> (r: Result<Self, Malformed>)
        ensures
            r is Ok <==> b@.len() == INITIATION_MSG_LEN as int,
            r is Ok ==> {
                let m = r->Ok_0;
                &&& m.src.ip@ == b@.subrange(0, 4)
                &&& m.src.port == u16_from_le(b@.subrange(4, 6))
                &&& m.msg@ == b@.subrange(EP_LEN as int, INITIATION_MSG_LEN as int)
            },
            r is Err ==> r == Err(Malformed),
    {
        let ip = read_array::<4>(b, 0)?;
        let port = u16_from_le_arr(read_array::<2>(b, 4)?);
        let src = Endpoint { ip, port };
        let msg = chunk_ref::<INITIATION_LEN>(b, EP_LEN).ok_or(Malformed)?;
        exact(b, INITIATION_MSG_LEN)?;
        Ok(Self { src, msg })
    }
}

/// hs → ingress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response<'a> {
    pub dst: Endpoint,
    pub msg: &'a [u8; RESPONSE_LEN],
}

/// The bytes `Response::encode` describes, as a pure function of the
/// fields.
pub open spec fn spec_encode_response(ip: Seq<u8>, port: u16, msg: Seq<u8>) -> Seq<u8>
    recommends
        ip.len() == 4,
        msg.len() == RESPONSE_LEN,
{
    ip + u16_to_le(port) + msg
}

proof fn lemma_spec_encode_response_decodes(ip: Seq<u8>, port: u16, msg: Seq<u8>)
    requires
        ip.len() == 4,
        msg.len() == RESPONSE_LEN,
    ensures
        ({
            let bytes = spec_encode_response(ip, port, msg);
            &&& bytes.len() == EP_LEN + RESPONSE_LEN
            &&& bytes.subrange(0, 4) =~= ip
            &&& u16_from_le(bytes.subrange(4, 6)) == port
            &&& bytes.subrange(EP_LEN as int, (EP_LEN + RESPONSE_LEN) as int) =~= msg
        }),
{
    let bytes = spec_encode_response(ip, port, msg);
    assert(bytes.subrange(0, 4) =~= ip);
    assert(bytes.subrange(4, 6) =~= u16_to_le(port));
    lemma_u16_le_roundtrip(port);
    assert(bytes.subrange(EP_LEN as int, (EP_LEN + RESPONSE_LEN) as int) =~= msg);
}

proof fn lemma_spec_encode_response_inverse(bytes: Seq<u8>)
    requires
        bytes.len() == EP_LEN + RESPONSE_LEN,
    ensures
        spec_encode_response(
            bytes.subrange(0, 4),
            u16_from_le(bytes.subrange(4, 6)),
            bytes.subrange(EP_LEN as int, (EP_LEN + RESPONSE_LEN) as int),
        ) =~= bytes,
{
    lemma_u16_le_inverse(bytes.subrange(4, 6));
}

impl<'a> Response<'a> {
    pub fn encode(&self, out: &mut [u8]) -> (r: Option<usize>)
        ensures
            r is Some <==> old(out)@.len() >= (EP_LEN + RESPONSE_LEN) as int,
            r is Some ==> {
                &&& r->Some_0 == EP_LEN + RESPONSE_LEN
                &&& final(out)@.subrange(0, r->Some_0 as int) == spec_encode_response(
                    self.dst.ip@,
                    self.dst.port,
                    self.msg@,
                )
            },
    {
        write_at(out, 0, &self.dst.ip)?;
        write_at(out, 4, &u16_to_le_arr(self.dst.port))?;
        write_at(out, EP_LEN, self.msg)?;
        assert(out@.subrange(0, (EP_LEN + RESPONSE_LEN) as int) =~= spec_encode_response(
            self.dst.ip@,
            self.dst.port,
            self.msg@,
        ));
        Some(EP_LEN + RESPONSE_LEN)
    }

    pub fn decode(b: &'a [u8]) -> (r: Result<Self, Malformed>)
        ensures
            r is Ok <==> b@.len() == (EP_LEN + RESPONSE_LEN) as int,
            r is Ok ==> {
                let m = r->Ok_0;
                &&& m.dst.ip@ == b@.subrange(0, 4)
                &&& m.dst.port == u16_from_le(b@.subrange(4, 6))
                &&& m.msg@ == b@.subrange(EP_LEN as int, (EP_LEN + RESPONSE_LEN) as int)
            },
            r is Err ==> r == Err(Malformed),
    {
        let ip = read_array::<4>(b, 0)?;
        let port = u16_from_le_arr(read_array::<2>(b, 4)?);
        let dst = Endpoint { ip, port };
        let msg = chunk_ref::<RESPONSE_LEN>(b, EP_LEN).ok_or(Malformed)?;
        exact(b, EP_LEN + RESPONSE_LEN)?;
        Ok(Self { dst, msg })
    }
}

/// hs → data: a freshly negotiated session. Carries transport keys, so the
/// receiving buffer must be zeroed once copied out (plan, secrets residue);
/// not `Debug`/`Clone`/`Copy` for the same reason (C9). No timestamp: `data`
/// starts the session clock itself, so a compromised `hs` cannot extend
/// a session past REJECT_AFTER_TIME.
#[derive(PartialEq, Eq)]
pub struct Install<'a> {
    pub peer: u16,
    /// Our index (the receiver index of inbound transport packets).
    pub local_index: u32,
    /// The initiator's index (the receiver index of our outbound packets).
    pub remote_index: u32,
    pub send: &'a [u8; 32],
    pub recv: &'a [u8; 32],
}

pub const INSTALL_LEN: usize = 2 + 4 + 4 + 32 + 32;

/// The bytes `Install::encode` describes, as a pure function of the
/// fields.
pub open spec fn spec_encode_install(
    peer: u16,
    local_index: u32,
    remote_index: u32,
    send: Seq<u8>,
    recv: Seq<u8>,
) -> Seq<u8>
    recommends
        send.len() == 32,
        recv.len() == 32,
{
    u16_to_le(peer) + u32_to_le(local_index) + u32_to_le(remote_index) + send + recv
}

proof fn lemma_spec_encode_install_decodes(
    peer: u16,
    local_index: u32,
    remote_index: u32,
    send: Seq<u8>,
    recv: Seq<u8>,
)
    requires
        send.len() == 32,
        recv.len() == 32,
    ensures
        ({
            let bytes = spec_encode_install(peer, local_index, remote_index, send, recv);
            &&& bytes.len() == INSTALL_LEN
            &&& u16_from_le(bytes.subrange(0, 2)) == peer
            &&& u32_from_le(bytes.subrange(2, 6)) == local_index
            &&& u32_from_le(bytes.subrange(6, 10)) == remote_index
            &&& bytes.subrange(10, 42) =~= send
            &&& bytes.subrange(42, 74) =~= recv
        }),
{
    let bytes = spec_encode_install(peer, local_index, remote_index, send, recv);
    assert(bytes.subrange(0, 2) =~= u16_to_le(peer));
    assert(bytes.subrange(2, 6) =~= u32_to_le(local_index));
    assert(bytes.subrange(6, 10) =~= u32_to_le(remote_index));
    assert(bytes.subrange(10, 42) =~= send);
    assert(bytes.subrange(42, 74) =~= recv);
    lemma_u16_le_roundtrip(peer);
    lemma_u32_le_roundtrip(local_index);
    lemma_u32_le_roundtrip(remote_index);
}

proof fn lemma_spec_encode_install_inverse(bytes: Seq<u8>)
    requires
        bytes.len() == INSTALL_LEN,
    ensures
        spec_encode_install(
            u16_from_le(bytes.subrange(0, 2)),
            u32_from_le(bytes.subrange(2, 6)),
            u32_from_le(bytes.subrange(6, 10)),
            bytes.subrange(10, 42),
            bytes.subrange(42, 74),
        ) =~= bytes,
{
    lemma_u16_le_inverse(bytes.subrange(0, 2));
    lemma_u32_le_inverse(bytes.subrange(2, 6));
    lemma_u32_le_inverse(bytes.subrange(6, 10));
}

impl<'a> Install<'a> {
    pub fn encode(&self, out: &mut [u8]) -> (r: Option<usize>)
        ensures
            r is Some <==> old(out)@.len() >= INSTALL_LEN as int,
            r is Some ==> {
                &&& r->Some_0 == INSTALL_LEN
                &&& final(out)@.subrange(0, INSTALL_LEN as int) == spec_encode_install(
                    self.peer,
                    self.local_index,
                    self.remote_index,
                    self.send@,
                    self.recv@,
                )
            },
    {
        write_at(out, 0, &u16_to_le_arr(self.peer))?;
        write_at(out, 2, &u32_to_le_arr(self.local_index))?;
        write_at(out, 6, &u32_to_le_arr(self.remote_index))?;
        write_at(out, 10, self.send)?;
        write_at(out, 42, self.recv)?;
        assert(out@.subrange(0, INSTALL_LEN as int) =~= spec_encode_install(
            self.peer,
            self.local_index,
            self.remote_index,
            self.send@,
            self.recv@,
        ));
        Some(INSTALL_LEN)
    }

    pub fn decode(b: &'a [u8]) -> (r: Result<Self, Malformed>)
        ensures
            r is Ok <==> b@.len() == INSTALL_LEN as int,
            r is Ok ==> {
                let m = r->Ok_0;
                &&& m.peer == u16_from_le(b@.subrange(0, 2))
                &&& m.local_index == u32_from_le(b@.subrange(2, 6))
                &&& m.remote_index == u32_from_le(b@.subrange(6, 10))
                &&& m.send@ == b@.subrange(10, 42)
                &&& m.recv@ == b@.subrange(42, 74)
            },
            r is Err ==> r == Err(Malformed),
    {
        let peer = u16_from_le_arr(read_array::<2>(b, 0)?);
        let local_index = u32_from_le_arr(read_array::<4>(b, 2)?);
        let remote_index = u32_from_le_arr(read_array::<4>(b, 6)?);
        let send = chunk_ref::<32>(b, 10).ok_or(Malformed)?;
        let recv = chunk_ref::<32>(b, 42).ok_or(Malformed)?;
        exact(b, INSTALL_LEN)?;
        Ok(Self { peer, local_index, remote_index, send, recv })
    }
}

/// pq → hs: a fresh Rosenpass OSK for `peer`, the WireGuard PSK under L8.
/// Secret, so the receiving buffer is zeroed once copied out; not
/// `Debug`/`Clone`/`Copy`, nor `PartialEq` (no variable-time `==` on the
/// OSK — equality is stated in spec only, via the lemmas below).
pub struct PskInstall<'a> {
    pub peer: u16,
    pub osk: &'a [u8; 32],
}

pub const PSK_INSTALL_LEN: usize = 2 + 32;

/// The bytes `PskInstall::encode` describes, as a pure function of the
/// fields.
pub open spec fn spec_encode_psk_install(peer: u16, osk: Seq<u8>) -> Seq<u8>
    recommends
        osk.len() == 32,
{
    u16_to_le(peer) + osk
}

proof fn lemma_spec_encode_psk_install_decodes(peer: u16, osk: Seq<u8>)
    requires
        osk.len() == 32,
    ensures
        ({
            let bytes = spec_encode_psk_install(peer, osk);
            &&& bytes.len() == PSK_INSTALL_LEN
            &&& u16_from_le(bytes.subrange(0, 2)) == peer
            &&& bytes.subrange(2, PSK_INSTALL_LEN as int) =~= osk
        }),
{
    let bytes = spec_encode_psk_install(peer, osk);
    assert(bytes.subrange(0, 2) =~= u16_to_le(peer));
    lemma_u16_le_roundtrip(peer);
    assert(bytes.subrange(2, PSK_INSTALL_LEN as int) =~= osk);
}

proof fn lemma_spec_encode_psk_install_inverse(bytes: Seq<u8>)
    requires
        bytes.len() == PSK_INSTALL_LEN,
    ensures
        spec_encode_psk_install(
            u16_from_le(bytes.subrange(0, 2)),
            bytes.subrange(2, PSK_INSTALL_LEN as int),
        ) =~= bytes,
{
    lemma_u16_le_inverse(bytes.subrange(0, 2));
}

impl<'a> PskInstall<'a> {
    pub fn encode(&self, out: &mut [u8]) -> (r: Option<usize>)
        ensures
            r is Some <==> old(out)@.len() >= PSK_INSTALL_LEN as int,
            r is Some ==> {
                &&& r->Some_0 == PSK_INSTALL_LEN
                &&& final(out)@.subrange(0, PSK_INSTALL_LEN as int) == spec_encode_psk_install(
                    self.peer,
                    self.osk@,
                )
            },
    {
        write_at(out, 0, &u16_to_le_arr(self.peer))?;
        write_at(out, 2, self.osk)?;
        assert(out@.subrange(0, PSK_INSTALL_LEN as int) =~= spec_encode_psk_install(
            self.peer,
            self.osk@,
        ));
        Some(PSK_INSTALL_LEN)
    }

    pub fn decode(b: &'a [u8]) -> (r: Result<Self, Malformed>)
        ensures
            r is Ok <==> b@.len() == PSK_INSTALL_LEN as int,
            r is Ok ==> {
                let m = r->Ok_0;
                &&& m.peer == u16_from_le(b@.subrange(0, 2))
                &&& m.osk@ == b@.subrange(2, PSK_INSTALL_LEN as int)
            },
            r is Err ==> r == Err(Malformed),
    {
        let peer = u16_from_le_arr(read_array::<2>(b, 0)?);
        let osk = chunk_ref::<32>(b, 2).ok_or(Malformed)?;
        exact(b, PSK_INSTALL_LEN)?;
        Ok(Self { peer, osk })
    }
}

/// ingress → data. Verified (M4 plan C3): `src`/`msg` are the only fields,
/// `msg` is a trailing slice (no zero-copy array ref), so no field hits
/// the `TryFrom<&[u8]> for &[u8; N]` gap above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transport<'a> {
    pub src: Endpoint,
    pub msg: &'a [u8],
}

/// The bytes `Transport::encode` describes, as a pure function of the
/// fields: the endpoint, then the trailing payload verbatim.
pub open spec fn spec_encode_transport(ip: Seq<u8>, port: u16, msg: Seq<u8>) -> Seq<u8>
    recommends
        ip.len() == 4,
{
    ip + u16_to_le(port) + msg
}

proof fn lemma_spec_encode_transport_decodes(ip: Seq<u8>, port: u16, msg: Seq<u8>)
    requires
        ip.len() == 4,
    ensures
        ({
            let bytes = spec_encode_transport(ip, port, msg);
            &&& bytes.len() == EP_LEN + msg.len()
            &&& bytes.subrange(0, 4) =~= ip
            &&& u16_from_le(bytes.subrange(4, 6)) == port
            &&& bytes.subrange(EP_LEN as int, bytes.len() as int) =~= msg
        }),
{
    let bytes = spec_encode_transport(ip, port, msg);
    assert(bytes.subrange(0, 4) =~= ip);
    assert(bytes.subrange(4, 6) =~= u16_to_le(port));
    lemma_u16_le_roundtrip(port);
    assert(bytes.subrange(EP_LEN as int, bytes.len() as int) =~= msg);
}

proof fn lemma_spec_encode_transport_inverse(bytes: Seq<u8>)
    requires
        bytes.len() >= EP_LEN,
    ensures
        spec_encode_transport(
            bytes.subrange(0, 4),
            u16_from_le(bytes.subrange(4, 6)),
            bytes.subrange(EP_LEN as int, bytes.len() as int),
        ) =~= bytes,
{
    lemma_u16_le_inverse(bytes.subrange(4, 6));
}

impl<'a> Transport<'a> {
    pub fn encode(&self, out: &mut [u8]) -> (r: Option<usize>)
        ensures
            r is Some <==> old(out)@.len() >= EP_LEN as int + self.msg@.len() as int,
            r is Some ==> {
                &&& r->Some_0 == EP_LEN + self.msg.len()
                &&& final(out)@.subrange(0, r->Some_0 as int) == spec_encode_transport(
                    self.src.ip@,
                    self.src.port,
                    self.msg@,
                )
            },
    {
        assert(old(out)@.len() == out@.len());
        assert(out@.len() == out.len() as int);
        let n = EP_LEN.checked_add(self.msg.len())?;
        write_at(out, 0, &self.src.ip)?;
        write_at(out, 4, &u16_to_le_arr(self.src.port))?;
        write_at(out, EP_LEN, self.msg)?;
        assert(out@.subrange(0, n as int) =~= spec_encode_transport(
            self.src.ip@,
            self.src.port,
            self.msg@,
        ));
        Some(n)
    }

    pub fn decode(bytes: &'a [u8]) -> (r: Result<Self, Malformed>)
        ensures
            r is Ok <==> bytes@.len() >= EP_LEN as int,
            r is Ok ==> {
                let m = r->Ok_0;
                &&& m.src.ip@ == bytes@.subrange(0, 4)
                &&& m.src.port == u16_from_le(bytes@.subrange(4, 6))
                &&& m.msg@ == bytes@.subrange(EP_LEN as int, bytes@.len() as int)
            },
            r is Err ==> r == Err(Malformed),
    {
        let ip = read_array::<4>(bytes, 0)?;
        let port = u16_from_le_arr(read_array::<2>(bytes, 4)?);
        let src = Endpoint { ip, port };
        let msg = rest(bytes, EP_LEN)?;
        Ok(Self { src, msg })
    }
}

/// ingress → pq (the source) and pq → ingress (the destination): a
/// Rosenpass message. Only InitHello and InitConf travel inbound, and only
/// RespHello and EmptyData outbound, so the length is one of four (M3 plan
/// C3/C4); anything else is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpDatagram<'a> {
    pub peer: Endpoint,
    pub msg: &'a [u8],
}

/// Wire lengths of the Rosenpass messages a responder exchanges.
pub const RP_LENS: [usize; 4] = [1092, 1132, 176, 64];

pub open spec fn rp_len_ok(n: int) -> bool {
    n == 1092 || n == 1132 || n == 176 || n == 64
}

/// The bytes `RpDatagram::encode` describes, as a pure function of the
/// fields.
pub open spec fn spec_encode_rp_datagram(ip: Seq<u8>, port: u16, msg: Seq<u8>) -> Seq<u8>
    recommends
        ip.len() == 4,
{
    ip + u16_to_le(port) + msg
}

proof fn lemma_spec_encode_rp_datagram_decodes(ip: Seq<u8>, port: u16, msg: Seq<u8>)
    requires
        ip.len() == 4,
    ensures
        ({
            let bytes = spec_encode_rp_datagram(ip, port, msg);
            &&& bytes.len() == EP_LEN + msg.len()
            &&& bytes.subrange(0, 4) =~= ip
            &&& u16_from_le(bytes.subrange(4, 6)) == port
            &&& bytes.subrange(EP_LEN as int, bytes.len() as int) =~= msg
        }),
{
    let bytes = spec_encode_rp_datagram(ip, port, msg);
    assert(bytes.subrange(0, 4) =~= ip);
    assert(bytes.subrange(4, 6) =~= u16_to_le(port));
    lemma_u16_le_roundtrip(port);
    assert(bytes.subrange(EP_LEN as int, bytes.len() as int) =~= msg);
}

proof fn lemma_spec_encode_rp_datagram_inverse(bytes: Seq<u8>)
    requires
        bytes.len() >= EP_LEN,
    ensures
        spec_encode_rp_datagram(
            bytes.subrange(0, 4),
            u16_from_le(bytes.subrange(4, 6)),
            bytes.subrange(EP_LEN as int, bytes.len() as int),
        ) =~= bytes,
{
    lemma_u16_le_inverse(bytes.subrange(4, 6));
}

impl<'a> RpDatagram<'a> {
    pub fn encode(&self, out: &mut [u8]) -> (r: Option<usize>)
        ensures
            r is Some <==> rp_len_ok(self.msg@.len() as int) && old(out)@.len() >= EP_LEN as int
                + self.msg@.len() as int,
            r is Some ==> {
                &&& r->Some_0 == EP_LEN + self.msg.len()
                &&& final(out)@.subrange(0, r->Some_0 as int) == spec_encode_rp_datagram(
                    self.peer.ip@,
                    self.peer.port,
                    self.msg@,
                )
            },
    {
        let n = self.msg.len();
        if !(n == 1092 || n == 1132 || n == 176 || n == 64) {
            return None;
        }
        let total = EP_LEN.checked_add(n)?;
        write_at(out, 0, &self.peer.ip)?;
        write_at(out, 4, &u16_to_le_arr(self.peer.port))?;
        write_at(out, EP_LEN, self.msg)?;
        assert(out@.subrange(0, total as int) =~= spec_encode_rp_datagram(
            self.peer.ip@,
            self.peer.port,
            self.msg@,
        ));
        Some(total)
    }

    pub fn decode(b: &'a [u8]) -> (r: Result<Self, Malformed>)
        ensures
            r is Ok <==> b@.len() >= EP_LEN as int && rp_len_ok(b@.len() as int - EP_LEN as int),
            r is Ok ==> {
                let m = r->Ok_0;
                &&& m.peer.ip@ == b@.subrange(0, 4)
                &&& m.peer.port == u16_from_le(b@.subrange(4, 6))
                &&& m.msg@ == b@.subrange(EP_LEN as int, b@.len() as int)
            },
            r is Err ==> r == Err(Malformed),
    {
        let ip = read_array::<4>(b, 0)?;
        let port = u16_from_le_arr(read_array::<2>(b, 4)?);
        let peer = Endpoint { ip, port };
        let msg = rest(b, EP_LEN)?;
        let n = msg.len();
        if !(n == 1092 || n == 1132 || n == 176 || n == 64) {
            return Err(Malformed);
        }
        Ok(Self { peer, msg })
    }
}

/// pq → ingress: the completion record of one input (M3b plan C3). `pq`
/// sends exactly one per input it took, in input order, before returning
/// the input's buffer; `ingress` pairs it with its own record of that
/// forward. There is no endpoint: the reply goes where `ingress` recorded
/// the forward came from, so `pq` cannot aim it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpReply<'a> {
    /// A RespHello or an EmptyData. `index` is the configured peer an
    /// EmptyData belongs to, `RP_NO_PEER` otherwise; `ingress` range-checks
    /// it.
    Reply { index: u8, msg: &'a [u8] },
    /// The input was refused, dropped or unreadable: nothing to send.
    NoReply,
}

/// `RpReply::Reply`'s `index` when no configured peer is named.
pub const RP_NO_PEER: u8 = 0xff;

/// The reply lengths a responder sends: RespHello, EmptyData.
pub const RP_REPLY_LENS: [usize; 2] = [1132, 64];

pub const TAG_REPLY: u8 = 1;
pub const TAG_NO_REPLY: u8 = 2;

pub open spec fn rp_reply_len_ok(n: int) -> bool {
    n == 1132 || n == 64
}

/// The bytes `RpReply::encode` describes for `Reply { index, msg }`.
pub open spec fn spec_encode_rp_reply_reply(index: u8, msg: Seq<u8>) -> Seq<u8> {
    seq![TAG_REPLY, index] + msg
}

/// The bytes `RpReply::encode` describes for `NoReply`.
pub open spec fn spec_encode_rp_reply_no_reply() -> Seq<u8> {
    seq![TAG_NO_REPLY]
}

proof fn lemma_spec_encode_rp_reply_reply_decodes(index: u8, msg: Seq<u8>)
    ensures
        ({
            let bytes = spec_encode_rp_reply_reply(index, msg);
            &&& bytes.len() == 2 + msg.len()
            &&& bytes[0] == TAG_REPLY
            &&& bytes[1] == index
            &&& bytes.subrange(2, bytes.len() as int) =~= msg
        }),
{
    let bytes = spec_encode_rp_reply_reply(index, msg);
    assert(bytes.subrange(2, bytes.len() as int) =~= msg);
}

proof fn lemma_spec_encode_rp_reply_reply_inverse(bytes: Seq<u8>)
    requires
        bytes.len() >= 2,
        bytes[0] == TAG_REPLY,
    ensures
        spec_encode_rp_reply_reply(bytes[1], bytes.subrange(2, bytes.len() as int)) =~= bytes,
{
}

proof fn lemma_spec_encode_rp_reply_no_reply_decodes()
    ensures
        ({
            let bytes = spec_encode_rp_reply_no_reply();
            &&& bytes.len() == 1
            &&& bytes[0] == TAG_NO_REPLY
        }),
{
}

impl<'a> RpReply<'a> {
    pub fn encode(&self, out: &mut [u8]) -> (r: Option<usize>)
        ensures
            self is Reply && rp_reply_len_ok(self->Reply_msg@.len() as int) ==> {
                &&& r is Some <==> old(out)@.len() >= 2 + self->Reply_msg@.len() as int
                &&& r is Some ==> {
                    &&& r->Some_0 == 2 + self->Reply_msg@.len() as int
                    &&& final(out)@.subrange(0, r->Some_0 as int) == spec_encode_rp_reply_reply(
                        self->Reply_index,
                        self->Reply_msg@,
                    )
                }
            },
            self is Reply && !rp_reply_len_ok(self->Reply_msg@.len() as int) ==> r is None,
            self is NoReply ==> {
                &&& r is Some <==> old(out)@.len() >= 1
                &&& r is Some ==> {
                    &&& r->Some_0 == 1
                    &&& final(out)@.subrange(0, 1) == spec_encode_rp_reply_no_reply()
                }
            },
    {
        match *self {
            RpReply::Reply { index, msg } => {
                let n = msg.len();
                if !(n == 1132 || n == 64) {
                    return None;
                }
                let total = 2usize.checked_add(n)?;
                write_at(out, 0, &[TAG_REPLY, index])?;
                write_at(out, 2, msg)?;
                assert(out@.subrange(0, total as int) =~= spec_encode_rp_reply_reply(
                    index,
                    msg@,
                ));
                Some(total)
            },
            RpReply::NoReply => {
                write_at(out, 0, &[TAG_NO_REPLY])?;
                assert(out@.subrange(0, 1) =~= spec_encode_rp_reply_no_reply());
                Some(1)
            },
        }
    }

    pub fn decode(b: &'a [u8]) -> (r: Result<Self, Malformed>)
        ensures
            r is Ok && r->Ok_0 is Reply ==> {
                let m = r->Ok_0;
                &&& b@.len() >= 2
                &&& b@[0] == TAG_REPLY
                &&& m->Reply_index == b@[1]
                &&& m->Reply_msg@ == b@.subrange(2, b@.len() as int)
                &&& rp_reply_len_ok(m->Reply_msg@.len() as int)
            },
            r is Ok && r->Ok_0 is NoReply <==> b@.len() == 1 && b@[0] == TAG_NO_REPLY,
            r is Err ==> {
                &&& r == Err(Malformed)
                &&& !(b@.len() >= 2 && b@[0] == TAG_REPLY && rp_reply_len_ok(
                    b@.len() as int - 2,
                ))
                &&& !(b@.len() == 1 && b@[0] == TAG_NO_REPLY)
            },
    {
        let tag = read_array::<1>(b, 0)?[0];
        if tag == TAG_REPLY {
            let index = read_array::<1>(b, 1)?[0];
            let msg = rest(b, 2)?;
            let n = msg.len();
            if !(n == 1132 || n == 64) {
                return Err(Malformed);
            }
            Ok(RpReply::Reply { index, msg })
        } else if tag == TAG_NO_REPLY {
            exact(b, 1)?;
            Ok(RpReply::NoReply)
        } else {
            Err(Malformed)
        }
    }
}

/// data → ingress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToIngress<'a> {
    /// A sealed transport message for `peer`'s current endpoint.
    Outbound { peer: u16, msg: &'a [u8] },
    /// `peer` authenticated a new highest counter from `endpoint`.
    EndpointUpdate { peer: u16, endpoint: Endpoint },
}

pub const TAG_OUTBOUND: u8 = 1;
pub const TAG_ENDPOINT: u8 = 2;

/// The bytes `ToIngress::encode` describes for `Outbound { peer, msg }`.
pub open spec fn spec_encode_to_ingress_outbound(peer: u16, msg: Seq<u8>) -> Seq<u8> {
    seq![TAG_OUTBOUND] + u16_to_le(peer) + msg
}

/// The bytes `ToIngress::encode` describes for
/// `EndpointUpdate { peer, endpoint }`.
pub open spec fn spec_encode_to_ingress_endpoint(peer: u16, ip: Seq<u8>, port: u16) -> Seq<u8>
    recommends
        ip.len() == 4,
{
    seq![TAG_ENDPOINT] + u16_to_le(peer) + ip + u16_to_le(port)
}

proof fn lemma_spec_encode_to_ingress_outbound_decodes(peer: u16, msg: Seq<u8>)
    ensures
        ({
            let bytes = spec_encode_to_ingress_outbound(peer, msg);
            &&& bytes.len() == 3 + msg.len()
            &&& bytes[0] == TAG_OUTBOUND
            &&& u16_from_le(bytes.subrange(1, 3)) == peer
            &&& bytes.subrange(3, bytes.len() as int) =~= msg
        }),
{
    let bytes = spec_encode_to_ingress_outbound(peer, msg);
    assert(bytes.subrange(1, 3) =~= u16_to_le(peer));
    lemma_u16_le_roundtrip(peer);
    assert(bytes.subrange(3, bytes.len() as int) =~= msg);
}

proof fn lemma_spec_encode_to_ingress_outbound_inverse(bytes: Seq<u8>)
    requires
        bytes.len() >= 3,
        bytes[0] == TAG_OUTBOUND,
    ensures
        spec_encode_to_ingress_outbound(
            u16_from_le(bytes.subrange(1, 3)),
            bytes.subrange(3, bytes.len() as int),
        ) =~= bytes,
{
    lemma_u16_le_inverse(bytes.subrange(1, 3));
}

proof fn lemma_spec_encode_to_ingress_endpoint_decodes(peer: u16, ip: Seq<u8>, port: u16)
    requires
        ip.len() == 4,
    ensures
        ({
            let bytes = spec_encode_to_ingress_endpoint(peer, ip, port);
            &&& bytes.len() == 9
            &&& bytes[0] == TAG_ENDPOINT
            &&& u16_from_le(bytes.subrange(1, 3)) == peer
            &&& bytes.subrange(3, 7) =~= ip
            &&& u16_from_le(bytes.subrange(7, 9)) == port
        }),
{
    let bytes = spec_encode_to_ingress_endpoint(peer, ip, port);
    assert(bytes.subrange(1, 3) =~= u16_to_le(peer));
    assert(bytes.subrange(3, 7) =~= ip);
    assert(bytes.subrange(7, 9) =~= u16_to_le(port));
    lemma_u16_le_roundtrip(peer);
    lemma_u16_le_roundtrip(port);
}

proof fn lemma_spec_encode_to_ingress_endpoint_inverse(bytes: Seq<u8>)
    requires
        bytes.len() == 9,
        bytes[0] == TAG_ENDPOINT,
    ensures
        spec_encode_to_ingress_endpoint(
            u16_from_le(bytes.subrange(1, 3)),
            bytes.subrange(3, 7),
            u16_from_le(bytes.subrange(7, 9)),
        ) =~= bytes,
{
    lemma_u16_le_inverse(bytes.subrange(1, 3));
    lemma_u16_le_inverse(bytes.subrange(7, 9));
}

impl<'a> ToIngress<'a> {
    pub fn encode(&self, out: &mut [u8]) -> (r: Option<usize>)
        ensures
            self is Outbound ==> {
                &&& r is Some <==> old(out)@.len() >= 3 + self->Outbound_msg@.len() as int
                &&& r is Some ==> {
                    &&& r->Some_0 == 3 + self->Outbound_msg@.len() as int
                    &&& final(out)@.subrange(0, r->Some_0 as int)
                        == spec_encode_to_ingress_outbound(
                        self->Outbound_peer,
                        self->Outbound_msg@,
                    )
                }
            },
            self is EndpointUpdate ==> {
                &&& r is Some <==> old(out)@.len() >= 9
                &&& r is Some ==> {
                    &&& r->Some_0 == 9
                    &&& final(out)@.subrange(0, 9) == spec_encode_to_ingress_endpoint(
                        self->EndpointUpdate_peer,
                        self->EndpointUpdate_endpoint.ip@,
                        self->EndpointUpdate_endpoint.port,
                    )
                }
            },
    {
        assert(old(out)@.len() == out@.len());
        assert(out@.len() == out.len() as int);
        match *self {
            ToIngress::Outbound { peer, msg } => {
                let total = 3usize.checked_add(msg.len())?;
                write_at(out, 0, &[TAG_OUTBOUND])?;
                write_at(out, 1, &u16_to_le_arr(peer))?;
                write_at(out, 3, msg)?;
                assert(out@.subrange(0, total as int) =~= spec_encode_to_ingress_outbound(
                    peer,
                    msg@,
                ));
                Some(total)
            },
            ToIngress::EndpointUpdate { peer, endpoint } => {
                write_at(out, 0, &[TAG_ENDPOINT])?;
                write_at(out, 1, &u16_to_le_arr(peer))?;
                write_at(out, 3, &endpoint.ip)?;
                write_at(out, 7, &u16_to_le_arr(endpoint.port))?;
                assert(out@.subrange(0, 9) =~= spec_encode_to_ingress_endpoint(
                    peer,
                    endpoint.ip@,
                    endpoint.port,
                ));
                Some(9)
            },
        }
    }

    pub fn decode(b: &'a [u8]) -> (r: Result<Self, Malformed>)
        ensures
            r is Ok && r->Ok_0 is Outbound ==> {
                let m = r->Ok_0;
                &&& b@.len() >= 3
                &&& b@[0] == TAG_OUTBOUND
                &&& m->Outbound_peer == u16_from_le(b@.subrange(1, 3))
                &&& m->Outbound_msg@ == b@.subrange(3, b@.len() as int)
            },
            r is Ok && r->Ok_0 is EndpointUpdate <==> b@.len() == 9 && b@[0] == TAG_ENDPOINT,
            r is Ok && r->Ok_0 is EndpointUpdate ==> {
                let m = r->Ok_0;
                &&& m->EndpointUpdate_peer == u16_from_le(b@.subrange(1, 3))
                &&& m->EndpointUpdate_endpoint.ip@ == b@.subrange(3, 7)
                &&& m->EndpointUpdate_endpoint.port == u16_from_le(b@.subrange(7, 9))
            },
            r is Err ==> {
                &&& r == Err(Malformed)
                &&& !(b@.len() >= 3 && b@[0] == TAG_OUTBOUND)
                &&& !(b@.len() == 9 && b@[0] == TAG_ENDPOINT)
            },
    {
        let tag = read_array::<1>(b, 0)?[0];
        let peer = u16_from_le_arr(read_array::<2>(b, 1)?);
        if tag == TAG_OUTBOUND {
            let msg = rest(b, 3)?;
            Ok(ToIngress::Outbound { peer, msg })
        } else if tag == TAG_ENDPOINT {
            let ip = read_array::<4>(b, 3)?;
            let port = u16_from_le_arr(read_array::<2>(b, 7)?);
            let endpoint = Endpoint { ip, port };
            exact(b, 9)?;
            Ok(ToIngress::EndpointUpdate { peer, endpoint })
        } else {
            Err(Malformed)
        }
    }
}

} // verus!

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests;
