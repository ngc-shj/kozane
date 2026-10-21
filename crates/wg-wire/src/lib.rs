//! WireGuard message codecs and the transport replay window, free of any
//! cryptography so that Kani can check them without compiling libcrux.
//!
//! Every parser is total: any input yields a value or a `WireError`, never a
//! panic (proved by the harnesses in `proofs`). Reserved bytes must be zero.

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

pub mod replay;

verus! {

pub const MSG_INITIATION: u8 = 1;
pub const MSG_RESPONSE: u8 = 2;
pub const MSG_COOKIE: u8 = 3;
pub const MSG_TRANSPORT: u8 = 4;

pub const INITIATION_LEN: usize = 148;
pub const RESPONSE_LEN: usize = 92;
pub const COOKIE_REPLY_LEN: usize = 64;
pub const TRANSPORT_HEADER_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
/// Header plus an empty (keepalive) payload's tag.
pub const TRANSPORT_MIN_LEN: usize = TRANSPORT_HEADER_LEN + TAG_LEN;

/// Bytes of an initiation covered by mac1 (everything before it).
pub const INITIATION_MAC1_OFFSET: usize = 116;
/// Bytes of an initiation covered by mac2 (everything before it).
pub const INITIATION_MAC2_OFFSET: usize = 132;
/// Bytes of a response covered by mac1 (everything before it).
pub const RESPONSE_MAC1_OFFSET: usize = 60;

/// 2^64 - 2^13 - 1 (whitepaper section 6.1).
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    WrongLength,
    WrongType,
    ReservedNonZero,
    TooShort,
    BufferTooSmall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageInitiation {
    pub sender: u32,
    pub ephemeral: [u8; 32],
    pub enc_static: [u8; 48],
    pub enc_timestamp: [u8; 28],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageResponse {
    pub sender: u32,
    pub receiver: u32,
    pub ephemeral: [u8; 32],
    pub enc_nothing: [u8; 16],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

/// Cookie reply (whitepaper section 5.4.7). `encrypted_cookie` is the
/// 16-byte cookie sealed under XChaCha20-Poly1305, followed by its tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CookieReply {
    pub receiver: u32,
    pub nonce: [u8; 24],
    pub encrypted_cookie: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transport<'a> {
    pub receiver: u32,
    pub counter: u64,
    /// Encrypted payload followed by its 16-byte tag (at least 16 bytes).
    pub ciphertext: &'a [u8],
}

// --- Little-endian byte layout, as specs and as the matching exec code. ---
//
// `std`'s `from_le_bytes`/`to_le_bytes` have no vstd spec (V0 probe, M4 plan
// C1), so the exec side is refactored to the shift-and-mask form that these
// spec functions state directly, rather than given a trusted spec.

pub open spec fn u32_from_le(b: Seq<u8>) -> u32
    recommends
        b.len() == 4,
{
    (b[0] as u32) | (b[1] as u32) << 8 | (b[2] as u32) << 16 | (b[3] as u32) << 24
}

pub open spec fn u32_to_le(x: u32) -> Seq<u8> {
    seq![(x & 0xff) as u8, ((x >> 8) & 0xff) as u8, ((x >> 16) & 0xff) as u8, ((x >> 24) & 0xff) as u8]
}

pub open spec fn u64_from_le(b: Seq<u8>) -> u64
    recommends
        b.len() == 8,
{
    (b[0] as u64) | (b[1] as u64) << 8 | (b[2] as u64) << 16 | (b[3] as u64) << 24 | (b[4] as u64)
        << 32 | (b[5] as u64) << 40 | (b[6] as u64) << 48 | (b[7] as u64) << 56
}

pub open spec fn u64_to_le(x: u64) -> Seq<u8> {
    seq![
        (x & 0xff) as u8,
        ((x >> 8) & 0xff) as u8,
        ((x >> 16) & 0xff) as u8,
        ((x >> 24) & 0xff) as u8,
        ((x >> 32) & 0xff) as u8,
        ((x >> 40) & 0xff) as u8,
        ((x >> 48) & 0xff) as u8,
        ((x >> 56) & 0xff) as u8,
    ]
}

/// `u32_from_le`/`u32_to_le` are inverses: encoding then decoding returns
/// the original integer.
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

/// `u32_to_le`/`u32_from_le` are inverses the other way: decoding then
/// re-encoding a 4-byte sequence returns it unchanged.
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

/// `u64_from_le`/`u64_to_le` are inverses: encoding then decoding returns
/// the original integer.
proof fn lemma_u64_le_roundtrip(x: u64)
    ensures
        u64_from_le(u64_to_le(x)) == x,
{
    let b = u64_to_le(x);
    assert(b.len() == 8);
    assert(b[0] == (x & 0xff) as u8);
    assert(b[1] == ((x >> 8) & 0xff) as u8);
    assert(b[2] == ((x >> 16) & 0xff) as u8);
    assert(b[3] == ((x >> 24) & 0xff) as u8);
    assert(b[4] == ((x >> 32) & 0xff) as u8);
    assert(b[5] == ((x >> 40) & 0xff) as u8);
    assert(b[6] == ((x >> 48) & 0xff) as u8);
    assert(b[7] == ((x >> 56) & 0xff) as u8);
    assert(u64_from_le(b) == (b[0] as u64) | (b[1] as u64) << 8 | (b[2] as u64) << 16 | (b[3]
        as u64) << 24 | (b[4] as u64) << 32 | (b[5] as u64) << 40 | (b[6] as u64) << 48 | (b[7]
        as u64) << 56);
    assert((((x & 0xff) as u8) as u64) | ((((x >> 8) & 0xff) as u8) as u64) << 8 | ((((x >> 16)
        & 0xff) as u8) as u64) << 16 | ((((x >> 24) & 0xff) as u8) as u64) << 24 | ((((x >> 32)
        & 0xff) as u8) as u64) << 32 | ((((x >> 40) & 0xff) as u8) as u64) << 40 | ((((x >> 48)
        & 0xff) as u8) as u64) << 48 | ((((x >> 56) & 0xff) as u8) as u64) << 56 == x) by (
    bit_vector);
}

/// `u64_to_le`/`u64_from_le` are inverses the other way: decoding then
/// re-encoding an 8-byte sequence returns it unchanged.
proof fn lemma_u64_le_inverse(b: Seq<u8>)
    requires
        b.len() == 8,
    ensures
        u64_to_le(u64_from_le(b)) == b,
{
    let b0 = b[0];
    let b1 = b[1];
    let b2 = b[2];
    let b3 = b[3];
    let b4 = b[4];
    let b5 = b[5];
    let b6 = b[6];
    let b7 = b[7];
    let x = u64_from_le(b);
    assert(x == (b0 as u64) | (b1 as u64) << 8 | (b2 as u64) << 16 | (b3 as u64) << 24 | (b4
        as u64) << 32 | (b5 as u64) << 40 | (b6 as u64) << 48 | (b7 as u64) << 56);
    assert({
        let v = (b0 as u64) | (b1 as u64) << 8 | (b2 as u64) << 16 | (b3 as u64) << 24 | (b4
            as u64) << 32 | (b5 as u64) << 40 | (b6 as u64) << 48 | (b7 as u64) << 56;
        &&& (v & 0xff) as u8 == b0
        &&& (v >> 8 & 0xff) as u8 == b1
        &&& (v >> 16 & 0xff) as u8 == b2
        &&& (v >> 24 & 0xff) as u8 == b3
        &&& (v >> 32 & 0xff) as u8 == b4
        &&& (v >> 40 & 0xff) as u8 == b5
        &&& (v >> 48 & 0xff) as u8 == b6
        &&& (v >> 56 & 0xff) as u8 == b7
    }) by (bit_vector);
    assert(u64_to_le(x).len() == 8);
    assert(u64_to_le(x) =~= b);
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
    [(x & 0xff) as u8, ((x >> 8) & 0xff) as u8, ((x >> 16) & 0xff) as u8, ((x >> 24) & 0xff) as u8]
}

#[inline]
fn u64_from_le_arr(b: [u8; 8]) -> (x: u64)
    ensures
        x == u64_from_le(b@),
{
    (b[0] as u64) | ((b[1] as u64) << 8) | ((b[2] as u64) << 16) | ((b[3] as u64) << 24)
        | ((b[4] as u64) << 32) | ((b[5] as u64) << 40) | ((b[6] as u64) << 48) | ((b[7] as u64)
        << 56)
}

#[inline]
fn u64_to_le_arr(x: u64) -> (b: [u8; 8])
    ensures
        b@ == u64_to_le(x),
{
    [
        (x & 0xff) as u8,
        ((x >> 8) & 0xff) as u8,
        ((x >> 16) & 0xff) as u8,
        ((x >> 24) & 0xff) as u8,
        ((x >> 32) & 0xff) as u8,
        ((x >> 40) & 0xff) as u8,
        ((x >> 48) & 0xff) as u8,
        ((x >> 56) & 0xff) as u8,
    ]
}

/// The 4-byte header `bytes` must start with: type `ty`, reserved zero.
pub open spec fn header_ok(bytes: Seq<u8>, ty: u8) -> bool {
    &&& bytes.len() >= 4
    &&& bytes[0] == ty
    &&& bytes[1] == 0
    &&& bytes[2] == 0
    &&& bytes[3] == 0
}

/// The 4 header bytes `header_ok` accepts, as a value: type `ty`, reserved
/// zero.
pub open spec fn header_bytes(ty: u8) -> Seq<u8> {
    seq![ty, 0u8, 0u8, 0u8]
}

/// `header_ok(bytes, ty)` is exactly "the first 4 bytes are `header_bytes(ty)`".
proof fn lemma_header_ok_eq(bytes: Seq<u8>, ty: u8)
    requires
        header_ok(bytes, ty),
    ensures
        bytes.subrange(0, 4) =~= header_bytes(ty),
{
}

proof fn lemma_header_bytes_ok(ty: u8)
    ensures
        header_ok(header_bytes(ty), ty),
{
}

/// Reads `N` bytes at `start`, replacing `split_first_chunk` (no vstd spec):
/// `get` on a literal range has one (V0 probe, M4 plan C1).
#[inline]
fn read_array<const N: usize>(bytes: &[u8], start: usize) -> (r: Result<[u8; N], WireError>)
    ensures
        r is Ok <==> start as int + N as int <= bytes@.len(),
        r is Ok ==> r->Ok_0@ == bytes@.subrange(start as int, start as int + N as int),
        r is Err ==> r == Err(WireError::TooShort),
{
    assert(bytes@.len() == bytes.len() as int);
    assert(bytes.len() <= usize::MAX);
    match start.checked_add(N) {
        None => {
            assert(start as int + N as int > bytes@.len());
            Err(WireError::TooShort)
        },
        Some(end) => {
            assert(end as int == start as int + N as int);
            match bytes.get(start..end) {
                None => {
                    assert(start as int + N as int > bytes@.len());
                    Err(WireError::TooShort)
                },
                Some(src) => {
                    assert(start as int + N as int <= bytes@.len());
                    assert(src@ == bytes@.subrange(start as int, start as int + N as int));
                    let mut out = [0u8; N];
                    out.copy_from_slice(src);
                    assert(out@ == src@);
                    Ok(out)
                },
            }
        },
    }
}

/// Writes `bytes` at `start`, replacing `split_at_mut_checked` and
/// `core::mem::take` (neither has a vstd spec): `get_mut` on a literal range
/// has one (V0 probe, M4 plan C1).
#[inline]
fn write_at(out: &mut [u8], start: usize, bytes: &[u8]) -> (r: Result<(), WireError>)
    ensures
        r is Ok <==> start as int + bytes@.len() as int <= old(out)@.len(),
        r is Ok ==> {
            &&& final(out)@.len() == old(out)@.len()
            &&& final(out)@.subrange(start as int, start as int + bytes@.len() as int) == bytes@
            &&& (forall|i: int|
                0 <= i < old(out)@.len() && !(start as int <= i < start as int + bytes@.len()
                    as int) ==> #[trigger] final(out)@[i] == old(out)@[i])
        },
        r is Err ==> final(out)@ == old(out)@ && r == Err(WireError::BufferTooSmall),
{
    assert(out@.len() == out.len() as int);
    assert(out.len() <= usize::MAX);
    assert(bytes@.len() == bytes.len() as int);
    assert(bytes.len() <= usize::MAX);
    match start.checked_add(bytes.len()) {
        None => Err(WireError::BufferTooSmall),
        Some(end) => match out.get_mut(start..end) {
            None => Err(WireError::BufferTooSmall),
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
                Ok(())
            },
        },
    }
}

/// The bytes `MessageInitiation::emit` describes, as a pure function of the
/// fields.
pub open spec fn spec_emit_initiation(
    sender: u32,
    ephemeral: Seq<u8>,
    enc_static: Seq<u8>,
    enc_timestamp: Seq<u8>,
    mac1: Seq<u8>,
    mac2: Seq<u8>,
) -> Seq<u8>
    recommends
        ephemeral.len() == 32,
        enc_static.len() == 48,
        enc_timestamp.len() == 28,
        mac1.len() == 16,
        mac2.len() == 16,
{
    Seq::new(
        INITIATION_LEN as nat,
        |i: int|
            if i < 4 {
                header_bytes(MSG_INITIATION)[i]
            } else if i < 8 {
                u32_to_le(sender)[i - 4]
            } else if i < 40 {
                ephemeral[i - 8]
            } else if i < 88 {
                enc_static[i - 40]
            } else if i < 116 {
                enc_timestamp[i - 88]
            } else if i < 132 {
                mac1[i - 116]
            } else {
                mac2[i - 132]
            },
    )
}

proof fn lemma_spec_emit_initiation_parses(
    sender: u32,
    ephemeral: Seq<u8>,
    enc_static: Seq<u8>,
    enc_timestamp: Seq<u8>,
    mac1: Seq<u8>,
    mac2: Seq<u8>,
)
    requires
        ephemeral.len() == 32,
        enc_static.len() == 48,
        enc_timestamp.len() == 28,
        mac1.len() == 16,
        mac2.len() == 16,
    ensures
        ({
            let bytes = spec_emit_initiation(
                sender,
                ephemeral,
                enc_static,
                enc_timestamp,
                mac1,
                mac2,
            );
            &&& bytes.len() == INITIATION_LEN
            &&& header_ok(bytes, MSG_INITIATION)
            &&& u32_from_le(bytes.subrange(4, 8)) == sender
            &&& bytes.subrange(8, 40) =~= ephemeral
            &&& bytes.subrange(40, 88) =~= enc_static
            &&& bytes.subrange(88, 116) =~= enc_timestamp
            &&& bytes.subrange(116, 132) =~= mac1
            &&& bytes.subrange(132, 148) =~= mac2
        }),
{
    let bytes = spec_emit_initiation(sender, ephemeral, enc_static, enc_timestamp, mac1, mac2);
    assert(bytes.len() == INITIATION_LEN);
    assert(bytes.subrange(0, 4) =~= header_bytes(MSG_INITIATION));
    lemma_header_bytes_ok(MSG_INITIATION);
    assert(header_ok(bytes, MSG_INITIATION));
    assert(bytes.subrange(4, 8) =~= u32_to_le(sender));
    lemma_u32_le_roundtrip(sender);
    assert(bytes.subrange(8, 40) =~= ephemeral);
    assert(bytes.subrange(40, 88) =~= enc_static);
    assert(bytes.subrange(88, 116) =~= enc_timestamp);
    assert(bytes.subrange(116, 132) =~= mac1);
    assert(bytes.subrange(132, 148) =~= mac2);
}

proof fn lemma_spec_emit_initiation_inverse(bytes: Seq<u8>)
    requires
        bytes.len() == INITIATION_LEN,
        header_ok(bytes, MSG_INITIATION),
    ensures
        spec_emit_initiation(
            u32_from_le(bytes.subrange(4, 8)),
            bytes.subrange(8, 40),
            bytes.subrange(40, 88),
            bytes.subrange(88, 116),
            bytes.subrange(116, 132),
            bytes.subrange(132, 148),
        ) =~= bytes,
{
    lemma_header_ok_eq(bytes, MSG_INITIATION);
    lemma_u32_le_inverse(bytes.subrange(4, 8));
}

impl MessageInitiation {
    pub fn parse(bytes: &[u8]) -> (r: Result<Self, WireError>)
        ensures
            r is Ok <==> (bytes@.len() == INITIATION_LEN as int && header_ok(
                bytes@,
                MSG_INITIATION,
            )),
            r is Ok ==> {
                let m = r->Ok_0;
                &&& m.sender == u32_from_le(bytes@.subrange(4, 8))
                &&& m.ephemeral@ == bytes@.subrange(8, 40)
                &&& m.enc_static@ == bytes@.subrange(40, 88)
                &&& m.enc_timestamp@ == bytes@.subrange(88, 116)
                &&& m.mac1@ == bytes@.subrange(116, 132)
                &&& m.mac2@ == bytes@.subrange(132, 148)
            },
    {
        if bytes.len() != INITIATION_LEN {
            return Err(WireError::WrongLength);
        }
        let header = read_array::<4>(bytes, 0)?;
        let (t, r0, r1, r2) = (header[0], header[1], header[2], header[3]);
        if t != MSG_INITIATION {
            return Err(WireError::WrongType);
        }
        if r0 != 0 || r1 != 0 || r2 != 0 {
            return Err(WireError::ReservedNonZero);
        }
        let sender = u32_from_le_arr(read_array::<4>(bytes, 4)?);
        let ephemeral = read_array::<32>(bytes, 8)?;
        let enc_static = read_array::<48>(bytes, 40)?;
        let enc_timestamp = read_array::<28>(bytes, 88)?;
        let mac1 = read_array::<16>(bytes, 116)?;
        let mac2 = read_array::<16>(bytes, 132)?;
        Ok(Self { sender, ephemeral, enc_static, enc_timestamp, mac1, mac2 })
    }

    pub fn emit(&self, out: &mut [u8]) -> (r: Result<usize, WireError>)
        ensures
            r is Ok <==> old(out)@.len() >= INITIATION_LEN,
            r is Ok ==> {
                &&& r->Ok_0 == INITIATION_LEN
                &&& final(out)@.subrange(0, INITIATION_LEN as int) == spec_emit_initiation(
                    self.sender,
                    self.ephemeral@,
                    self.enc_static@,
                    self.enc_timestamp@,
                    self.mac1@,
                    self.mac2@,
                )
            },
            r is Err ==> r == Err(WireError::BufferTooSmall),
    {
        write_at(out, 0, &[MSG_INITIATION, 0, 0, 0])?;
        write_at(out, 4, &u32_to_le_arr(self.sender))?;
        write_at(out, 8, &self.ephemeral)?;
        write_at(out, 40, &self.enc_static)?;
        write_at(out, 88, &self.enc_timestamp)?;
        write_at(out, 116, &self.mac1)?;
        write_at(out, 132, &self.mac2)?;
        assert(out@.subrange(0, INITIATION_LEN as int) =~= spec_emit_initiation(
            self.sender,
            self.ephemeral@,
            self.enc_static@,
            self.enc_timestamp@,
            self.mac1@,
            self.mac2@,
        ));
        Ok(INITIATION_LEN)
    }
}

/// The bytes `MessageResponse::emit` describes, as a pure function of the
/// fields.
pub open spec fn spec_emit_response(
    sender: u32,
    receiver: u32,
    ephemeral: Seq<u8>,
    enc_nothing: Seq<u8>,
    mac1: Seq<u8>,
    mac2: Seq<u8>,
) -> Seq<u8>
    recommends
        ephemeral.len() == 32,
        enc_nothing.len() == 16,
        mac1.len() == 16,
        mac2.len() == 16,
{
    Seq::new(
        RESPONSE_LEN as nat,
        |i: int|
            if i < 4 {
                header_bytes(MSG_RESPONSE)[i]
            } else if i < 8 {
                u32_to_le(sender)[i - 4]
            } else if i < 12 {
                u32_to_le(receiver)[i - 8]
            } else if i < 44 {
                ephemeral[i - 12]
            } else if i < 60 {
                enc_nothing[i - 44]
            } else if i < 76 {
                mac1[i - 60]
            } else {
                mac2[i - 76]
            },
    )
}

proof fn lemma_spec_emit_response_parses(
    sender: u32,
    receiver: u32,
    ephemeral: Seq<u8>,
    enc_nothing: Seq<u8>,
    mac1: Seq<u8>,
    mac2: Seq<u8>,
)
    requires
        ephemeral.len() == 32,
        enc_nothing.len() == 16,
        mac1.len() == 16,
        mac2.len() == 16,
    ensures
        ({
            let bytes = spec_emit_response(sender, receiver, ephemeral, enc_nothing, mac1, mac2);
            &&& bytes.len() == RESPONSE_LEN
            &&& header_ok(bytes, MSG_RESPONSE)
            &&& u32_from_le(bytes.subrange(4, 8)) == sender
            &&& u32_from_le(bytes.subrange(8, 12)) == receiver
            &&& bytes.subrange(12, 44) =~= ephemeral
            &&& bytes.subrange(44, 60) =~= enc_nothing
            &&& bytes.subrange(60, 76) =~= mac1
            &&& bytes.subrange(76, 92) =~= mac2
        }),
{
    let bytes = spec_emit_response(sender, receiver, ephemeral, enc_nothing, mac1, mac2);
    assert(bytes.len() == RESPONSE_LEN);
    assert(bytes.subrange(0, 4) =~= header_bytes(MSG_RESPONSE));
    lemma_header_bytes_ok(MSG_RESPONSE);
    assert(header_ok(bytes, MSG_RESPONSE));
    assert(bytes.subrange(4, 8) =~= u32_to_le(sender));
    assert(bytes.subrange(8, 12) =~= u32_to_le(receiver));
    lemma_u32_le_roundtrip(sender);
    lemma_u32_le_roundtrip(receiver);
    assert(bytes.subrange(12, 44) =~= ephemeral);
    assert(bytes.subrange(44, 60) =~= enc_nothing);
    assert(bytes.subrange(60, 76) =~= mac1);
    assert(bytes.subrange(76, 92) =~= mac2);
}

proof fn lemma_spec_emit_response_inverse(bytes: Seq<u8>)
    requires
        bytes.len() == RESPONSE_LEN,
        header_ok(bytes, MSG_RESPONSE),
    ensures
        spec_emit_response(
            u32_from_le(bytes.subrange(4, 8)),
            u32_from_le(bytes.subrange(8, 12)),
            bytes.subrange(12, 44),
            bytes.subrange(44, 60),
            bytes.subrange(60, 76),
            bytes.subrange(76, 92),
        ) =~= bytes,
{
    lemma_header_ok_eq(bytes, MSG_RESPONSE);
    lemma_u32_le_inverse(bytes.subrange(4, 8));
    lemma_u32_le_inverse(bytes.subrange(8, 12));
}

impl MessageResponse {
    pub fn parse(bytes: &[u8]) -> (r: Result<Self, WireError>)
        ensures
            r is Ok <==> (bytes@.len() == RESPONSE_LEN as int && header_ok(bytes@, MSG_RESPONSE)),
            r is Ok ==> {
                let m = r->Ok_0;
                &&& m.sender == u32_from_le(bytes@.subrange(4, 8))
                &&& m.receiver == u32_from_le(bytes@.subrange(8, 12))
                &&& m.ephemeral@ == bytes@.subrange(12, 44)
                &&& m.enc_nothing@ == bytes@.subrange(44, 60)
                &&& m.mac1@ == bytes@.subrange(60, 76)
                &&& m.mac2@ == bytes@.subrange(76, 92)
            },
    {
        if bytes.len() != RESPONSE_LEN {
            return Err(WireError::WrongLength);
        }
        let header = read_array::<4>(bytes, 0)?;
        let (t, r0, r1, r2) = (header[0], header[1], header[2], header[3]);
        if t != MSG_RESPONSE {
            return Err(WireError::WrongType);
        }
        if r0 != 0 || r1 != 0 || r2 != 0 {
            return Err(WireError::ReservedNonZero);
        }
        let sender = u32_from_le_arr(read_array::<4>(bytes, 4)?);
        let receiver = u32_from_le_arr(read_array::<4>(bytes, 8)?);
        let ephemeral = read_array::<32>(bytes, 12)?;
        let enc_nothing = read_array::<16>(bytes, 44)?;
        let mac1 = read_array::<16>(bytes, 60)?;
        let mac2 = read_array::<16>(bytes, 76)?;
        Ok(Self { sender, receiver, ephemeral, enc_nothing, mac1, mac2 })
    }

    pub fn emit(&self, out: &mut [u8]) -> (r: Result<usize, WireError>)
        ensures
            r is Ok <==> old(out)@.len() >= RESPONSE_LEN,
            r is Ok ==> {
                &&& r->Ok_0 == RESPONSE_LEN
                &&& final(out)@.subrange(0, RESPONSE_LEN as int) == spec_emit_response(
                    self.sender,
                    self.receiver,
                    self.ephemeral@,
                    self.enc_nothing@,
                    self.mac1@,
                    self.mac2@,
                )
            },
            r is Err ==> r == Err(WireError::BufferTooSmall),
    {
        write_at(out, 0, &[MSG_RESPONSE, 0, 0, 0])?;
        write_at(out, 4, &u32_to_le_arr(self.sender))?;
        write_at(out, 8, &u32_to_le_arr(self.receiver))?;
        write_at(out, 12, &self.ephemeral)?;
        write_at(out, 44, &self.enc_nothing)?;
        write_at(out, 60, &self.mac1)?;
        write_at(out, 76, &self.mac2)?;
        assert(out@.subrange(0, RESPONSE_LEN as int) =~= spec_emit_response(
            self.sender,
            self.receiver,
            self.ephemeral@,
            self.enc_nothing@,
            self.mac1@,
            self.mac2@,
        ));
        Ok(RESPONSE_LEN)
    }
}

/// The bytes `CookieReply::emit` describes, as a pure function of the
/// fields (not a whole `CookieReply`, so the inverse lemma below never
/// needs to build one).
pub open spec fn spec_emit_cookie_reply(receiver: u32, nonce: Seq<u8>, encrypted_cookie: Seq<u8>) -> Seq<u8>
    recommends
        nonce.len() == 24,
        encrypted_cookie.len() == 32,
{
    Seq::new(
        COOKIE_REPLY_LEN as nat,
        |i: int|
            if i < 4 {
                header_bytes(MSG_COOKIE)[i]
            } else if i < 8 {
                u32_to_le(receiver)[i - 4]
            } else if i < 32 {
                nonce[i - 8]
            } else {
                encrypted_cookie[i - 32]
            },
    )
}

/// `spec_emit_cookie_reply`'s result always parses back to its own fields.
proof fn lemma_spec_emit_cookie_reply_parses(receiver: u32, nonce: Seq<u8>, encrypted_cookie: Seq<u8>)
    requires
        nonce.len() == 24,
        encrypted_cookie.len() == 32,
    ensures
        ({
            let bytes = spec_emit_cookie_reply(receiver, nonce, encrypted_cookie);
            &&& bytes.len() == COOKIE_REPLY_LEN
            &&& header_ok(bytes, MSG_COOKIE)
            &&& u32_from_le(bytes.subrange(4, 8)) == receiver
            &&& bytes.subrange(8, 32) =~= nonce
            &&& bytes.subrange(32, 64) =~= encrypted_cookie
        }),
{
    let bytes = spec_emit_cookie_reply(receiver, nonce, encrypted_cookie);
    assert(bytes.len() == COOKIE_REPLY_LEN);
    assert(bytes.subrange(0, 4) =~= header_bytes(MSG_COOKIE));
    lemma_header_bytes_ok(MSG_COOKIE);
    assert(header_ok(bytes, MSG_COOKIE));
    assert(bytes.subrange(4, 8) =~= u32_to_le(receiver));
    lemma_u32_le_roundtrip(receiver);
    assert(bytes.subrange(8, 32) =~= nonce);
    assert(bytes.subrange(32, 64) =~= encrypted_cookie);
}

/// Conversely, any bytes that parse decode-then-encode back to themselves:
/// `spec_emit_cookie_reply` is total on the range `parse` accepts.
proof fn lemma_spec_emit_cookie_reply_inverse(bytes: Seq<u8>)
    requires
        bytes.len() == COOKIE_REPLY_LEN,
        header_ok(bytes, MSG_COOKIE),
    ensures
        spec_emit_cookie_reply(
            u32_from_le(bytes.subrange(4, 8)),
            bytes.subrange(8, 32),
            bytes.subrange(32, 64),
        ) =~= bytes,
{
    lemma_header_ok_eq(bytes, MSG_COOKIE);
    lemma_u32_le_inverse(bytes.subrange(4, 8));
}

impl CookieReply {
    pub fn parse(bytes: &[u8]) -> (r: Result<Self, WireError>)
        ensures
            r is Ok <==> (bytes@.len() == COOKIE_REPLY_LEN as int && header_ok(bytes@, MSG_COOKIE)),
            r is Ok ==> {
                let m = r->Ok_0;
                &&& m.receiver == u32_from_le(bytes@.subrange(4, 8))
                &&& m.nonce@ == bytes@.subrange(8, 32)
                &&& m.encrypted_cookie@ == bytes@.subrange(32, 64)
            },
    {
        if bytes.len() != COOKIE_REPLY_LEN {
            return Err(WireError::WrongLength);
        }
        let header = read_array::<4>(bytes, 0)?;
        let (t, r0, r1, r2) = (header[0], header[1], header[2], header[3]);
        if t != MSG_COOKIE {
            return Err(WireError::WrongType);
        }
        if r0 != 0 || r1 != 0 || r2 != 0 {
            return Err(WireError::ReservedNonZero);
        }
        let receiver = u32_from_le_arr(read_array::<4>(bytes, 4)?);
        let nonce = read_array::<24>(bytes, 8)?;
        let encrypted_cookie = read_array::<32>(bytes, 32)?;
        Ok(Self { receiver, nonce, encrypted_cookie })
    }

    pub fn emit(&self, out: &mut [u8]) -> (r: Result<usize, WireError>)
        ensures
            r is Ok <==> old(out)@.len() >= COOKIE_REPLY_LEN,
            r is Ok ==> {
                &&& r->Ok_0 == COOKIE_REPLY_LEN
                &&& final(out)@.subrange(0, COOKIE_REPLY_LEN as int) == spec_emit_cookie_reply(
                    self.receiver,
                    self.nonce@,
                    self.encrypted_cookie@,
                )
            },
            r is Err ==> r == Err(WireError::BufferTooSmall),
    {
        write_at(out, 0, &[MSG_COOKIE, 0, 0, 0])?;
        write_at(out, 4, &u32_to_le_arr(self.receiver))?;
        write_at(out, 8, &self.nonce)?;
        write_at(out, 32, &self.encrypted_cookie)?;
        assert(out@.subrange(0, COOKIE_REPLY_LEN as int) =~= spec_emit_cookie_reply(
            self.receiver,
            self.nonce@,
            self.encrypted_cookie@,
        ));
        Ok(COOKIE_REPLY_LEN)
    }
}

/// The bytes `emit_transport_header` describes, as a pure function of the
/// fields.
pub open spec fn spec_emit_transport_header(receiver: u32, counter: u64) -> Seq<u8> {
    Seq::new(
        TRANSPORT_HEADER_LEN as nat,
        |i: int|
            if i < 4 {
                header_bytes(MSG_TRANSPORT)[i]
            } else if i < 8 {
                u32_to_le(receiver)[i - 4]
            } else {
                u64_to_le(counter)[i - 8]
            },
    )
}

proof fn lemma_spec_emit_transport_header_parses(receiver: u32, counter: u64)
    ensures
        ({
            let bytes = spec_emit_transport_header(receiver, counter);
            &&& bytes.len() == TRANSPORT_HEADER_LEN
            &&& header_ok(bytes, MSG_TRANSPORT)
            &&& u32_from_le(bytes.subrange(4, 8)) == receiver
            &&& u64_from_le(bytes.subrange(8, 16)) == counter
        }),
{
    let bytes = spec_emit_transport_header(receiver, counter);
    assert(bytes.len() == TRANSPORT_HEADER_LEN);
    assert(bytes.subrange(0, 4) =~= header_bytes(MSG_TRANSPORT));
    lemma_header_bytes_ok(MSG_TRANSPORT);
    assert(header_ok(bytes, MSG_TRANSPORT));
    assert(bytes.subrange(4, 8) =~= u32_to_le(receiver));
    assert(bytes.subrange(8, 16) =~= u64_to_le(counter));
    lemma_u32_le_roundtrip(receiver);
    lemma_u64_le_roundtrip(counter);
}

proof fn lemma_spec_emit_transport_header_inverse(bytes: Seq<u8>)
    requires
        bytes.len() == TRANSPORT_HEADER_LEN,
        header_ok(bytes, MSG_TRANSPORT),
    ensures
        spec_emit_transport_header(
            u32_from_le(bytes.subrange(4, 8)),
            u64_from_le(bytes.subrange(8, 16)),
        ) =~= bytes,
{
    lemma_header_ok_eq(bytes, MSG_TRANSPORT);
    lemma_u32_le_inverse(bytes.subrange(4, 8));
    lemma_u64_le_inverse(bytes.subrange(8, 16));
}

impl<'a> Transport<'a> {
    pub fn parse(bytes: &'a [u8]) -> (r: Result<Self, WireError>)
        ensures
            r is Ok <==> (bytes@.len() >= TRANSPORT_MIN_LEN && header_ok(bytes@, MSG_TRANSPORT)),
            r is Ok ==> {
                let t = r->Ok_0;
                &&& t.receiver == u32_from_le(bytes@.subrange(4, 8))
                &&& t.counter == u64_from_le(bytes@.subrange(8, 16))
                &&& t.ciphertext@ == bytes@.subrange(16, bytes@.len() as int)
            },
    {
        if bytes.len() < TRANSPORT_MIN_LEN {
            return Err(WireError::TooShort);
        }
        let header = read_array::<4>(bytes, 0)?;
        let (t, r0, r1, r2) = (header[0], header[1], header[2], header[3]);
        if t != MSG_TRANSPORT {
            return Err(WireError::WrongType);
        }
        if r0 != 0 || r1 != 0 || r2 != 0 {
            return Err(WireError::ReservedNonZero);
        }
        let receiver = u32_from_le_arr(read_array::<4>(bytes, 4)?);
        let counter = u64_from_le_arr(read_array::<8>(bytes, 8)?);
        match bytes.get(16..bytes.len()) {
            None => Err(WireError::TooShort),
            Some(ciphertext) => Ok(Self { receiver, counter, ciphertext }),
        }
    }
}

/// Writes the 16-byte transport header; the caller appends the ciphertext.
pub fn emit_transport_header(receiver: u32, counter: u64, out: &mut [u8]) -> (r: Result<
    usize,
    WireError,
>)
    ensures
        r is Ok <==> old(out)@.len() >= TRANSPORT_HEADER_LEN,
        r is Ok ==> {
            &&& r->Ok_0 == TRANSPORT_HEADER_LEN
            &&& final(out)@.subrange(0, TRANSPORT_HEADER_LEN as int) == spec_emit_transport_header(
                receiver,
                counter,
            )
        },
        r is Err ==> r == Err(WireError::BufferTooSmall),
{
    write_at(out, 0, &[MSG_TRANSPORT, 0, 0, 0])?;
    write_at(out, 4, &u32_to_le_arr(receiver))?;
    write_at(out, 8, &u64_to_le_arr(counter))?;
    assert(out@.subrange(0, TRANSPORT_HEADER_LEN as int) =~= spec_emit_transport_header(
        receiver,
        counter,
    ));
    Ok(TRANSPORT_HEADER_LEN)
}

} // verus!

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests;
