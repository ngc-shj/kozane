//! Rosenpass V02 message codecs, free of any cryptography so that Kani can
//! check them without compiling libcrux (M3 plan C1).
//!
//! Every message is an envelope `type ‖ reserved[3] ‖ payload ‖ mac[16] ‖
//! cookie[16]` (upstream `msgs.rs`). Every parser is total: any input yields
//! a value or a `WireError`, never a panic (proved by the harnesses in
//! `proofs`). Reserved bytes must be zero; upstream always sends zeros there.

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

pub const MSG_INIT_HELLO: u8 = 0x81;
pub const MSG_RESP_HELLO: u8 = 0x82;
pub const MSG_INIT_CONF: u8 = 0x83;
pub const MSG_EMPTY_DATA: u8 = 0x84;
pub const MSG_COOKIE_REPLY: u8 = 0x86;

pub const SID_LEN: usize = 4;
pub const TAG_LEN: usize = 16;
pub const MAC_LEN: usize = 16;
pub const COOKIE_LEN: usize = 16;
/// Kyber-512 (round 3) public key and ciphertext.
pub const EPK_LEN: usize = 800;
pub const ECT_LEN: usize = 768;
/// Classic McEliece 460896 (round 3) ciphertext.
pub const SCT_LEN: usize = 188;
/// The initiator's peer id (32 bytes) sealed under ChaCha20-Poly1305.
pub const PIDI_CT_LEN: usize = 32 + TAG_LEN;
/// `pidi[32] ‖ biscuit_no[12] ‖ ck[32]`.
pub const BISCUIT_PT_LEN: usize = 76;
/// XChaCha20-Poly1305 nonce, the sealed plaintext and its tag.
pub const BISCUIT_CT_LEN: usize = 24 + BISCUIT_PT_LEN + TAG_LEN;
pub const EMPTY_DATA_CTR_LEN: usize = 8;

pub const INIT_HELLO_LEN: usize = 1092;
pub const RESP_HELLO_LEN: usize = 1132;
pub const INIT_CONF_LEN: usize = 176;
pub const EMPTY_DATA_LEN: usize = 64;

/// `type ‖ reserved[3]`: every payload, its session ids first, starts here.
pub const HEADER_LEN: usize = 4;
pub const ENVELOPE_LEN: usize = HEADER_LEN + MAC_LEN + COOKIE_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    WrongLength,
    WrongType,
    ReservedNonZero,
    TooShort,
    BufferTooSmall,
}

/// InitHello (0x81, 1092 bytes), sent by the initiator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitHello {
    pub sidi: [u8; SID_LEN],
    pub epki: [u8; EPK_LEN],
    pub sctr: [u8; SCT_LEN],
    pub pidi_ct: [u8; PIDI_CT_LEN],
    pub auth: [u8; TAG_LEN],
    pub mac: [u8; MAC_LEN],
    pub cookie: [u8; COOKIE_LEN],
}

/// RespHello (0x82, 1132 bytes), sent by the responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespHello {
    pub sidr: [u8; SID_LEN],
    pub sidi: [u8; SID_LEN],
    pub ecti: [u8; ECT_LEN],
    pub scti: [u8; SCT_LEN],
    pub auth: [u8; TAG_LEN],
    pub biscuit_ct: [u8; BISCUIT_CT_LEN],
    pub mac: [u8; MAC_LEN],
    pub cookie: [u8; COOKIE_LEN],
}

/// InitConf (0x83, 176 bytes), sent by the initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitConf {
    pub sidi: [u8; SID_LEN],
    pub sidr: [u8; SID_LEN],
    pub biscuit_ct: [u8; BISCUIT_CT_LEN],
    pub auth: [u8; TAG_LEN],
    pub mac: [u8; MAC_LEN],
    pub cookie: [u8; COOKIE_LEN],
}

/// EmptyData (0x84, 64 bytes): the responder's acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyData {
    pub sid: [u8; SID_LEN],
    pub ctr: [u8; EMPTY_DATA_CTR_LEN],
    pub auth: [u8; TAG_LEN],
    pub mac: [u8; MAC_LEN],
    pub cookie: [u8; COOKIE_LEN],
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

/// Whichever `parse` accepts a buffer, `peek_type` (below) reads back that
/// message's own type: `header_ok` already forces the first byte to equal
/// `ty`, and `peek_type` always returns exactly the first byte when there is
/// one (its own `ensures`).
proof fn lemma_peek_type_agrees(bytes: Seq<u8>, ty: u8)
    requires
        header_ok(bytes, ty),
    ensures
        bytes.len() >= 1 && bytes[0] == ty,
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

/// The message type of a datagram, without validating anything else.
pub fn peek_type(bytes: &[u8]) -> (r: Result<u8, WireError>)
    ensures
        r is Ok <==> bytes@.len() >= 1,
        r is Ok ==> r->Ok_0 == bytes@[0],
        r is Err ==> r == Err(WireError::TooShort),
{
    let b = read_array::<1>(bytes, 0)?;
    Ok(b[0])
}

/// The bytes `InitHello::emit` describes, as a pure function of the fields.
pub open spec fn spec_emit_init_hello(
    sidi: Seq<u8>,
    epki: Seq<u8>,
    sctr: Seq<u8>,
    pidi_ct: Seq<u8>,
    auth: Seq<u8>,
    mac: Seq<u8>,
    cookie: Seq<u8>,
) -> Seq<u8>
    recommends
        sidi.len() == SID_LEN,
        epki.len() == EPK_LEN,
        sctr.len() == SCT_LEN,
        pidi_ct.len() == PIDI_CT_LEN,
        auth.len() == TAG_LEN,
        mac.len() == MAC_LEN,
        cookie.len() == COOKIE_LEN,
{
    Seq::new(
        INIT_HELLO_LEN as nat,
        |i: int|
            if i < 4 {
                header_bytes(MSG_INIT_HELLO)[i]
            } else if i < 8 {
                sidi[i - 4]
            } else if i < 808 {
                epki[i - 8]
            } else if i < 996 {
                sctr[i - 808]
            } else if i < 1044 {
                pidi_ct[i - 996]
            } else if i < 1060 {
                auth[i - 1044]
            } else if i < 1076 {
                mac[i - 1060]
            } else {
                cookie[i - 1076]
            },
    )
}

proof fn lemma_spec_emit_init_hello_parses(
    sidi: Seq<u8>,
    epki: Seq<u8>,
    sctr: Seq<u8>,
    pidi_ct: Seq<u8>,
    auth: Seq<u8>,
    mac: Seq<u8>,
    cookie: Seq<u8>,
)
    requires
        sidi.len() == SID_LEN,
        epki.len() == EPK_LEN,
        sctr.len() == SCT_LEN,
        pidi_ct.len() == PIDI_CT_LEN,
        auth.len() == TAG_LEN,
        mac.len() == MAC_LEN,
        cookie.len() == COOKIE_LEN,
    ensures
        ({
            let bytes = spec_emit_init_hello(sidi, epki, sctr, pidi_ct, auth, mac, cookie);
            &&& bytes.len() == INIT_HELLO_LEN
            &&& header_ok(bytes, MSG_INIT_HELLO)
            &&& bytes.subrange(4, 8) =~= sidi
            &&& bytes.subrange(8, 808) =~= epki
            &&& bytes.subrange(808, 996) =~= sctr
            &&& bytes.subrange(996, 1044) =~= pidi_ct
            &&& bytes.subrange(1044, 1060) =~= auth
            &&& bytes.subrange(1060, 1076) =~= mac
            &&& bytes.subrange(1076, 1092) =~= cookie
        }),
{
    let bytes = spec_emit_init_hello(sidi, epki, sctr, pidi_ct, auth, mac, cookie);
    assert(bytes.len() == INIT_HELLO_LEN);
    assert(bytes.subrange(0, 4) =~= header_bytes(MSG_INIT_HELLO));
    lemma_header_bytes_ok(MSG_INIT_HELLO);
    assert(header_ok(bytes, MSG_INIT_HELLO));
    assert(bytes.subrange(4, 8) =~= sidi);
    assert(bytes.subrange(8, 808) =~= epki);
    assert(bytes.subrange(808, 996) =~= sctr);
    assert(bytes.subrange(996, 1044) =~= pidi_ct);
    assert(bytes.subrange(1044, 1060) =~= auth);
    assert(bytes.subrange(1060, 1076) =~= mac);
    assert(bytes.subrange(1076, 1092) =~= cookie);
}

proof fn lemma_spec_emit_init_hello_inverse(bytes: Seq<u8>)
    requires
        bytes.len() == INIT_HELLO_LEN,
        header_ok(bytes, MSG_INIT_HELLO),
    ensures
        spec_emit_init_hello(
            bytes.subrange(4, 8),
            bytes.subrange(8, 808),
            bytes.subrange(808, 996),
            bytes.subrange(996, 1044),
            bytes.subrange(1044, 1060),
            bytes.subrange(1060, 1076),
            bytes.subrange(1076, 1092),
        ) =~= bytes,
{
    lemma_header_ok_eq(bytes, MSG_INIT_HELLO);
}

impl InitHello {
    pub fn parse(bytes: &[u8]) -> (r: Result<Self, WireError>)
        ensures
            r is Ok <==> (bytes@.len() == INIT_HELLO_LEN as int && header_ok(
                bytes@,
                MSG_INIT_HELLO,
            )),
            r is Ok ==> {
                let m = r->Ok_0;
                &&& m.sidi@ == bytes@.subrange(4, 8)
                &&& m.epki@ == bytes@.subrange(8, 808)
                &&& m.sctr@ == bytes@.subrange(808, 996)
                &&& m.pidi_ct@ == bytes@.subrange(996, 1044)
                &&& m.auth@ == bytes@.subrange(1044, 1060)
                &&& m.mac@ == bytes@.subrange(1060, 1076)
                &&& m.cookie@ == bytes@.subrange(1076, 1092)
            },
    {
        if bytes.len() != INIT_HELLO_LEN {
            return Err(WireError::WrongLength);
        }
        let header = read_array::<4>(bytes, 0)?;
        let (t, r0, r1, r2) = (header[0], header[1], header[2], header[3]);
        if t != MSG_INIT_HELLO {
            return Err(WireError::WrongType);
        }
        if r0 != 0 || r1 != 0 || r2 != 0 {
            return Err(WireError::ReservedNonZero);
        }
        let sidi = read_array::<SID_LEN>(bytes, 4)?;
        let epki = read_array::<EPK_LEN>(bytes, 8)?;
        let sctr = read_array::<SCT_LEN>(bytes, 808)?;
        let pidi_ct = read_array::<PIDI_CT_LEN>(bytes, 996)?;
        let auth = read_array::<TAG_LEN>(bytes, 1044)?;
        let mac = read_array::<MAC_LEN>(bytes, 1060)?;
        let cookie = read_array::<COOKIE_LEN>(bytes, 1076)?;
        Ok(Self { sidi, epki, sctr, pidi_ct, auth, mac, cookie })
    }

    pub fn emit(&self, out: &mut [u8]) -> (r: Result<usize, WireError>)
        ensures
            r is Ok <==> old(out)@.len() >= INIT_HELLO_LEN,
            r is Ok ==> {
                &&& r->Ok_0 == INIT_HELLO_LEN
                &&& final(out)@.subrange(0, INIT_HELLO_LEN as int) == spec_emit_init_hello(
                    self.sidi@,
                    self.epki@,
                    self.sctr@,
                    self.pidi_ct@,
                    self.auth@,
                    self.mac@,
                    self.cookie@,
                )
            },
            r is Err ==> r == Err(WireError::BufferTooSmall),
    {
        write_at(out, 0, &[MSG_INIT_HELLO, 0, 0, 0])?;
        write_at(out, 4, &self.sidi)?;
        write_at(out, 8, &self.epki)?;
        write_at(out, 808, &self.sctr)?;
        write_at(out, 996, &self.pidi_ct)?;
        write_at(out, 1044, &self.auth)?;
        write_at(out, 1060, &self.mac)?;
        write_at(out, 1076, &self.cookie)?;
        assert(out@.subrange(0, INIT_HELLO_LEN as int) =~= spec_emit_init_hello(
            self.sidi@,
            self.epki@,
            self.sctr@,
            self.pidi_ct@,
            self.auth@,
            self.mac@,
            self.cookie@,
        ));
        Ok(INIT_HELLO_LEN)
    }
}

/// The bytes `RespHello::emit` describes, as a pure function of the fields.
pub open spec fn spec_emit_resp_hello(
    sidr: Seq<u8>,
    sidi: Seq<u8>,
    ecti: Seq<u8>,
    scti: Seq<u8>,
    auth: Seq<u8>,
    biscuit_ct: Seq<u8>,
    mac: Seq<u8>,
    cookie: Seq<u8>,
) -> Seq<u8>
    recommends
        sidr.len() == SID_LEN,
        sidi.len() == SID_LEN,
        ecti.len() == ECT_LEN,
        scti.len() == SCT_LEN,
        auth.len() == TAG_LEN,
        biscuit_ct.len() == BISCUIT_CT_LEN,
        mac.len() == MAC_LEN,
        cookie.len() == COOKIE_LEN,
{
    Seq::new(
        RESP_HELLO_LEN as nat,
        |i: int|
            if i < 4 {
                header_bytes(MSG_RESP_HELLO)[i]
            } else if i < 8 {
                sidr[i - 4]
            } else if i < 12 {
                sidi[i - 8]
            } else if i < 780 {
                ecti[i - 12]
            } else if i < 968 {
                scti[i - 780]
            } else if i < 984 {
                auth[i - 968]
            } else if i < 1100 {
                biscuit_ct[i - 984]
            } else if i < 1116 {
                mac[i - 1100]
            } else {
                cookie[i - 1116]
            },
    )
}

proof fn lemma_spec_emit_resp_hello_parses(
    sidr: Seq<u8>,
    sidi: Seq<u8>,
    ecti: Seq<u8>,
    scti: Seq<u8>,
    auth: Seq<u8>,
    biscuit_ct: Seq<u8>,
    mac: Seq<u8>,
    cookie: Seq<u8>,
)
    requires
        sidr.len() == SID_LEN,
        sidi.len() == SID_LEN,
        ecti.len() == ECT_LEN,
        scti.len() == SCT_LEN,
        auth.len() == TAG_LEN,
        biscuit_ct.len() == BISCUIT_CT_LEN,
        mac.len() == MAC_LEN,
        cookie.len() == COOKIE_LEN,
    ensures
        ({
            let bytes = spec_emit_resp_hello(sidr, sidi, ecti, scti, auth, biscuit_ct, mac, cookie);
            &&& bytes.len() == RESP_HELLO_LEN
            &&& header_ok(bytes, MSG_RESP_HELLO)
            &&& bytes.subrange(4, 8) =~= sidr
            &&& bytes.subrange(8, 12) =~= sidi
            &&& bytes.subrange(12, 780) =~= ecti
            &&& bytes.subrange(780, 968) =~= scti
            &&& bytes.subrange(968, 984) =~= auth
            &&& bytes.subrange(984, 1100) =~= biscuit_ct
            &&& bytes.subrange(1100, 1116) =~= mac
            &&& bytes.subrange(1116, 1132) =~= cookie
        }),
{
    let bytes = spec_emit_resp_hello(sidr, sidi, ecti, scti, auth, biscuit_ct, mac, cookie);
    assert(bytes.len() == RESP_HELLO_LEN);
    assert(bytes.subrange(0, 4) =~= header_bytes(MSG_RESP_HELLO));
    lemma_header_bytes_ok(MSG_RESP_HELLO);
    assert(header_ok(bytes, MSG_RESP_HELLO));
    assert(bytes.subrange(4, 8) =~= sidr);
    assert(bytes.subrange(8, 12) =~= sidi);
    assert(bytes.subrange(12, 780) =~= ecti);
    assert(bytes.subrange(780, 968) =~= scti);
    assert(bytes.subrange(968, 984) =~= auth);
    assert(bytes.subrange(984, 1100) =~= biscuit_ct);
    assert(bytes.subrange(1100, 1116) =~= mac);
    assert(bytes.subrange(1116, 1132) =~= cookie);
}

proof fn lemma_spec_emit_resp_hello_inverse(bytes: Seq<u8>)
    requires
        bytes.len() == RESP_HELLO_LEN,
        header_ok(bytes, MSG_RESP_HELLO),
    ensures
        spec_emit_resp_hello(
            bytes.subrange(4, 8),
            bytes.subrange(8, 12),
            bytes.subrange(12, 780),
            bytes.subrange(780, 968),
            bytes.subrange(968, 984),
            bytes.subrange(984, 1100),
            bytes.subrange(1100, 1116),
            bytes.subrange(1116, 1132),
        ) =~= bytes,
{
    lemma_header_ok_eq(bytes, MSG_RESP_HELLO);
}

impl RespHello {
    pub fn parse(bytes: &[u8]) -> (r: Result<Self, WireError>)
        ensures
            r is Ok <==> (bytes@.len() == RESP_HELLO_LEN as int && header_ok(
                bytes@,
                MSG_RESP_HELLO,
            )),
            r is Ok ==> {
                let m = r->Ok_0;
                &&& m.sidr@ == bytes@.subrange(4, 8)
                &&& m.sidi@ == bytes@.subrange(8, 12)
                &&& m.ecti@ == bytes@.subrange(12, 780)
                &&& m.scti@ == bytes@.subrange(780, 968)
                &&& m.auth@ == bytes@.subrange(968, 984)
                &&& m.biscuit_ct@ == bytes@.subrange(984, 1100)
                &&& m.mac@ == bytes@.subrange(1100, 1116)
                &&& m.cookie@ == bytes@.subrange(1116, 1132)
            },
    {
        if bytes.len() != RESP_HELLO_LEN {
            return Err(WireError::WrongLength);
        }
        let header = read_array::<4>(bytes, 0)?;
        let (t, r0, r1, r2) = (header[0], header[1], header[2], header[3]);
        if t != MSG_RESP_HELLO {
            return Err(WireError::WrongType);
        }
        if r0 != 0 || r1 != 0 || r2 != 0 {
            return Err(WireError::ReservedNonZero);
        }
        let sidr = read_array::<SID_LEN>(bytes, 4)?;
        let sidi = read_array::<SID_LEN>(bytes, 8)?;
        let ecti = read_array::<ECT_LEN>(bytes, 12)?;
        let scti = read_array::<SCT_LEN>(bytes, 780)?;
        let auth = read_array::<TAG_LEN>(bytes, 968)?;
        let biscuit_ct = read_array::<BISCUIT_CT_LEN>(bytes, 984)?;
        let mac = read_array::<MAC_LEN>(bytes, 1100)?;
        let cookie = read_array::<COOKIE_LEN>(bytes, 1116)?;
        Ok(Self { sidr, sidi, ecti, scti, auth, biscuit_ct, mac, cookie })
    }

    pub fn emit(&self, out: &mut [u8]) -> (r: Result<usize, WireError>)
        ensures
            r is Ok <==> old(out)@.len() >= RESP_HELLO_LEN,
            r is Ok ==> {
                &&& r->Ok_0 == RESP_HELLO_LEN
                &&& final(out)@.subrange(0, RESP_HELLO_LEN as int) == spec_emit_resp_hello(
                    self.sidr@,
                    self.sidi@,
                    self.ecti@,
                    self.scti@,
                    self.auth@,
                    self.biscuit_ct@,
                    self.mac@,
                    self.cookie@,
                )
            },
            r is Err ==> r == Err(WireError::BufferTooSmall),
    {
        write_at(out, 0, &[MSG_RESP_HELLO, 0, 0, 0])?;
        write_at(out, 4, &self.sidr)?;
        write_at(out, 8, &self.sidi)?;
        write_at(out, 12, &self.ecti)?;
        write_at(out, 780, &self.scti)?;
        write_at(out, 968, &self.auth)?;
        write_at(out, 984, &self.biscuit_ct)?;
        write_at(out, 1100, &self.mac)?;
        write_at(out, 1116, &self.cookie)?;
        assert(out@.subrange(0, RESP_HELLO_LEN as int) =~= spec_emit_resp_hello(
            self.sidr@,
            self.sidi@,
            self.ecti@,
            self.scti@,
            self.auth@,
            self.biscuit_ct@,
            self.mac@,
            self.cookie@,
        ));
        Ok(RESP_HELLO_LEN)
    }
}

/// The bytes `InitConf::emit` describes, as a pure function of the fields.
pub open spec fn spec_emit_init_conf(
    sidi: Seq<u8>,
    sidr: Seq<u8>,
    biscuit_ct: Seq<u8>,
    auth: Seq<u8>,
    mac: Seq<u8>,
    cookie: Seq<u8>,
) -> Seq<u8>
    recommends
        sidi.len() == SID_LEN,
        sidr.len() == SID_LEN,
        biscuit_ct.len() == BISCUIT_CT_LEN,
        auth.len() == TAG_LEN,
        mac.len() == MAC_LEN,
        cookie.len() == COOKIE_LEN,
{
    Seq::new(
        INIT_CONF_LEN as nat,
        |i: int|
            if i < 4 {
                header_bytes(MSG_INIT_CONF)[i]
            } else if i < 8 {
                sidi[i - 4]
            } else if i < 12 {
                sidr[i - 8]
            } else if i < 128 {
                biscuit_ct[i - 12]
            } else if i < 144 {
                auth[i - 128]
            } else if i < 160 {
                mac[i - 144]
            } else {
                cookie[i - 160]
            },
    )
}

proof fn lemma_spec_emit_init_conf_parses(
    sidi: Seq<u8>,
    sidr: Seq<u8>,
    biscuit_ct: Seq<u8>,
    auth: Seq<u8>,
    mac: Seq<u8>,
    cookie: Seq<u8>,
)
    requires
        sidi.len() == SID_LEN,
        sidr.len() == SID_LEN,
        biscuit_ct.len() == BISCUIT_CT_LEN,
        auth.len() == TAG_LEN,
        mac.len() == MAC_LEN,
        cookie.len() == COOKIE_LEN,
    ensures
        ({
            let bytes = spec_emit_init_conf(sidi, sidr, biscuit_ct, auth, mac, cookie);
            &&& bytes.len() == INIT_CONF_LEN
            &&& header_ok(bytes, MSG_INIT_CONF)
            &&& bytes.subrange(4, 8) =~= sidi
            &&& bytes.subrange(8, 12) =~= sidr
            &&& bytes.subrange(12, 128) =~= biscuit_ct
            &&& bytes.subrange(128, 144) =~= auth
            &&& bytes.subrange(144, 160) =~= mac
            &&& bytes.subrange(160, 176) =~= cookie
        }),
{
    let bytes = spec_emit_init_conf(sidi, sidr, biscuit_ct, auth, mac, cookie);
    assert(bytes.len() == INIT_CONF_LEN);
    assert(bytes.subrange(0, 4) =~= header_bytes(MSG_INIT_CONF));
    lemma_header_bytes_ok(MSG_INIT_CONF);
    assert(header_ok(bytes, MSG_INIT_CONF));
    assert(bytes.subrange(4, 8) =~= sidi);
    assert(bytes.subrange(8, 12) =~= sidr);
    assert(bytes.subrange(12, 128) =~= biscuit_ct);
    assert(bytes.subrange(128, 144) =~= auth);
    assert(bytes.subrange(144, 160) =~= mac);
    assert(bytes.subrange(160, 176) =~= cookie);
}

proof fn lemma_spec_emit_init_conf_inverse(bytes: Seq<u8>)
    requires
        bytes.len() == INIT_CONF_LEN,
        header_ok(bytes, MSG_INIT_CONF),
    ensures
        spec_emit_init_conf(
            bytes.subrange(4, 8),
            bytes.subrange(8, 12),
            bytes.subrange(12, 128),
            bytes.subrange(128, 144),
            bytes.subrange(144, 160),
            bytes.subrange(160, 176),
        ) =~= bytes,
{
    lemma_header_ok_eq(bytes, MSG_INIT_CONF);
}

impl InitConf {
    pub fn parse(bytes: &[u8]) -> (r: Result<Self, WireError>)
        ensures
            r is Ok <==> (bytes@.len() == INIT_CONF_LEN as int && header_ok(
                bytes@,
                MSG_INIT_CONF,
            )),
            r is Ok ==> {
                let m = r->Ok_0;
                &&& m.sidi@ == bytes@.subrange(4, 8)
                &&& m.sidr@ == bytes@.subrange(8, 12)
                &&& m.biscuit_ct@ == bytes@.subrange(12, 128)
                &&& m.auth@ == bytes@.subrange(128, 144)
                &&& m.mac@ == bytes@.subrange(144, 160)
                &&& m.cookie@ == bytes@.subrange(160, 176)
            },
    {
        if bytes.len() != INIT_CONF_LEN {
            return Err(WireError::WrongLength);
        }
        let header = read_array::<4>(bytes, 0)?;
        let (t, r0, r1, r2) = (header[0], header[1], header[2], header[3]);
        if t != MSG_INIT_CONF {
            return Err(WireError::WrongType);
        }
        if r0 != 0 || r1 != 0 || r2 != 0 {
            return Err(WireError::ReservedNonZero);
        }
        let sidi = read_array::<SID_LEN>(bytes, 4)?;
        let sidr = read_array::<SID_LEN>(bytes, 8)?;
        let biscuit_ct = read_array::<BISCUIT_CT_LEN>(bytes, 12)?;
        let auth = read_array::<TAG_LEN>(bytes, 128)?;
        let mac = read_array::<MAC_LEN>(bytes, 144)?;
        let cookie = read_array::<COOKIE_LEN>(bytes, 160)?;
        Ok(Self { sidi, sidr, biscuit_ct, auth, mac, cookie })
    }

    /// Total: for any buffer, this returns `Ok` iff the buffer is at least
    /// `INIT_CONF_LEN` bytes, and never panics.
    pub fn emit(&self, out: &mut [u8]) -> (r: Result<usize, WireError>)
        ensures
            r is Ok <==> old(out)@.len() >= INIT_CONF_LEN,
            r is Ok ==> {
                &&& r->Ok_0 == INIT_CONF_LEN
                &&& final(out)@.subrange(0, INIT_CONF_LEN as int) == spec_emit_init_conf(
                    self.sidi@,
                    self.sidr@,
                    self.biscuit_ct@,
                    self.auth@,
                    self.mac@,
                    self.cookie@,
                )
            },
            r is Err ==> r == Err(WireError::BufferTooSmall),
    {
        write_at(out, 0, &[MSG_INIT_CONF, 0, 0, 0])?;
        write_at(out, 4, &self.sidi)?;
        write_at(out, 8, &self.sidr)?;
        write_at(out, 12, &self.biscuit_ct)?;
        write_at(out, 128, &self.auth)?;
        write_at(out, 144, &self.mac)?;
        write_at(out, 160, &self.cookie)?;
        assert(out@.subrange(0, INIT_CONF_LEN as int) =~= spec_emit_init_conf(
            self.sidi@,
            self.sidr@,
            self.biscuit_ct@,
            self.auth@,
            self.mac@,
            self.cookie@,
        ));
        Ok(INIT_CONF_LEN)
    }
}

/// The bytes `EmptyData::emit` describes, as a pure function of the fields.
pub open spec fn spec_emit_empty_data(
    sid: Seq<u8>,
    ctr: Seq<u8>,
    auth: Seq<u8>,
    mac: Seq<u8>,
    cookie: Seq<u8>,
) -> Seq<u8>
    recommends
        sid.len() == SID_LEN,
        ctr.len() == EMPTY_DATA_CTR_LEN,
        auth.len() == TAG_LEN,
        mac.len() == MAC_LEN,
        cookie.len() == COOKIE_LEN,
{
    Seq::new(
        EMPTY_DATA_LEN as nat,
        |i: int|
            if i < 4 {
                header_bytes(MSG_EMPTY_DATA)[i]
            } else if i < 8 {
                sid[i - 4]
            } else if i < 16 {
                ctr[i - 8]
            } else if i < 32 {
                auth[i - 16]
            } else if i < 48 {
                mac[i - 32]
            } else {
                cookie[i - 48]
            },
    )
}

proof fn lemma_spec_emit_empty_data_parses(
    sid: Seq<u8>,
    ctr: Seq<u8>,
    auth: Seq<u8>,
    mac: Seq<u8>,
    cookie: Seq<u8>,
)
    requires
        sid.len() == SID_LEN,
        ctr.len() == EMPTY_DATA_CTR_LEN,
        auth.len() == TAG_LEN,
        mac.len() == MAC_LEN,
        cookie.len() == COOKIE_LEN,
    ensures
        ({
            let bytes = spec_emit_empty_data(sid, ctr, auth, mac, cookie);
            &&& bytes.len() == EMPTY_DATA_LEN
            &&& header_ok(bytes, MSG_EMPTY_DATA)
            &&& bytes.subrange(4, 8) =~= sid
            &&& bytes.subrange(8, 16) =~= ctr
            &&& bytes.subrange(16, 32) =~= auth
            &&& bytes.subrange(32, 48) =~= mac
            &&& bytes.subrange(48, 64) =~= cookie
        }),
{
    let bytes = spec_emit_empty_data(sid, ctr, auth, mac, cookie);
    assert(bytes.len() == EMPTY_DATA_LEN);
    assert(bytes.subrange(0, 4) =~= header_bytes(MSG_EMPTY_DATA));
    lemma_header_bytes_ok(MSG_EMPTY_DATA);
    assert(header_ok(bytes, MSG_EMPTY_DATA));
    assert(bytes.subrange(4, 8) =~= sid);
    assert(bytes.subrange(8, 16) =~= ctr);
    assert(bytes.subrange(16, 32) =~= auth);
    assert(bytes.subrange(32, 48) =~= mac);
    assert(bytes.subrange(48, 64) =~= cookie);
}

proof fn lemma_spec_emit_empty_data_inverse(bytes: Seq<u8>)
    requires
        bytes.len() == EMPTY_DATA_LEN,
        header_ok(bytes, MSG_EMPTY_DATA),
    ensures
        spec_emit_empty_data(
            bytes.subrange(4, 8),
            bytes.subrange(8, 16),
            bytes.subrange(16, 32),
            bytes.subrange(32, 48),
            bytes.subrange(48, 64),
        ) =~= bytes,
{
    lemma_header_ok_eq(bytes, MSG_EMPTY_DATA);
}

impl EmptyData {
    pub fn parse(bytes: &[u8]) -> (r: Result<Self, WireError>)
        ensures
            r is Ok <==> (bytes@.len() == EMPTY_DATA_LEN as int && header_ok(
                bytes@,
                MSG_EMPTY_DATA,
            )),
            r is Ok ==> {
                let m = r->Ok_0;
                &&& m.sid@ == bytes@.subrange(4, 8)
                &&& m.ctr@ == bytes@.subrange(8, 16)
                &&& m.auth@ == bytes@.subrange(16, 32)
                &&& m.mac@ == bytes@.subrange(32, 48)
                &&& m.cookie@ == bytes@.subrange(48, 64)
            },
    {
        if bytes.len() != EMPTY_DATA_LEN {
            return Err(WireError::WrongLength);
        }
        let header = read_array::<4>(bytes, 0)?;
        let (t, r0, r1, r2) = (header[0], header[1], header[2], header[3]);
        if t != MSG_EMPTY_DATA {
            return Err(WireError::WrongType);
        }
        if r0 != 0 || r1 != 0 || r2 != 0 {
            return Err(WireError::ReservedNonZero);
        }
        let sid = read_array::<SID_LEN>(bytes, 4)?;
        let ctr = read_array::<EMPTY_DATA_CTR_LEN>(bytes, 8)?;
        let auth = read_array::<TAG_LEN>(bytes, 16)?;
        let mac = read_array::<MAC_LEN>(bytes, 32)?;
        let cookie = read_array::<COOKIE_LEN>(bytes, 48)?;
        Ok(Self { sid, ctr, auth, mac, cookie })
    }

    pub fn emit(&self, out: &mut [u8]) -> (r: Result<usize, WireError>)
        ensures
            r is Ok <==> old(out)@.len() >= EMPTY_DATA_LEN,
            r is Ok ==> {
                &&& r->Ok_0 == EMPTY_DATA_LEN
                &&& final(out)@.subrange(0, EMPTY_DATA_LEN as int) == spec_emit_empty_data(
                    self.sid@,
                    self.ctr@,
                    self.auth@,
                    self.mac@,
                    self.cookie@,
                )
            },
            r is Err ==> r == Err(WireError::BufferTooSmall),
    {
        write_at(out, 0, &[MSG_EMPTY_DATA, 0, 0, 0])?;
        write_at(out, 4, &self.sid)?;
        write_at(out, 8, &self.ctr)?;
        write_at(out, 16, &self.auth)?;
        write_at(out, 32, &self.mac)?;
        write_at(out, 48, &self.cookie)?;
        assert(out@.subrange(0, EMPTY_DATA_LEN as int) =~= spec_emit_empty_data(
            self.sid@,
            self.ctr@,
            self.auth@,
            self.mac@,
            self.cookie@,
        ));
        Ok(EMPTY_DATA_LEN)
    }
}

} // verus!

const _: () = assert!(INIT_HELLO_LEN == ENVELOPE_LEN + SID_LEN + EPK_LEN + SCT_LEN + PIDI_CT_LEN + TAG_LEN);
const _: () = assert!(RESP_HELLO_LEN == ENVELOPE_LEN + 2 * SID_LEN + ECT_LEN + SCT_LEN + TAG_LEN + BISCUIT_CT_LEN);
const _: () = assert!(INIT_CONF_LEN == ENVELOPE_LEN + 2 * SID_LEN + BISCUIT_CT_LEN + TAG_LEN);
const _: () = assert!(EMPTY_DATA_LEN == ENVELOPE_LEN + SID_LEN + EMPTY_DATA_CTR_LEN + TAG_LEN);

/// The mac covers every byte before it, the cookie every byte before it.
pub const fn mac_offset(len: usize) -> usize {
    len.saturating_sub(MAC_LEN + COOKIE_LEN)
}

pub const fn cookie_offset(len: usize) -> usize {
    len.saturating_sub(COOKIE_LEN)
}

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests;
