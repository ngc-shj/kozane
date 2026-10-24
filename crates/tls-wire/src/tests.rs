#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

use std::vec;
use std::vec::Vec;

use super::der::{MAX_SIG_LEN, MIN_SIG_LEN, ecdsa_sig_value};
use super::framing::Reassembler;
use super::hello::{client_hello, walk};
use super::record::{alert, change_cipher_spec, header, inner_plaintext};
use super::*;

// --- the ClientHello builder the bound tests share ---

fn vec8(data: &[u8]) -> Vec<u8> {
    let mut v = vec![u8::try_from(data.len()).unwrap()];
    v.extend_from_slice(data);
    v
}

fn vec16(data: &[u8]) -> Vec<u8> {
    let mut v = u16::try_from(data.len()).unwrap().to_be_bytes().to_vec();
    v.extend_from_slice(data);
    v
}

fn u16s(list: &[u16]) -> Vec<u8> {
    list.iter().flat_map(|v| v.to_be_bytes()).collect()
}

fn versions(list: &[u16]) -> Vec<u8> {
    vec8(&u16s(list))
}

fn list16(list: &[u16]) -> Vec<u8> {
    vec16(&u16s(list))
}

/// key_share client_shares with (group, key length) entries.
fn shares(entries: &[(u16, usize)]) -> Vec<u8> {
    let mut v = Vec::new();
    for &(group, len) in entries {
        v.extend_from_slice(&group.to_be_bytes());
        v.extend_from_slice(&vec16(&vec![0x42; len]));
    }
    vec16(&v)
}

fn alpn(names: &[&[u8]]) -> Vec<u8> {
    let list: Vec<u8> = names.iter().flat_map(|n| vec8(n)).collect();
    vec16(&list)
}

fn sni(name: &[u8]) -> Vec<u8> {
    let mut entry = vec![0u8];
    entry.extend_from_slice(&vec16(name));
    vec16(&entry)
}

struct Ch {
    legacy_version: u16,
    session_id: Vec<u8>,
    suites: Vec<u16>,
    compression: Vec<u8>,
    exts: Vec<(u16, Vec<u8>)>,
}

impl Ch {
    /// The smallest ClientHello the profile accepts.
    fn good() -> Self {
        Ch {
            legacy_version: TLS12,
            session_id: vec![0x11; 32],
            suites: vec![0x1301, TLS_CHACHA20_POLY1305_SHA256],
            compression: vec![0],
            exts: vec![
                (ext::SUPPORTED_VERSIONS, versions(&[TLS13])),
                (ext::SUPPORTED_GROUPS, list16(&[X25519MLKEM768])),
                (ext::KEY_SHARE, shares(&[(X25519MLKEM768, CLIENT_SHARE_LEN)])),
                (ext::SIGNATURE_ALGORITHMS, list16(&[0x0804, ECDSA_SECP256R1_SHA256])),
            ],
        }
    }

    fn set(mut self, ty: u16, data: Vec<u8>) -> Self {
        match self.exts.iter_mut().find(|(t, _)| *t == ty) {
            Some(e) => e.1 = data,
            None => self.exts.push((ty, data)),
        }
        self
    }

    fn push(mut self, ty: u16, data: Vec<u8>) -> Self {
        self.exts.push((ty, data));
        self
    }

    fn without(mut self, ty: u16) -> Self {
        self.exts.retain(|(t, _)| *t != ty);
        self
    }

    fn body(&self) -> Vec<u8> {
        let mut b = self.legacy_version.to_be_bytes().to_vec();
        b.extend_from_slice(&[0x5a; 32]);
        b.extend_from_slice(&vec8(&self.session_id));
        b.extend_from_slice(&list16(&self.suites));
        b.extend_from_slice(&vec8(&self.compression));
        let mut exts = Vec::new();
        for (ty, data) in &self.exts {
            exts.extend_from_slice(&ty.to_be_bytes());
            exts.extend_from_slice(&vec16(data));
        }
        b.extend_from_slice(&vec16(&exts));
        b
    }

    /// Header and body.
    fn message(&self) -> Vec<u8> {
        let body = self.body();
        let mut m = vec![hs::CLIENT_HELLO];
        m.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
        m.extend_from_slice(&body);
        m
    }

    /// Padded (an unknown extension) to exactly `total` message bytes.
    fn padded_to(self, total: usize) -> Self {
        let now = self.message().len();
        self.push(21, vec![0; total - now - 4])
    }
}

fn parse(ch: &Ch) -> Result<(), Refusal> {
    client_hello(&ch.body()).map(|_| ())
}

/// A ClientHello's body from captured records (one handshake message).
fn captured_body(records: &[u8]) -> Vec<u8> {
    let mut r = Reassembler::new();
    let mut rest = records;
    let mut first = true;
    while !rest.is_empty() {
        let h = header(rest[..5].try_into().unwrap(), first).unwrap();
        first = false;
        r.push(&rest[5..5 + h.len]).unwrap();
        rest = &rest[5 + h.len..];
    }
    let m = r.peek().unwrap().unwrap();
    assert_eq!(m.msg_type, hs::CLIENT_HELLO);
    m.body.to_vec()
}

const CORPUS: &str = "src/__fuzz__/tests__parsers_never_panic_and_stay_in_bounds/corpus";

fn seed(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS).join(name)).unwrap()
}

// --- constants and the refusal table ---

#[test]
fn record_limits_are_rfc_8446s() {
    assert_eq!((RECORD_HEADER_LEN, MAX_PLAINTEXT, MAX_CIPHERTEXT), (5, 16_384, 16_640));
}

#[test]
fn refusal_codes_are_their_index_and_fit_the_audit_width() {
    for (i, r) in Refusal::ALL.iter().enumerate() {
        assert_eq!(usize::from(r.code()), i, "{r:?}");
    }
    assert!(Refusal::ALL.len() <= 32);
}

/// `Refusal::ALL` lists every variant once: `position` is exhaustive, so a
/// new variant does not compile until it is given the next position, and
/// the positions must be exactly ALL's indices up to its last (a variant
/// missing from ALL would encode to audit's unknown code, unnamed).
#[test]
fn refusal_all_lists_every_variant_once() {
    fn position(r: Refusal) -> usize {
        match r {
            Refusal::RecordType => 0,
            Refusal::RecordVersion => 1,
            Refusal::RecordOverflow => 2,
            Refusal::BadChangeCipherSpec => 3,
            Refusal::UnexpectedChangeCipherSpec => 4,
            Refusal::InnerAllZero => 5,
            Refusal::InnerType => 6,
            Refusal::HandshakeTooLong => 7,
            Refusal::NotAtRecordBoundary => 8,
            Refusal::UnexpectedMessage => 9,
            Refusal::Decode => 10,
            Refusal::LegacyVersion => 11,
            Refusal::SessionIdTooLong => 12,
            Refusal::NoChaCha => 13,
            Refusal::Compression => 14,
            Refusal::DuplicateExtension => 15,
            Refusal::NoTls13 => 16,
            Refusal::NoPqGroup => 17,
            Refusal::NoPqShare => 18,
            Refusal::KeyShareLength => 19,
            Refusal::DuplicateKeyShare => 20,
            Refusal::NoSignatureAlgorithm => 21,
            Refusal::NoApplicationProtocol => 22,
            Refusal::PskNotLast => 23,
            Refusal::PskWithoutModes => 24,
            Refusal::BadKeyShare => 25,
            Refusal::DecryptError => 26,
            Refusal::BadRecordMac => 27,
            Refusal::KeyUpdateValue => 28,
            Refusal::Internal => 29,
            Refusal::PeerAlert => 30,
            Refusal::Closed => 31,
        }
    }
    for (i, r) in Refusal::ALL.iter().enumerate() {
        assert_eq!(position(*r), i, "{r:?}");
    }
    assert_eq!(position(Refusal::Closed) + 1, Refusal::ALL.len());
}

#[test]
fn refusal_names_are_the_variant_names() {
    for r in Refusal::ALL {
        assert_eq!(r.name(), std::format!("{r:?}"));
    }
}

#[test]
fn every_refusal_but_the_peers_own_answers_with_an_alert() {
    for r in Refusal::ALL {
        assert_eq!(r.alert().is_none(), matches!(r, Refusal::PeerAlert | Refusal::Closed), "{r:?}");
    }
    assert_eq!(Refusal::NoPqGroup.alert(), Some(Alert::HandshakeFailure));
    assert_eq!(Refusal::NoTls13.alert(), Some(Alert::ProtocolVersion));
    assert_eq!(Refusal::DecryptError.alert(), Some(Alert::DecryptError));
    assert_eq!(Refusal::BadRecordMac.alert(), Some(Alert::BadRecordMac));
    assert_eq!(Refusal::UnexpectedChangeCipherSpec.alert(), Some(Alert::UnexpectedMessage));
    assert_eq!(Refusal::KeyUpdateValue.alert(), Some(Alert::IllegalParameter));
}

// --- record headers ---

fn hdr(ty: u8, version: u16, len: usize) -> [u8; 5] {
    let [v0, v1] = version.to_be_bytes();
    let [l0, l1] = u16::try_from(len).unwrap().to_be_bytes();
    [ty, v0, v1, l0, l1]
}

#[test]
fn plaintext_record_of_2_14_is_accepted_and_one_more_is_overflow() {
    assert_eq!(header(&hdr(22, TLS12, MAX_PLAINTEXT), false).unwrap().len, MAX_PLAINTEXT);
    assert_eq!(header(&hdr(22, TLS12, MAX_PLAINTEXT + 1), false), Err(Refusal::RecordOverflow));
    assert_eq!(header(&hdr(21, TLS12, MAX_PLAINTEXT + 1), false), Err(Refusal::RecordOverflow));
}

#[test]
fn ciphertext_record_of_2_14_plus_256_is_accepted_and_one_more_is_overflow() {
    assert_eq!(header(&hdr(23, TLS12, MAX_CIPHERTEXT), false).unwrap().len, MAX_CIPHERTEXT);
    assert_eq!(header(&hdr(23, TLS12, MAX_CIPHERTEXT + 1), false), Err(Refusal::RecordOverflow));
}

#[test]
fn legacy_version_0x0301_is_allowed_on_the_first_record_only() {
    assert!(header(&hdr(22, TLS10, 10), true).is_ok());
    assert_eq!(header(&hdr(22, TLS10, 10), false), Err(Refusal::RecordVersion));
    assert_eq!(header(&hdr(22, 0x0302, 10), true), Err(Refusal::RecordVersion));
    assert_eq!(header(&hdr(22, TLS13, 10), false), Err(Refusal::RecordVersion));
}

#[test]
fn unknown_content_type_is_refused() {
    assert_eq!(header(&hdr(24, TLS12, 10), false), Err(Refusal::RecordType));
    assert_eq!(header(&hdr(19, TLS12, 10), false), Err(Refusal::RecordType));
}

#[test]
fn zero_length_records_are_refused_except_application_data() {
    assert_eq!(header(&hdr(22, TLS12, 0), false), Err(Refusal::Decode));
    assert_eq!(header(&hdr(21, TLS12, 0), false), Err(Refusal::Decode));
    assert_eq!(header(&hdr(20, TLS12, 0), false), Err(Refusal::Decode));
    assert!(header(&hdr(23, TLS12, 0), false).is_ok());
}

#[test]
fn change_cipher_spec_is_exactly_one_byte_0x01() {
    assert_eq!(change_cipher_spec(&[1]), Ok(()));
    assert_eq!(change_cipher_spec(&[2]), Err(Refusal::BadChangeCipherSpec));
    assert_eq!(change_cipher_spec(&[1, 1]), Err(Refusal::BadChangeCipherSpec));
    assert_eq!(change_cipher_spec(&[]), Err(Refusal::BadChangeCipherSpec));
}

#[test]
fn inner_plaintext_strips_padding_and_takes_the_last_nonzero_byte_as_type() {
    assert_eq!(inner_plaintext(&[b'h', b'i', 23, 0, 0, 0]), Ok((ContentType::ApplicationData, &b"hi"[..])));
    assert_eq!(inner_plaintext(&[1, 0, 21]), Ok((ContentType::Alert, &[1, 0][..])));
    assert_eq!(inner_plaintext(&[23]), Ok((ContentType::ApplicationData, &[][..])));
}

#[test]
fn all_zero_inner_plaintext_is_refused() {
    assert_eq!(inner_plaintext(&[0, 0, 0]), Err(Refusal::InnerAllZero));
    assert_eq!(inner_plaintext(&[]), Err(Refusal::InnerAllZero));
}

#[test]
fn inner_type_must_be_handshake_alert_or_application_data() {
    assert_eq!(inner_plaintext(&[1, 20]), Err(Refusal::InnerType));
    assert_eq!(inner_plaintext(&[1, 24, 0]), Err(Refusal::InnerType));
    assert_eq!(inner_plaintext(&[22]), Err(Refusal::Decode));
}

#[test]
fn inner_plaintext_of_2_14_plus_1_is_accepted_and_one_more_is_overflow() {
    let mut p = vec![0x41u8; MAX_PLAINTEXT + 1];
    p[MAX_PLAINTEXT] = 23;
    assert!(inner_plaintext(&p).is_ok());
    p.push(0);
    assert_eq!(inner_plaintext(&p), Err(Refusal::RecordOverflow));
}

#[test]
fn alert_body_is_two_bytes() {
    assert_eq!(alert(&[2, 40]), Ok((2, 40)));
    assert_eq!(alert(&[2]), Err(Refusal::Decode));
    assert_eq!(alert(&[2, 40, 0]), Err(Refusal::Decode));
}

// --- handshake framing ---

#[test]
fn a_message_may_span_records() {
    let m = Ch::good().message();
    let mut r = Reassembler::new();
    r.push(&m[..3]).unwrap();
    assert_eq!(r.peek(), Ok(None));
    r.push(&m[3..100]).unwrap();
    assert_eq!(r.peek(), Ok(None));
    r.push(&m[100..]).unwrap();
    let got = r.peek().unwrap().unwrap();
    assert_eq!((got.msg_type, got.bytes), (hs::CLIENT_HELLO, &m[..]));
}

#[test]
fn several_messages_may_share_a_record() {
    let mut rec = vec![hs::KEY_UPDATE, 0, 0, 1, 0];
    rec.extend_from_slice(&[hs::KEY_UPDATE, 0, 0, 1, 1]);
    let mut r = Reassembler::new();
    r.push(&rec).unwrap();
    let first = r.peek().unwrap().unwrap();
    assert_eq!(first.body, &[0]);
    let n = first.bytes.len();
    r.consume(n);
    assert!(!r.is_empty());
    assert_eq!(r.peek().unwrap().unwrap().body, &[1]);
    r.consume(5);
    assert!(r.is_zeroized());
}

#[test]
fn handshake_message_of_8192_bytes_is_accepted_and_8193_refused() {
    let ok = Ch::good().padded_to(MAX_HANDSHAKE).message();
    assert_eq!(ok.len(), MAX_HANDSHAKE);
    let mut r = Reassembler::new();
    r.push(&ok).unwrap();
    assert_eq!(r.peek().unwrap().unwrap().bytes.len(), MAX_HANDSHAKE);

    let big = Ch::good().padded_to(MAX_HANDSHAKE + 1).message();
    let mut r = Reassembler::new();
    // Refused from the header alone, before the body.
    r.push(&big[..4]).unwrap();
    assert_eq!(r.peek(), Err(Refusal::HandshakeTooLong));
    let mut r = Reassembler::new();
    assert_eq!(r.push(&big), Err(Refusal::HandshakeTooLong));
}

#[test]
fn zero_length_handshake_fragment_is_refused() {
    assert_eq!(Reassembler::new().push(&[]), Err(Refusal::Decode));
}

#[test]
fn consume_zeroes_what_it_removes() {
    let mut r = Reassembler::new();
    r.push(&[hs::FINISHED, 0, 0, 2, 0xaa, 0xbb, 0xcc]).unwrap();
    r.consume(6);
    assert_eq!(r.peek(), Ok(None));
    r.wipe();
    assert!(r.is_zeroized());
}

// --- ClientHello: captured clients ---

#[test]
fn openssl_and_curl_client_hellos_with_x25519mlkem768_are_accepted() {
    for name in ["seed-openssl-mlkem768", "seed-openssl-default", "seed-curl-mlkem768", "seed-curl-default"] {
        let body = captured_body(&seed(name));
        let ch = client_hello(&body).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(ch.key_share.len(), CLIENT_SHARE_LEN, "{name}");
    }
    let body = captured_body(&seed("seed-openssl-mlkem768"));
    let ch = client_hello(&body).unwrap();
    assert!(ch.alpn);
    assert_eq!(ch.server_name, Some(&b"gw.example"[..]));
    let body = captured_body(&seed("seed-curl-default"));
    assert!(client_hello(&body).unwrap().alpn);
}

#[test]
fn a_classical_only_client_hello_is_refused_with_no_pq_group() {
    assert_eq!(parse_seed("seed-openssl-x25519"), Err(Refusal::NoPqGroup));
}

fn parse_seed(name: &str) -> Result<(), Refusal> {
    client_hello(&captured_body(&seed(name))).map(|_| ())
}

#[test]
fn a_tls12_only_client_hello_is_refused_with_no_tls13() {
    assert_eq!(parse_seed("seed-openssl-tls12"), Err(Refusal::NoTls13));
}

// --- ClientHello: bounds and rules ---

#[test]
fn smallest_profile_client_hello_is_accepted() {
    let ch = Ch::good();
    let body = ch.body();
    let got = client_hello(&body).unwrap();
    assert_eq!(got.session_id, &[0x11; 32]);
    assert!(!got.alpn && !got.early_data && got.server_name.is_none());
}

#[test]
fn session_id_of_32_is_echoed_and_33_refused() {
    let mut ch = Ch::good();
    ch.session_id = vec![7; 32];
    assert_eq!(client_hello(&ch.body()).unwrap().session_id, &[7; 32]);
    ch.session_id = vec![7; 33];
    assert_eq!(parse(&ch), Err(Refusal::SessionIdTooLong));
}

#[test]
fn client_hello_of_8192_bytes_is_accepted_and_8193_refused() {
    let ok = Ch::good().padded_to(MAX_HANDSHAKE);
    assert_eq!(ok.message().len(), MAX_HANDSHAKE);
    assert_eq!(parse(&ok), Ok(()));
    let big = Ch::good().padded_to(MAX_HANDSHAKE + 1);
    assert_eq!(parse(&big), Err(Refusal::HandshakeTooLong));
}

#[test]
fn key_share_of_1216_is_accepted_and_1215_or_1217_refused() {
    let ch = Ch::good().set(ext::KEY_SHARE, shares(&[(X25519MLKEM768, 1216)]));
    assert_eq!(client_hello(&ch.body()).unwrap().key_share.len(), 1216);
    for len in [1215, 1217] {
        let ch = Ch::good().set(ext::KEY_SHARE, shares(&[(X25519MLKEM768, len)]));
        assert_eq!(parse(&ch), Err(Refusal::KeyShareLength), "{len}");
    }
}

#[test]
fn duplicate_extension_is_refused() {
    let ch = Ch::good().push(ext::SUPPORTED_VERSIONS, versions(&[TLS13]));
    assert_eq!(parse(&ch), Err(Refusal::DuplicateExtension));
    // Unknown types too.
    let ch = Ch::good().push(0x7777, vec![]).push(0x7777, vec![1]);
    assert_eq!(parse(&ch), Err(Refusal::DuplicateExtension));
}

#[test]
fn more_than_64_extensions_are_refused() {
    let mut ch = Ch::good();
    for t in 0..(MAX_EXTENSIONS - ch.exts.len()) {
        ch = ch.push(0x7000 + u16::try_from(t).unwrap(), vec![]);
    }
    assert_eq!(parse(&ch), Ok(()));
    let ch = ch.push(0x6fff, vec![]);
    assert_eq!(parse(&ch), Err(Refusal::DuplicateExtension));
}

#[test]
fn unknown_extensions_are_skipped() {
    let ch = Ch::good().push(0xfafa, vec![]).push(0x1234, vec![1, 2, 3]);
    assert_eq!(parse(&ch), Ok(()));
}

#[test]
fn duplicate_key_share_group_is_refused() {
    let ch = Ch::good().set(ext::KEY_SHARE, shares(&[(X25519MLKEM768, CLIENT_SHARE_LEN), (0x6a6a, 1), (0x6a6a, 1)]));
    assert_eq!(parse(&ch), Err(Refusal::DuplicateKeyShare));
    let ch = Ch::good().set(ext::KEY_SHARE, shares(&[(X25519MLKEM768, CLIENT_SHARE_LEN), (X25519MLKEM768, CLIENT_SHARE_LEN)]));
    assert_eq!(parse(&ch), Err(Refusal::DuplicateKeyShare));
}

#[test]
fn more_than_16_key_shares_are_refused() {
    let mut entries = vec![(X25519MLKEM768, CLIENT_SHARE_LEN)];
    entries.extend((0..MAX_KEY_SHARES - 1).map(|g| (0x6000 + u16::try_from(g).unwrap(), 1)));
    assert_eq!(parse(&Ch::good().set(ext::KEY_SHARE, shares(&entries))), Ok(()));
    entries.push((0x5fff, 1));
    assert_eq!(parse(&Ch::good().set(ext::KEY_SHARE, shares(&entries))), Err(Refusal::Decode));
}

#[test]
fn pq_group_supported_without_a_share_has_its_own_reason() {
    let ch = Ch::good().set(ext::KEY_SHARE, shares(&[(0x6a6a, 32)]));
    assert_eq!(parse(&ch), Err(Refusal::NoPqShare));
    assert_eq!(parse(&Ch::good().without(ext::KEY_SHARE)), Err(Refusal::NoPqShare));
    let ch = Ch::good().set(ext::KEY_SHARE, shares(&[]));
    assert_eq!(parse(&ch), Err(Refusal::NoPqShare));
}

#[test]
fn supported_groups_without_x25519mlkem768_is_no_pq_group() {
    assert_eq!(parse(&Ch::good().set(ext::SUPPORTED_GROUPS, list16(&[0x6a6a]))), Err(Refusal::NoPqGroup));
    assert_eq!(parse(&Ch::good().without(ext::SUPPORTED_GROUPS)), Err(Refusal::NoPqGroup));
}

#[test]
fn supported_versions_must_include_tls13() {
    assert_eq!(parse(&Ch::good().set(ext::SUPPORTED_VERSIONS, versions(&[TLS12]))), Err(Refusal::NoTls13));
    assert_eq!(parse(&Ch::good().without(ext::SUPPORTED_VERSIONS)), Err(Refusal::NoTls13));
    assert_eq!(parse(&Ch::good().set(ext::SUPPORTED_VERSIONS, versions(&[0x7f1c, TLS13]))), Ok(()));
}

#[test]
fn legacy_version_other_than_0x0303_is_refused() {
    let mut ch = Ch::good();
    ch.legacy_version = TLS10;
    assert_eq!(parse(&ch), Err(Refusal::LegacyVersion));
}

#[test]
fn cipher_suites_must_include_chacha20_poly1305() {
    let mut ch = Ch::good();
    ch.suites = vec![0x1301, 0x1302];
    assert_eq!(parse(&ch), Err(Refusal::NoChaCha));
    ch.suites = vec![];
    assert_eq!(parse(&ch), Err(Refusal::Decode));
}

#[test]
fn compression_must_be_exactly_null() {
    let mut ch = Ch::good();
    ch.compression = vec![0, 1];
    assert_eq!(parse(&ch), Err(Refusal::Compression));
    ch.compression = vec![1];
    assert_eq!(parse(&ch), Err(Refusal::Compression));
}

#[test]
fn signature_algorithms_must_include_ecdsa_p256_sha256() {
    assert_eq!(parse(&Ch::good().set(ext::SIGNATURE_ALGORITHMS, list16(&[0x0804]))), Err(Refusal::NoSignatureAlgorithm));
    assert_eq!(parse(&Ch::good().without(ext::SIGNATURE_ALGORITHMS)), Err(Refusal::NoSignatureAlgorithm));
}

#[test]
fn alpn_selects_http11_and_refuses_a_list_without_it() {
    let ch = Ch::good().set(ext::ALPN, alpn(&[b"h2", b"http/1.1"]));
    assert!(client_hello(&ch.body()).unwrap().alpn);
    let ch = Ch::good().set(ext::ALPN, alpn(&[b"h2"]));
    assert_eq!(parse(&ch), Err(Refusal::NoApplicationProtocol));
    let ch = Ch::good().set(ext::ALPN, alpn(&[b""]));
    assert_eq!(parse(&ch), Err(Refusal::Decode));
}

#[test]
fn server_name_is_parsed_and_malformed_ones_refused() {
    let ch = Ch::good().set(ext::SERVER_NAME, sni(b"gw.example"));
    assert_eq!(client_hello(&ch.body()).unwrap().server_name, Some(&b"gw.example"[..]));
    let ch = Ch::good().set(ext::SERVER_NAME, vec![0, 5, 0]);
    assert_eq!(parse(&ch), Err(Refusal::Decode));
}

#[test]
fn pre_shared_key_must_be_last() {
    let ch = Ch::good()
        .push(ext::PSK_KEY_EXCHANGE_MODES, vec8(&[1]))
        .push(ext::PRE_SHARED_KEY, vec![0; 8])
        .push(0x7777, vec![]);
    assert_eq!(parse(&ch), Err(Refusal::PskNotLast));
}

#[test]
fn pre_shared_key_requires_psk_key_exchange_modes() {
    let ch = Ch::good().push(ext::PRE_SHARED_KEY, vec![0; 8]);
    assert_eq!(parse(&ch), Err(Refusal::PskWithoutModes));
    let ch = Ch::good().push(ext::PSK_KEY_EXCHANGE_MODES, vec8(&[1])).push(ext::PRE_SHARED_KEY, vec![0; 8]);
    assert_eq!(parse(&ch), Ok(()));
}

#[test]
fn early_data_is_noted_and_must_be_empty() {
    let ch = Ch::good().push(ext::EARLY_DATA, vec![]);
    assert!(client_hello(&ch.body()).unwrap().early_data);
    let ch = Ch::good().push(ext::EARLY_DATA, vec![0]);
    assert_eq!(parse(&ch), Err(Refusal::Decode));
}

#[test]
fn trailing_bytes_after_the_extensions_are_refused() {
    let mut body = Ch::good().body();
    body.push(0);
    assert_eq!(client_hello(&body).map(|_| ()), Err(Refusal::Decode));
}

#[test]
fn extension_overrunning_its_block_is_refused() {
    assert_eq!(walk(&[0, 43, 0, 9, 2, 3, 4]), Err(Refusal::Decode));
    assert_eq!(walk(&[0, 43]), Err(Refusal::Decode));
    assert!(walk(&[]).is_ok());
}

// --- serializers ---

#[test]
fn server_hello_carries_the_profile_and_echoes_the_session_id() {
    let mut out = [0u8; 2048];
    let share = [0x33u8; SERVER_SHARE_LEN];
    let n = emit::server_hello(&mut out, &[0x22; 32], &[9; 32], &share).unwrap();
    let m = &out[..n];
    assert_eq!(m[0], hs::SERVER_HELLO);
    assert_eq!(usize::try_from(u32::from_be_bytes([0, m[1], m[2], m[3]])).unwrap(), n - 4);
    assert_eq!(&m[4..6], &TLS12.to_be_bytes());
    assert_eq!(&m[6..38], &[0x22; 32]);
    assert_eq!(&m[38..71], &vec8(&[9; 32])[..]);
    assert_eq!(&m[71..74], &[0x13, 0x03, 0]);
    let exts = &m[76..];
    assert_eq!(u16::from_be_bytes([m[74], m[75]]) as usize, exts.len());
    assert_eq!(&exts[..6], &[0, 43, 0, 2, 3, 4]);
    assert_eq!(&exts[6..12], &[0, 51, 0x04, 0x64, 0x11, 0xec]);
    assert_eq!(&exts[12..14], &[0x04, 0x60]);
    assert_eq!(&exts[14..], &share[..]);
    assert_eq!(emit::server_hello(&mut out[..n - 1], &[0x22; 32], &[9; 32], &share), Err(Refusal::Internal));
}

#[test]
fn encrypted_extensions_selects_http11_only_when_alpn_was_offered() {
    let mut out = [0u8; 64];
    let n = emit::encrypted_extensions(&mut out, false).unwrap();
    assert_eq!(&out[..n], &[8, 0, 0, 2, 0, 0]);
    let n = emit::encrypted_extensions(&mut out, true).unwrap();
    let mut want = vec![8, 0, 0, 17, 0, 15, 0, 16, 0, 11, 0, 9, 8];
    want.extend_from_slice(b"http/1.1");
    assert_eq!(&out[..n], &want[..]);
}

#[test]
fn certificate_carries_one_der_with_no_extensions() {
    let mut out = [0u8; 64];
    let n = emit::certificate(&mut out, &[0x30, 1, 2]).unwrap();
    assert_eq!(&out[..n], &[11, 0, 0, 12, 0, 0, 0, 8, 0, 0, 3, 0x30, 1, 2, 0, 0]);
    assert_eq!(emit::certificate(&mut out, &[]), Err(Refusal::Internal));
    assert_eq!(emit::certificate(&mut out[..15], &[0x30, 1, 2]), Err(Refusal::Internal));
}

#[test]
fn finished_key_update_alert_and_record_header_bytes() {
    let mut out = [0u8; 40];
    let n = emit::finished(&mut out, &[0xab; 32]).unwrap();
    assert_eq!(&out[..4], &[20, 0, 0, 32]);
    assert_eq!(n, 36);
    let n = emit::key_update(&mut out, true).unwrap();
    assert_eq!(&out[..n], &[24, 0, 0, 1, 1]);
    assert_eq!(emit::alert(Alert::CloseNotify), [1, 0]);
    assert_eq!(emit::alert(Alert::BadRecordMac), [2, 20]);
    assert_eq!(emit::record_header(ContentType::ApplicationData, 300), Ok([23, 3, 3, 1, 44]));
}

// --- DER ECDSA-Sig-Value ---

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn der_encoder_matches_signatures_openssl_verified() {
    let fixture = include_str!("testdata/ecdsa_sigs.txt");
    let mut n = 0;
    for line in fixture.lines().filter(|l| !l.starts_with('#')) {
        let [_, rs, der] = line.split(' ').collect::<Vec<_>>()[..] else { panic!("{line}") };
        let rs: [u8; 64] = hex(rs).try_into().unwrap();
        let mut out = [0u8; MAX_SIG_LEN];
        let len = ecdsa_sig_value(&rs, &mut out).unwrap();
        assert_eq!(&out[..len], &hex(der)[..], "{line}");
        n += 1;
    }
    assert_eq!(n, 5);
}

#[test]
fn der_integers_are_minimal_at_both_length_bounds() {
    let mut out = [0u8; MAX_SIG_LEN];
    let mut rs = [0u8; 64];
    rs[31] = 1;
    rs[63] = 0x7f;
    let n = ecdsa_sig_value(&rs, &mut out).unwrap();
    assert_eq!((n, &out[..n]), (MIN_SIG_LEN, &[0x30, 6, 2, 1, 1, 2, 1, 0x7f][..]));
    let n = ecdsa_sig_value(&[0xff; 64], &mut out).unwrap();
    assert_eq!(n, MAX_SIG_LEN);
    assert_eq!(&out[..5], &[0x30, 70, 2, 33, 0]);
    assert_eq!(&out[37..40], &[2, 33, 0]);
    // A leading zero byte is stripped, not kept.
    let mut rs = [0x11u8; 64];
    rs[0] = 0;
    let n = ecdsa_sig_value(&rs, &mut out).unwrap();
    assert_eq!(&out[2..4], &[2, 31]);
    assert_eq!(n, 2 + 33 + 34);
}

#[test]
fn der_encoder_refuses_a_zero_scalar() {
    let mut out = [0u8; MAX_SIG_LEN];
    let mut rs = [0x11u8; 64];
    rs[..32].fill(0);
    assert_eq!(ecdsa_sig_value(&rs, &mut out), Err(Refusal::Internal));
    let mut rs = [0x11u8; 64];
    rs[32..].fill(0);
    assert_eq!(ecdsa_sig_value(&rs, &mut out), Err(Refusal::Internal));
}

#[test]
fn certificate_verify_wraps_the_der_signature() {
    let mut out = [0u8; 100];
    let n = emit::certificate_verify(&mut out, &[0xff; 64]).unwrap();
    assert_eq!(&out[..8], &[15, 0, 0, 76, 4, 3, 0, 72]);
    assert_eq!(n, 4 + 4 + MAX_SIG_LEN);
}

// --- the bolero target: every parser on arbitrary bytes. None may panic,
// and whatever it returns lies inside the input. ---

fn inside(outer: &[u8], inner: &[u8]) -> bool {
    let (o, i) = (outer.as_ptr_range(), inner.as_ptr_range());
    inner.is_empty() || (o.start <= i.start && i.end <= o.end)
}

fn check_hello(bytes: &[u8]) {
    if let Ok(ch) = client_hello(bytes) {
        assert!(inside(bytes, ch.random) && inside(bytes, ch.session_id) && inside(bytes, ch.key_share));
        assert!(ch.session_id.len() <= MAX_SESSION_ID);
        assert!(ch.server_name.is_none_or(|n| inside(bytes, n)));
    }
    if let Ok(e) = walk(bytes) {
        for s in [e.supported_versions, e.supported_groups, e.key_share, e.signature_algorithms, e.alpn, e.server_name]
            .into_iter()
            .flatten()
        {
            assert!(inside(bytes, s));
        }
    }
}

fn fuzz_one(bytes: &[u8]) {
    // As a record stream, the way tls-core feeds the parsers.
    let mut r = Reassembler::new();
    let mut rest = bytes;
    let mut first = true;
    while let Some((h, tail)) = rest.split_first_chunk::<5>() {
        let Ok(h) = header(h, first) else { break };
        first = false;
        let Some((body, tail)) = tail.split_at_checked(h.len) else { break };
        rest = tail;
        match h.content_type {
            ContentType::Handshake => {
                if r.push(body).is_err() {
                    break;
                }
                while let Ok(Some(m)) = r.peek() {
                    assert!(m.bytes.len() <= MAX_HANDSHAKE && m.body.len() + 4 == m.bytes.len());
                    check_hello(m.body);
                    let n = m.bytes.len();
                    r.consume(n);
                }
            }
            ContentType::ChangeCipherSpec => {
                let _ = change_cipher_spec(body);
            }
            ContentType::Alert => {
                let _ = alert(body);
            }
            ContentType::ApplicationData => {
                if let Ok((_, content)) = inner_plaintext(body) {
                    assert!(inside(body, content));
                }
            }
        }
    }
    // As a bare message body.
    check_hello(bytes);
    if let Some(rs) = bytes.first_chunk::<64>() {
        let mut out = [0u8; MAX_SIG_LEN];
        if let Ok(n) = ecdsa_sig_value(rs, &mut out) {
            assert!((MIN_SIG_LEN..=MAX_SIG_LEN).contains(&n));
        }
    }
}

#[test]
fn fuzz_parsers_never_panic_and_stay_in_bounds() {
    bolero::check!().for_each(fuzz_one);
}
