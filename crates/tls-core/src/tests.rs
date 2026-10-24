#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

use std::collections::HashMap;
use std::string::String;
use std::vec;
use std::vec::Vec;

use tls_wire::{Alert, ContentType, Refusal, hs};

use super::conn::*;
use super::handshake::{Buffers, Ctx, Event, MAX_EARLY_SKIP, Session, State};
use super::hybrid::{EXCHANGE_RANDOMNESS_LEN, HybridSecret, exchange_with_randomness};
use super::record::{RecordKey, SEQ_LIMIT};
use super::rng::{HedgeHw, Hedged, Rng};
use super::schedule::testing::{early, handshake, master, schedule_from_ikm};
use super::schedule::{expand_label, extract, next_traffic_secret, traffic_key, verify_data};
use super::test_client::*;
use super::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn h32(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn hybrid_share_lengths_are_the_drafts() {
    assert_eq!((X25519MLKEM768, CLIENT_SHARE_LEN, SERVER_SHARE_LEN), (4588, 1216, 1120));
}

// ---------------------------------------------------------------- RFC 8448 §3

/// RFC 8448 section 3 (a 1-RTT handshake): the X25519 shared secret as IKM
/// and the transcript hashes the trace prints. Only the SHA-256 values are
/// compared; the trace's AES-128-GCM keys and IVs are not this suite's.
const RFC8448_IKM: &str = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";
const RFC8448_HELLO_HASH: &str = "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8";
const RFC8448_CV_HASH: &str = "edb7725fa7a3473b031ec8ef65a2485493900138a2b91291407d7951a06110ed";
const RFC8448_FINISHED_HASH: &str = "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13";

#[test]
fn rfc8448_early_handshake_and_master_secrets() {
    let ks = schedule_from_ikm(&h32(RFC8448_IKM), &h32(RFC8448_HELLO_HASH)).unwrap();
    assert_eq!(early(&ks), &h32("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"));
    assert_eq!(handshake(&ks), &h32("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"));
    assert_eq!(master(&ks), &h32("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"));
}

#[test]
fn rfc8448_handshake_traffic_secrets() {
    let ks = schedule_from_ikm(&h32(RFC8448_IKM), &h32(RFC8448_HELLO_HASH)).unwrap();
    assert_eq!(ks.client_handshake().as_bytes(), &h32("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"));
    assert_eq!(ks.server_handshake().as_bytes(), &h32("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"));
}

#[test]
fn rfc8448_application_traffic_secrets() {
    let ks = schedule_from_ikm(&h32(RFC8448_IKM), &h32(RFC8448_HELLO_HASH)).unwrap();
    let app = ks.application(&h32(RFC8448_FINISHED_HASH)).unwrap();
    assert_eq!(app.client.as_bytes(), &h32("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"));
    assert_eq!(app.server.as_bytes(), &h32("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"));
    // The client handshake secret is handed back for the client Finished.
    assert_eq!(app.client_hs.as_bytes(), &h32("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"));
}

#[test]
fn rfc8448_finished_keys_and_verify_data() {
    let ks = schedule_from_ikm(&h32(RFC8448_IKM), &h32(RFC8448_HELLO_HASH)).unwrap();
    let server_key = schedule::finished_key(ks.server_handshake()).unwrap();
    assert_eq!(server_key.as_bytes(), &h32("008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"));
    let client_key = schedule::finished_key(ks.client_handshake()).unwrap();
    assert_eq!(client_key.as_bytes(), &h32("b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4"));
    assert_eq!(
        verify_data(ks.server_handshake(), &h32(RFC8448_CV_HASH)).unwrap(),
        h32("9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718")
    );
    assert_eq!(
        verify_data(ks.client_handshake(), &h32(RFC8448_FINISHED_HASH)).unwrap(),
        h32("a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61")
    );
}

#[test]
fn hkdf_over_libcrux_hmac_matches_libcrux_hkdf() {
    use libcrux_hkdf::{Algorithm, expand, extract as ref_extract};
    for (salt, ikm) in [(&[0u8; 32][..], &[0u8; 32][..]), (&[7u8; 32][..], &[9u8; 64][..]), (&[][..], &[1u8; 5][..])] {
        let mut ours = Secret::<32>::zero();
        extract(&mut ours, salt, ikm).unwrap();
        let mut theirs = [0u8; 32];
        ref_extract(Algorithm::Sha256, &mut theirs, salt, ikm).unwrap();
        assert_eq!(ours.as_bytes(), &theirs);
        for (label, ctx, len) in [(&b"key"[..], &[][..], 32), (b"iv", &[], 12), (b"c hs traffic", &[0x55; 32][..], 32)] {
            let mut info = (len as u16).to_be_bytes().to_vec();
            info.push(6 + label.len() as u8);
            info.extend_from_slice(b"tls13 ");
            info.extend_from_slice(label);
            info.push(ctx.len() as u8);
            info.extend_from_slice(ctx);
            let mut want = vec![0u8; len];
            expand(Algorithm::Sha256, &mut want, &theirs, &info).unwrap();
            let mut got = vec![0u8; len];
            expand_label(&mut got, &theirs, label, ctx).unwrap();
            assert_eq!(got, want);
        }
    }
}

#[test]
fn expand_label_refuses_more_than_one_hash() {
    let mut out = [0u8; 33];
    assert_eq!(expand_label(&mut out, &[1; 32], b"key", &[]), Err(Refusal::Internal));
}

// ---------------------------------------------------------------- keylog fixture

struct Keylog {
    secrets: HashMap<String, [u8; 32]>,
    keys: HashMap<String, Vec<u8>>,
    ivs: HashMap<String, Vec<u8>>,
    records: Vec<(String, u64, Vec<u8>, Vec<u8>)>,
}

fn keylog() -> Keylog {
    let mut k = Keylog { secrets: HashMap::new(), keys: HashMap::new(), ivs: HashMap::new(), records: Vec::new() };
    for line in include_str!("testdata/keylog.txt").lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "SECRET" => drop(k.secrets.insert(f[1].into(), h32(f[2]))),
            "KEY" => drop(k.keys.insert(f[1].into(), hex(f[2]))),
            "IV" => drop(k.ivs.insert(f[1].into(), hex(f[2]))),
            "RECORD" => k.records.push((f[1].into(), f[2].parse().unwrap(), hex(f[3]), hex(f[4]))),
            other => panic!("keylog fixture: {other}"),
        }
    }
    k
}

#[test]
fn keylog_fixture_keys_and_ivs_are_reproduced() {
    let k = keylog();
    assert_eq!(k.secrets.len(), 5);
    for (name, secret) in &k.secrets {
        let (key, iv) = traffic_key(&Secret::copy_from(secret)).unwrap();
        assert_eq!(&key.as_bytes()[..], &k.keys[name][..], "{name}");
        assert_eq!(&iv.as_bytes()[..], &k.ivs[name][..], "{name}");
    }
}

#[test]
fn keylog_fixture_records_decrypt_under_their_traffic_keys() {
    let k = keylog();
    assert_eq!(k.records.len(), 5);
    for (name, seq, rec, want) in &k.records {
        let mut key = RecordKey::new(&Secret::copy_from(&k.secrets[name])).unwrap();
        key.set_seq(*seq);
        let mut plain = vec![0u8; rec.len()];
        let got = key.open(rec[..5].try_into().unwrap(), &rec[5..], &mut plain).unwrap();
        assert_eq!(got, &want[..], "{name} {seq}");
    }
    // The KeyUpdate record is one (request_update = 0 or 1).
    let (_, _, _, ku) = &k.records[3];
    assert_eq!(&ku[..4], &[hs::KEY_UPDATE, 0, 0, 1]);
}

#[test]
fn keylog_fixture_traffic_upd_is_reproduced() {
    let k = keylog();
    let next = next_traffic_secret(&Secret::copy_from(&k.secrets["CLIENT_TRAFFIC_SECRET_0"])).unwrap();
    assert_eq!(next.as_bytes(), &k.secrets["CLIENT_TRAFFIC_SECRET_1"]);
}

#[test]
fn keylog_fixture_record_fails_under_the_wrong_sequence_number() {
    let k = keylog();
    let (name, _, rec, _) = &k.records[2];
    let mut key = RecordKey::new(&Secret::copy_from(&k.secrets[name])).unwrap();
    key.set_seq(1);
    let mut plain = vec![0u8; rec.len()];
    assert_eq!(key.open(rec[..5].try_into().unwrap(), &rec[5..], &mut plain).map(|_| ()), Err(Refusal::BadRecordMac));
}

// ---------------------------------------------------------------- record protection

#[test]
fn records_round_trip_and_the_nonce_follows_the_sequence() {
    let secret = Secret::copy_from(&[0x42; 32]);
    let mut w = RecordKey::new(&secret).unwrap();
    let mut r = RecordKey::new(&secret).unwrap();
    for i in 0..3u8 {
        let rec = protect(&mut w, ContentType::ApplicationData, &[i; 10]);
        assert_eq!(unprotect(&mut r, &rec), (ContentType::ApplicationData, vec![i; 10]));
    }
    // Replayed: the reader's sequence moved on.
    let rec = protect(&mut w, ContentType::ApplicationData, b"x");
    let mut plain = vec![0u8; 64];
    let _ = r.open(rec[..5].try_into().unwrap(), &rec[5..], &mut plain).unwrap();
    assert!(r.open(rec[..5].try_into().unwrap(), &rec[5..], &mut plain).is_err());
}

#[test]
fn sequence_number_never_wraps_and_keeps_the_last_for_an_alert() {
    let secret = Secret::copy_from(&[0x42; 32]);
    let mut w = RecordKey::new(&secret).unwrap();
    w.set_seq(SEQ_LIMIT - 1);
    let mut scratch = [0u8; 8];
    let mut out = [0u8; 64];
    assert_eq!(w.seal(ContentType::ApplicationData, &mut scratch, 1, &mut out), Err(Refusal::Internal));
    assert!(w.seal(ContentType::Alert, &mut scratch, 2, &mut out).is_ok());
    assert_eq!(w.seal(ContentType::Alert, &mut scratch, 2, &mut out), Err(Refusal::Internal));
    let mut r = RecordKey::new(&secret).unwrap();
    r.set_seq(SEQ_LIMIT);
    assert_eq!(r.open(&[23, 3, 3, 0, 17], &[0; 17], &mut [0; 32]).map(|_| ()), Err(Refusal::Internal));
}

#[test]
fn seal_wipes_its_plaintext() {
    let mut w = RecordKey::new(&Secret::copy_from(&[1; 32])).unwrap();
    let mut scratch = [0x77u8; 16];
    let mut out = [0u8; 64];
    w.seal(ContentType::ApplicationData, &mut scratch, 10, &mut out).unwrap();
    assert!(scratch[..11].iter().all(|&b| b == 0));
}

// ---------------------------------------------------------------- hedged RNG

struct FakeHw {
    rndr: Option<u64>,
    counter: u64,
}

impl HedgeHw for FakeHw {
    fn rndr(&mut self) -> Option<u64> {
        self.rndr
    }
    fn counter(&mut self) -> u64 {
        self.counter
    }
}

fn hedged(seed: u8, rndr: Option<u64>) -> Hedged<FakeHw> {
    Hedged::new(Secret::copy_from(&[seed; 32]), FakeHw { rndr, counter: 5 })
}

#[test]
fn hedged_fails_the_draw_without_rndr() {
    let mut out = [0u8; 40];
    assert!(hedged(1, None).fill(&mut out).is_err());
}

#[test]
fn hedged_blocks_differ_and_depend_on_seed_and_rndr() {
    let draw = |seed, rndr| {
        let mut out = [0u8; 64];
        hedged(seed, Some(rndr)).fill(&mut out).unwrap();
        out
    };
    let a = draw(1, 9);
    assert_ne!(a[..32], a[32..]);
    assert_ne!(a, draw(2, 9));
    assert_ne!(a, draw(1, 10));
}

/// L9: with RNDR failing, no handshake: the ClientHello is refused with
/// internal_error and no ServerHello is written.
#[test]
fn tls_rndr_failure_means_no_handshake() {
    let mut session = Session::new();
    let mut client = Client::new(4);
    let ch = record(ContentType::Handshake, &client.client_hello(Offer::default()));
    let (mut rx, mut tx, mut out) = (vec![0; 17_000], vec![0; 5000], vec![0; 16_000]);
    let mut bufs = Buffers { rx: &mut rx, tx: &mut tx, out: &mut out };
    let mut rng = hedged(1, None);
    let mut signer = TestSigner { calls: 0 };
    let mut ctx = Ctx { cert: CERT, rng: &mut rng, signer: &mut signer };
    assert_eq!(session.on_record(&ch, &mut bufs, &mut ctx), Err(Refusal::Internal));
    let n = session.fail(Refusal::Internal, &mut bufs);
    assert_eq!(&out[..n], &[21, 3, 3, 0, 2, 2, Alert::InternalError as u8]);
    assert_eq!(signer.calls, 0);
    assert!(session.is_zeroized());
}

// ---------------------------------------------------------------- hybrid exchange

#[test]
fn exchange_agrees_with_the_client_side_decapsulation() {
    let client = Client::new(5);
    let share: [u8; CLIENT_SHARE_LEN] = client.share().try_into().unwrap();
    let mut rng = CountingRng::new(1);
    let (secret, server_share) = HybridSecret::exchange(&share, &mut rng).unwrap();
    assert_eq!(rng.drawn.len(), EXCHANGE_RANDOMNESS_LEN);
    assert_eq!(secret.ikm(), &client.ikm_for(&server_share));
    // Fresh randomness, fresh secret and share.
    let (again, share2) = HybridSecret::exchange(&share, &mut rng).unwrap();
    assert_ne!(again.ikm(), secret.ikm());
    assert_ne!(share2, server_share);
}

#[test]
fn exchange_refuses_an_encapsulation_key_failing_the_modulus_check() {
    let mut share: [u8; CLIENT_SHARE_LEN] = Client::new(6).share().try_into().unwrap();
    // 12-bit coefficients of 0xfff are >= q (FIPS 203 section 7.2).
    share[..3].fill(0xff);
    assert_eq!(exchange_with_randomness(&share, &[1; 64]).map(|_| ()), Err(Refusal::BadKeyShare));
}

#[test]
fn exchange_refuses_a_low_order_x25519_point() {
    let mut share: [u8; CLIENT_SHARE_LEN] = Client::new(6).share().try_into().unwrap();
    share[1184..].fill(0);
    assert_eq!(exchange_with_randomness(&share, &[1; 64]).map(|_| ()), Err(Refusal::BadKeyShare));
}

#[test]
fn exchange_refuses_when_the_rng_fails() {
    let share: [u8; CLIENT_SHARE_LEN] = Client::new(6).share().try_into().unwrap();
    assert_eq!(HybridSecret::exchange(&share, &mut hedged(1, None)).map(|_| ()), Err(Refusal::Internal));
}

/// S-R3-2's unit half: with known randomness, neither the X25519 ephemeral
/// nor the ML-KEM randomness is in anything the exchange or the handshake
/// leaves, and after the connection closes every buffer is zero.
#[test]
fn exchange_randomness_is_absent_from_outputs_and_wiped_buffers() {
    let mut server = Server::new();
    let mut client = Client::new(7);
    server.rng = CountingRng::new(0x80);
    let ch = client.client_hello(Offer::default());
    let step = server.feed(&record(ContentType::Handshake, &ch)).unwrap();
    let flight = server.sent(step);
    let drawn = server.rng.drawn.clone();
    let (kem_rand, scalar) = (&drawn[..32], &drawn[32..64]);
    let mut clamped: [u8; 32] = scalar.try_into().unwrap();
    libcrux_curve25519::clamp(&mut clamped);
    for (name, needle) in [("kem randomness", kem_rand), ("scalar", scalar), ("clamped scalar", &clamped[..])] {
        assert!(!contains(&flight, needle), "{name} in the flight");
        assert!(!contains(&server.tx, needle) && !contains(&server.rx, needle), "{name} in a buffer");
    }
    client.read_flight(&flight);
    server.feed(&client.finished()).unwrap();
    let mut bufs = Buffers { rx: &mut server.rx, tx: &mut server.tx, out: &mut server.out };
    server.session.close(&mut bufs);
    assert!(server.session.is_zeroized() && server.buffers_zero());
}

// ---------------------------------------------------------------- the handshake

#[test]
fn a_valid_handshake_completes_and_application_data_flows_both_ways() {
    let (mut server, mut client) = connected(Offer { alpn: true, early_data: false });
    assert!(client.alpn_selected);
    assert_eq!(server.signer.calls, 1);
    assert_eq!(server.session.state(), State::Connected);
    let step = server.feed(&client.app(b"GET / HTTP/1.1\r\n")).unwrap();
    assert_eq!(step.event, Event::AppData(16));
    assert_eq!(&server.rx[..16], b"GET / HTTP/1.1\r\n");
    let mut bufs = Buffers { rx: &mut server.rx, tx: &mut server.tx, out: &mut server.out };
    let n = server.session.seal_app(b"HTTP/1.1 200 OK\r\n", &mut bufs).unwrap();
    let recs = split_records(&server.out[..n]);
    assert_eq!(unprotect(&mut client.app_read, &recs[0]), (ContentType::ApplicationData, b"HTTP/1.1 200 OK\r\n".to_vec()));
}

#[test]
fn a_client_hello_spanning_two_records_is_accepted() {
    let mut server = Server::new();
    let mut client = Client::new(8);
    let ch = client.client_hello(Offer::default());
    let first = server.feed(&record(ContentType::Handshake, &ch[..700])).unwrap();
    assert_eq!(first.event, Event::None);
    let step = server.feed(&record(ContentType::Handshake, &ch[700..])).unwrap();
    assert_eq!(step.event, Event::Flight);
    client.read_flight(&server.sent(step));
}

#[test]
fn a_client_hello_not_ending_its_record_is_refused() {
    let mut server = Server::new();
    let mut client = Client::new(8);
    let mut ch = client.client_hello(Offer::default());
    ch.extend_from_slice(&[hs::FINISHED, 0, 0, 1]);
    assert_eq!(server.feed(&record(ContentType::Handshake, &ch)), Err(Refusal::NotAtRecordBoundary));
    assert!(server.session.is_zeroized());
}

/// The first record in `sent`, opened under the client's read key.
fn alert_of(client: &mut Client, sent: &[u8]) -> (ContentType, Vec<u8>) {
    let n = 5 + usize::from(u16::from_be_bytes([sent[3], sent[4]]));
    unprotect(&mut client.app_read, &sent[..n])
}

fn after_flight(offer: Offer) -> (Server, Client) {
    let mut server = Server::new();
    let mut client = Client::new(9);
    let ch = client.client_hello(offer);
    let step = server.feed(&record(ContentType::Handshake, &ch)).unwrap();
    client.read_flight(&server.sent(step));
    (server, client)
}

/// Feeds a record the server must refuse and checks the alert it sealed
/// (under its application key) and that the session and buffers are wiped.
fn refused(server: &mut Server, client: &mut Client, rec: &[u8], want: Refusal) {
    assert_eq!(server.feed(rec), Err(want));
    let alert = want.alert().unwrap() as u8;
    assert_eq!(alert_of(client, &server.out), (ContentType::Alert, vec![2, alert]));
    assert!(server.session.is_zeroized() && server.buffers_zero(), "wiped after {want:?}");
}

#[test]
fn tampered_finished_is_decrypt_error_and_wipes() {
    let (mut server, mut client) = after_flight(Offer::default());
    let mut fin = client.finished_message();
    fin[10] ^= 1;
    let rec = protect(&mut client.hs_write, ContentType::Handshake, &fin);
    refused(&mut server, &mut client, &rec, Refusal::DecryptError);
}

#[test]
fn finished_of_the_wrong_length_is_refused() {
    let (mut server, mut client) = after_flight(Offer::default());
    let mut fin = client.finished_message();
    fin[3] = 31;
    fin.pop();
    let rec = protect(&mut client.hs_write, ContentType::Handshake, &fin);
    refused(&mut server, &mut client, &rec, Refusal::Decode);
}

#[test]
fn finished_not_ending_its_record_is_refused() {
    let (mut server, mut client) = after_flight(Offer::default());
    let mut fin = client.finished_message();
    fin.extend_from_slice(&[hs::KEY_UPDATE, 0, 0, 1, 0]);
    let rec = protect(&mut client.hs_write, ContentType::Handshake, &fin);
    refused(&mut server, &mut client, &rec, Refusal::NotAtRecordBoundary);
}

#[test]
fn flipped_tag_is_bad_record_mac_and_wipes() {
    let (mut server, mut client) = after_flight(Offer::default());
    let mut rec = client.finished();
    *rec.last_mut().unwrap() ^= 1;
    refused(&mut server, &mut client, &rec, Refusal::BadRecordMac);
}

#[test]
fn out_of_order_message_is_unexpected_message() {
    // Application data before the client Finished.
    let (mut server, mut client) = after_flight(Offer::default());
    let rec = protect(&mut client.hs_write, ContentType::ApplicationData, b"early");
    refused(&mut server, &mut client, &rec, Refusal::UnexpectedMessage);
    // A second ClientHello, in the clear, after the flight.
    let (mut server, mut client) = after_flight(Offer::default());
    let ch = Client::new(1).client_hello(Offer::default());
    refused(&mut server, &mut client, &record(ContentType::Handshake, &ch), Refusal::UnexpectedMessage);
    // A Finished first.
    let mut server = Server::new();
    let rec = record(ContentType::Handshake, &[hs::FINISHED, 0, 0, 32, 0, 0]);
    assert_eq!(server.feed(&rec), Err(Refusal::UnexpectedMessage));
    assert!(server.session.is_zeroized());
}

#[test]
fn application_data_before_the_client_hello_is_unexpected_message() {
    let mut server = Server::new();
    assert_eq!(server.feed(&record(ContentType::ApplicationData, &[0; 20])), Err(Refusal::UnexpectedMessage));
    assert_eq!(&server.out[..7], &[21, 3, 3, 0, 2, 2, Alert::UnexpectedMessage as u8]);
}

#[test]
fn one_ccs_before_the_client_finished_is_accepted() {
    let (mut server, mut client) = after_flight(Offer::default());
    assert_eq!(server.feed(&record(ContentType::ChangeCipherSpec, &[1])).unwrap().event, Event::None);
    assert_eq!(server.feed(&client.finished()).unwrap().event, Event::Connected);
}

#[test]
fn second_ccs_is_unexpected_message() {
    let (mut server, mut client) = after_flight(Offer::default());
    server.feed(&record(ContentType::ChangeCipherSpec, &[1])).unwrap();
    refused(&mut server, &mut client, &record(ContentType::ChangeCipherSpec, &[1]), Refusal::UnexpectedChangeCipherSpec);
}

#[test]
fn ccs_after_finished_is_unexpected_message() {
    let (mut server, mut client) = connected(Offer::default());
    refused(&mut server, &mut client, &record(ContentType::ChangeCipherSpec, &[1]), Refusal::UnexpectedChangeCipherSpec);
}

#[test]
fn ccs_before_the_client_hello_is_unexpected_message() {
    let mut server = Server::new();
    assert_eq!(server.feed(&record(ContentType::ChangeCipherSpec, &[1])), Err(Refusal::UnexpectedChangeCipherSpec));
}

#[test]
fn ccs_other_than_0x01_is_refused() {
    let (mut server, mut client) = after_flight(Offer::default());
    refused(&mut server, &mut client, &record(ContentType::ChangeCipherSpec, &[2]), Refusal::BadChangeCipherSpec);
}

#[test]
fn key_update_value_2_is_illegal_parameter() {
    let (mut server, mut client) = connected(Offer::default());
    let rec = client.app_handshake(&[hs::KEY_UPDATE, 0, 0, 1, 2]);
    refused(&mut server, &mut client, &rec, Refusal::KeyUpdateValue);
}

#[test]
fn key_update_before_connected_is_unexpected_message() {
    let (mut server, mut client) = after_flight(Offer::default());
    let rec = protect(&mut client.hs_write, ContentType::Handshake, &[hs::KEY_UPDATE, 0, 0, 1, 0]);
    refused(&mut server, &mut client, &rec, Refusal::UnexpectedMessage);
}

#[test]
fn key_update_updates_the_read_key() {
    let (mut server, mut client) = connected(Offer::default());
    let rec = client.app_handshake(&[hs::KEY_UPDATE, 0, 0, 1, 0]);
    assert_eq!(server.feed(&rec).unwrap().event, Event::None);
    let next = next_traffic_secret(&client.client_ap).unwrap();
    client.app_write = RecordKey::new(&next).unwrap();
    assert_eq!(server.feed(&client.app(b"after")).unwrap().event, Event::AppData(5));
}

#[test]
fn key_update_request_is_answered_once_before_the_next_record() {
    let (mut server, mut client) = connected(Offer::default());
    // Two requests before the server writes: one flag, one answer.
    for _ in 0..2 {
        let rec = client.app_handshake(&[hs::KEY_UPDATE, 0, 0, 1, 1]);
        server.feed(&rec).unwrap();
        let next = next_traffic_secret(&client.client_ap).unwrap();
        client.app_write = RecordKey::new(&next).unwrap();
        client.client_ap = next;
    }
    let mut bufs = Buffers { rx: &mut server.rx, tx: &mut server.tx, out: &mut server.out };
    let n = server.session.seal_app(b"one", &mut bufs).unwrap();
    let recs = split_records(&server.out[..n]);
    assert_eq!(recs.len(), 2);
    assert_eq!(unprotect(&mut client.app_read, &recs[0]), (ContentType::Handshake, vec![hs::KEY_UPDATE, 0, 0, 1, 0]));
    let next = next_traffic_secret(&client.server_ap).unwrap();
    client.app_read = RecordKey::new(&next).unwrap();
    assert_eq!(unprotect(&mut client.app_read, &recs[1]), (ContentType::ApplicationData, b"one".to_vec()));
    let mut bufs = Buffers { rx: &mut server.rx, tx: &mut server.tx, out: &mut server.out };
    let n = server.session.seal_app(b"two", &mut bufs).unwrap();
    assert_eq!(split_records(&server.out[..n]).len(), 1);
}

fn junk(len: usize) -> Vec<u8> {
    let mut r = vec![23, 3, 3];
    r.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    r.extend(std::iter::repeat_n(0xee, len));
    r
}

#[test]
fn early_data_offered_is_skipped_up_to_16_kib() {
    let (mut server, mut client) = after_flight(Offer { early_data: true, alpn: false });
    for len in [MAX_EARLY_SKIP - 100, 100] {
        assert_eq!(server.feed(&junk(len)).unwrap().event, Event::None);
    }
    assert_eq!(server.feed(&client.finished()).unwrap().event, Event::Connected);
}

#[test]
fn early_data_over_16_kib_is_bad_record_mac() {
    let (mut server, mut client) = after_flight(Offer { early_data: true, alpn: false });
    server.feed(&junk(MAX_EARLY_SKIP - 100)).unwrap();
    refused(&mut server, &mut client, &junk(101), Refusal::BadRecordMac);
}

#[test]
fn undecryptable_record_without_early_data_is_bad_record_mac() {
    let (mut server, mut client) = after_flight(Offer::default());
    refused(&mut server, &mut client, &junk(100), Refusal::BadRecordMac);
}

#[test]
fn undecryptable_record_after_connected_is_bad_record_mac() {
    let (mut server, mut client) = connected(Offer { early_data: true, alpn: false });
    refused(&mut server, &mut client, &junk(100), Refusal::BadRecordMac);
}

#[test]
fn early_data_skip_ends_at_the_first_record_that_deprotects() {
    let (mut server, mut client) = after_flight(Offer { early_data: true, alpn: false });
    let fin = client.finished_message();
    let first = protect(&mut client.hs_write, ContentType::Handshake, &fin[..10]);
    assert_eq!(server.feed(&first).unwrap().event, Event::None);
    refused(&mut server, &mut client, &junk(100), Refusal::BadRecordMac);
}

#[test]
fn client_close_notify_is_reported_and_later_records_refused() {
    let (mut server, mut client) = connected(Offer::default());
    let rec = protect(&mut client.app_write, ContentType::Alert, &[1, 0]);
    assert_eq!(server.feed(&rec).unwrap().event, Event::CloseNotify);
    assert_eq!(server.feed(&client.app(b"late")), Err(Refusal::Closed));
}

#[test]
fn a_fatal_client_alert_is_not_answered() {
    let (mut server, mut client) = connected(Offer::default());
    let rec = protect(&mut client.app_write, ContentType::Alert, &[2, 40]);
    server.out.fill(0xaa);
    assert_eq!(server.feed(&rec), Err(Refusal::PeerAlert));
    assert!(server.out.iter().all(|&b| b == 0xaa));
    assert!(server.session.is_zeroized());
}

#[test]
fn close_seals_close_notify_then_wipes() {
    let (mut server, mut client) = connected(Offer::default());
    let mut bufs = Buffers { rx: &mut server.rx, tx: &mut server.tx, out: &mut server.out };
    let n = server.session.close(&mut bufs);
    assert_eq!(alert_of(&mut client, &server.out[..n]), (ContentType::Alert, vec![1, 0]));
    assert!(server.session.is_zeroized() && server.buffers_zero());
}

// ---------------------------------------------------------------- conn

const A: [u8; 4] = [10, 0, 0, 1];
const B: [u8; 4] = [10, 0, 0, 2];
const S: u64 = 1_000_000_000;

/// The table is eight slots of buffers: built on a thread whose stack
/// holds it in a debug build.
fn with_table(f: impl FnOnce(&mut Table) + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || f(&mut Table::new()))
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn per_source_cap_admits_two_and_another_source_still_gets_a_slot() {
    with_table(|t| {
        assert!(t.admit(A, 0).is_ok() && t.admit(A, 0).is_ok());
        assert_eq!(t.admit(A, 0), Err(AdmitRefusal::PerSource));
        assert!(t.admit(B, 0).is_ok());
    });
}

#[test]
fn table_is_full_at_max_conns() {
    with_table(|t| {
        for i in 0..MAX_CONNS {
            t.admit([10, 0, 1, u8::try_from(i / 2).unwrap()], 0).unwrap();
        }
        assert_eq!(t.admit([10, 9, 9, 9], 0), Err(AdmitRefusal::Full));
    });
}

#[test]
fn closing_slots_count_toward_the_per_source_cap_until_released() {
    with_table(|t| {
        let i = t.admit(A, 0).unwrap();
        t.admit(A, 0).unwrap();
        assert_eq!(t.slots[i].close(CloseCause::Error, &mut [], 1), (0, Action::Abort));
        assert_eq!(t.admit(A, 1), Err(AdmitRefusal::PerSource));
        assert_eq!(t.slots[i].abort_pass(Endpoint::Client, true), Action::Release);
        assert!(t.admit(A, 1).is_ok());
    });
}

fn slot_at(stage_steps: usize, now: u64) -> std::boxed::Box<Slot> {
    let mut s = std::boxed::Box::new(Slot::new());
    s.open(A, now);
    for _ in 0..stage_steps {
        s.advance(now);
    }
    s
}

#[test]
fn handshake_timeout_fires_at_10_s_and_wipes() {
    let mut s = slot_at(0, 0);
    assert_eq!(s.tick(HANDSHAKE_TIMEOUT_NS - 1), (Action::None, None));
    assert_eq!(s.tick(HANDSHAKE_TIMEOUT_NS), (Action::Abort, Some(Timeout::Handshake)));
    assert!(s.is_zeroized());
}

#[test]
fn activity_does_not_reset_the_handshake_timer() {
    let mut s = slot_at(0, 0);
    s.activity(HANDSHAKE_TIMEOUT_NS - S);
    assert_eq!(s.tick(HANDSHAKE_TIMEOUT_NS), (Action::Abort, Some(Timeout::Handshake)));
}

#[test]
fn activity_does_not_reset_the_head_timer() {
    let mut s = slot_at(1, 3 * S);
    assert_eq!(s.stage(), Some(Stage::Head));
    s.activity(3 * S + HEAD_TIMEOUT_NS - S);
    assert_eq!(s.tick(3 * S + HEAD_TIMEOUT_NS - 1), (Action::None, None));
    assert_eq!(s.tick(3 * S + HEAD_TIMEOUT_NS), (Action::Abort, Some(Timeout::Head)));
    assert!(s.is_zeroized());
}

#[test]
fn backend_connect_timeout_fires_at_5_s() {
    let mut s = slot_at(2, 0);
    assert_eq!(s.tick(BACKEND_CONNECT_TIMEOUT_NS - 1), (Action::None, None));
    assert_eq!(s.tick(BACKEND_CONNECT_TIMEOUT_NS), (Action::Abort, Some(Timeout::BackendConnect)));
}

#[test]
fn idle_timeout_is_reset_by_activity_while_streaming() {
    let mut s = slot_at(3, 0);
    s.activity(20 * S);
    assert_eq!(s.tick(20 * S + IDLE_TIMEOUT_NS - 1), (Action::None, None));
    assert_eq!(s.tick(20 * S + IDLE_TIMEOUT_NS), (Action::Abort, Some(Timeout::Idle)));
    assert!(s.is_zeroized());
}

#[test]
fn lifetime_ends_a_busy_connection_at_120_s() {
    let mut s = slot_at(3, 0);
    for t in (10..120).step_by(10) {
        s.activity(t * S);
        assert_eq!(s.tick(t * S), (Action::None, None));
    }
    assert_eq!(s.tick(LIFETIME_NS), (Action::Abort, Some(Timeout::Lifetime)));
}

/// A slot driven to Connected by the host client.
fn connected_slot() -> (std::boxed::Box<Slot>, Client, Vec<u8>) {
    let mut s = slot_at(0, 0);
    let mut client = Client::new(11);
    let mut out = vec![0u8; 16 * 1024];
    let mut rng = CountingRng::new(1);
    let mut signer = TestSigner { calls: 0 };
    let mut ctx = Ctx { cert: CERT, rng: &mut rng, signer: &mut signer };
    let ch = record(ContentType::Handshake, &client.client_hello(Offer::default()));
    let step = s.on_record(&ch, &mut out, &mut ctx, S).unwrap();
    client.read_flight(&out[..step.written]);
    let step = s.on_record(&client.finished(), &mut out, &mut ctx, 2 * S).unwrap();
    assert_eq!(step.event, Event::Connected);
    assert_eq!(s.stage(), Some(Stage::Head));
    (s, client, out)
}

#[test]
fn an_alert_wipes_the_slot_then_drains_and_aborts() {
    let (mut s, mut client, mut out) = connected_slot();
    let step = s.on_record(&client.app(b"GET /"), &mut out, &mut Ctx {
        cert: CERT,
        rng: &mut CountingRng::new(1),
        signer: &mut TestSigner { calls: 0 },
    }, 3 * S);
    assert_eq!(step.map(|s| s.event), Ok(Event::AppData(5)));
    assert_eq!(s.app_data(5), b"GET /");
    let mut bad = client.app(b"x");
    *bad.last_mut().unwrap() ^= 1;
    let failed = s
        .on_record(&bad, &mut out, &mut Ctx { cert: CERT, rng: &mut CountingRng::new(1), signer: &mut TestSigner { calls: 0 } }, 4 * S)
        .unwrap_err();
    assert_eq!(failed.refusal, Refusal::BadRecordMac);
    assert_eq!(alert_of(&mut client, &out[..failed.written]), (ContentType::Alert, vec![2, 20]));
    assert!(s.is_zeroized());
    assert_eq!(s.drained(5 * S), Action::Abort);
    assert_eq!(s.abort_pass(Endpoint::Client, true), Action::Release);
    assert!(s.is_free());
}

#[test]
fn a_timeout_wipes_a_connected_slot() {
    let (mut s, _, _) = connected_slot();
    assert!(!s.is_zeroized());
    assert_eq!(s.tick(2 * S + HEAD_TIMEOUT_NS), (Action::Abort, Some(Timeout::Head)));
    assert!(s.is_zeroized());
}

#[test]
fn clean_close_sends_close_notify_lingers_then_aborts_on_inbound() {
    let (mut s, mut client, mut out) = connected_slot();
    s.advance(3 * S);
    s.advance(3 * S);
    let (n, action) = s.close(CloseCause::BackendFin, &mut out, 4 * S);
    assert_eq!(action, Action::None);
    assert_eq!(alert_of(&mut client, &out[..n]), (ContentType::Alert, vec![1, 0]));
    assert!(s.is_zeroized());
    assert_eq!(s.drained(5 * S), Action::None);
    assert_eq!(s.tick(5 * S + CLOSE_LINGER_NS - 1), (Action::None, None));
    assert_eq!(s.inbound(), Action::Abort);
}

#[test]
fn linger_ends_with_an_abort_after_2_s() {
    let (mut s, _, mut out) = connected_slot();
    s.close(CloseCause::SelfResponse, &mut out, 4 * S);
    s.drained(5 * S);
    assert_eq!(s.tick(5 * S + CLOSE_LINGER_NS), (Action::Abort, None));
}

#[test]
fn a_close_that_never_drains_is_bounded_by_the_idle_timeout() {
    let (mut s, _, mut out) = connected_slot();
    s.close(CloseCause::BackendFin, &mut out, 4 * S);
    assert_eq!(s.tick(4 * S + IDLE_TIMEOUT_NS), (Action::Abort, Some(Timeout::Idle)));
}

#[test]
fn backend_reset_and_errors_abort_without_close_notify() {
    for cause in [CloseCause::BackendRst, CloseCause::ClientClosed, CloseCause::Error] {
        let (mut s, _, mut out) = connected_slot();
        out.fill(0xaa);
        assert_eq!(s.close(cause, &mut out, 4 * S), (0, Action::Abort), "{cause:?}");
        assert!(out.iter().all(|&b| b == 0xaa));
        assert!(s.is_zeroized());
    }
}

#[test]
fn rst_dispatched_on_a_pass_up_to_8_releases_on_that_pass() {
    for k in 1..=MAX_RST_PASSES {
        let mut s = slot_at(0, 0);
        s.close(CloseCause::Error, &mut [], 1);
        for _ in 1..k {
            assert_eq!(s.abort_pass(Endpoint::Client, false), Action::None);
        }
        assert_eq!(s.abort_pass(Endpoint::Client, true), Action::Release, "pass {k}");
    }
}

#[test]
fn rst_never_dispatched_releases_after_pass_8() {
    let mut s = slot_at(0, 0);
    s.close(CloseCause::Error, &mut [], 1);
    for _ in 1..MAX_RST_PASSES {
        assert_eq!(s.abort_pass(Endpoint::Client, false), Action::None);
    }
    assert_eq!(s.abort_pass(Endpoint::Client, false), Action::Release);
    assert!(s.is_free());
}

#[test]
fn an_open_backend_socket_must_see_its_rst_too() {
    let mut s = slot_at(2, 0);
    s.close(CloseCause::BackendRst, &mut [], 1);
    assert_eq!(s.abort_pass(Endpoint::Client, true), Action::None);
    assert_eq!(s.abort_pass(Endpoint::Backend, false), Action::None);
    assert_eq!(s.abort_pass(Endpoint::Backend, true), Action::Release);
}

#[test]
fn the_backend_rst_stays_pending_until_dispatched_or_its_passes_run_out() {
    // A clean close aborts the backend while the client drains: the PD
    // releases the backend socket once this turns false, not at the slot's
    // release.
    let (mut s, _, mut out) = streaming();
    assert!(!s.backend_rst_pending(), "nothing aborted yet");
    s.backend_fin(&mut out, 5 * S);
    assert!(s.backend_rst_pending());
    assert_eq!(s.abort_pass(Endpoint::Backend, false), Action::None);
    assert!(s.backend_rst_pending());
    assert_eq!(s.abort_pass(Endpoint::Backend, true), Action::None, "the client still drains");
    assert!(!s.backend_rst_pending());

    let (mut s, _, _) = streaming();
    s.client_fin(5 * S);
    for _ in 1..MAX_RST_PASSES {
        s.abort_pass(Endpoint::Backend, false);
        assert!(s.backend_rst_pending());
    }
    s.abort_pass(Endpoint::Backend, false);
    assert!(!s.backend_rst_pending(), "released after pass 8 without its RST");
}

#[test]
fn a_released_slot_is_reset_in_place_and_serves_a_new_handshake() {
    let (mut s, _, mut out) = connected_slot();
    assert_eq!(s.close(CloseCause::Error, &mut out, 3 * S), (0, Action::Abort));
    assert_eq!(s.abort_pass(Endpoint::Client, true), Action::Release);
    assert!(s.is_free() && s.source() == [0; 4]);
    s.open(B, 4 * S);
    let mut client = Client::new(12);
    let mut ctx = Ctx { cert: CERT, rng: &mut CountingRng::new(2), signer: &mut TestSigner { calls: 0 } };
    let ch = record(ContentType::Handshake, &client.client_hello(Offer::default()));
    let step = s.on_record(&ch, &mut out, &mut ctx, 5 * S).unwrap();
    client.read_flight(&out[..step.written]);
    assert_eq!(s.on_record(&client.finished(), &mut out, &mut ctx, 5 * S).unwrap().event, Event::Connected);
}

#[test]
fn a_refused_connection_holds_a_slot_only_until_its_rst() {
    with_table(|t| {
        t.admit(A, 0).unwrap();
        let i = t.refuse().unwrap();
        assert!(!t.slots[i].is_free() && t.slots[i].stage().is_none());
        // It carries no source: A's second connection is still admitted.
        assert!(t.admit(A, 0).is_ok());
        assert_eq!(t.slots[i].abort_pass(Endpoint::Client, false), Action::None);
        assert_eq!(t.slots[i].abort_pass(Endpoint::Client, true), Action::Release);
        assert!(t.slots[i].is_free());
    });
}

#[test]
fn a_refused_connection_whose_rst_never_goes_out_is_released_after_pass_8() {
    with_table(|t| {
        let i = t.refuse().unwrap();
        for _ in 1..MAX_RST_PASSES {
            assert_eq!(t.slots[i].abort_pass(Endpoint::Client, false), Action::None);
        }
        assert_eq!(t.slots[i].abort_pass(Endpoint::Client, false), Action::Release);
    });
}

#[test]
fn refuse_finds_no_slot_in_a_full_table() {
    with_table(|t| {
        for i in 0..MAX_CONNS {
            t.admit([10, 0, 1, u8::try_from(i).unwrap()], 0).unwrap();
        }
        assert_eq!(t.refuse(), None);
    });
}

#[test]
fn closed_and_timeout_codes_are_their_index_and_names_their_variants() {
    for (i, c) in Closed::ALL.iter().enumerate() {
        assert_eq!(usize::from(c.code()), i);
        assert_eq!(c.name(), std::format!("{c:?}"));
    }
    for (i, t) in Timeout::ALL.iter().enumerate() {
        assert_eq!(usize::from(t.stage()), i);
        assert_eq!(t.name(), std::format!("{t:?}"));
    }
    assert!(Closed::ALL.len() <= 32 && Timeout::ALL.len() <= 32);
    assert_eq!(Closed::from(CloseCause::SelfResponse), Closed::SelfResponse);
    assert_eq!(Closed::from(AdmitRefusal::PerSource), Closed::PerSource);
}

#[test]
fn append_head_moves_application_data_into_the_head_buffer_up_to_its_room() {
    let (mut s, mut client, mut out) = connected_slot();
    let mut ctx = Ctx { cert: CERT, rng: &mut CountingRng::new(1), signer: &mut TestSigner { calls: 0 } };
    let step = s.on_record(&client.app(b"GET / HTTP/1.1\r\n"), &mut out, &mut ctx, 3 * S).unwrap();
    assert_eq!(step.event, Event::AppData(16));
    assert_eq!(s.append_head(16, HEAD_BUF_LEN - 4), 4);
    assert_eq!(&s.head[HEAD_BUF_LEN - 4..], b"GET ");
    assert!(s.app_data(16).iter().all(|&b| b == 0), "the moved plaintext is wiped from the record buffer");
    let step = s.on_record(&client.app(b"Host: x\r\n"), &mut out, &mut ctx, 3 * S).unwrap();
    assert_eq!(step.event, Event::AppData(9));
    assert_eq!(s.append_head(9, 0), 9);
    assert_eq!(&s.head[..9], b"Host: x\r\n");
}

/// M6 plan C12 (R2-T N8): a `TlsSign` answered Unavailable ends the pass in
/// `KeyUnavailable` with its code and the KEY_UNAVAILABLE halt; a pass whose
/// signs were all answered halts nothing.
#[test]
fn a_sign_answered_unavailable_halts_tls_with_its_code_and_key_unavailable() {
    assert_eq!(crate::halt::after_sign(Some(0x48)), Some((0x48, crate::halt::KEY_UNAVAILABLE)));
    assert_eq!(crate::halt::after_sign(None), None);
    let reasons = [crate::halt::NO_CLOCK, crate::halt::RNDR, crate::halt::INIT_FAILED, crate::halt::KEY_UNAVAILABLE];
    assert_eq!(reasons, [1, 2, 3, 4]);
}

// ---------------------------------------------------------------- proxy

/// `connected_slot`'s head stage starts here.
const HEAD_AT: u64 = 2 * S;

const GET: &[u8] = b"GET /x?y=1 HTTP/1.1\r\nHost: gw.example\r\nKeep-Alive: marker\r\nX-Forwarded-For: 6.6.6.6\r\n\
Forwarded: for=6.6.6.6\r\nUser-Agent: t\r\n\r\n";

/// `data` as one client record through the proxy.
fn feed(s: &mut Slot, client: &mut Client, data: &[u8], out: &mut [u8], now: u64) -> Next {
    let mut ctx = Ctx { cert: CERT, rng: &mut CountingRng::new(1), signer: &mut TestSigner { calls: 0 } };
    s.client_record(&client.app(data), out, &mut ctx, now)
}

/// The fake backend: takes what `to_backend` offers, `chunk` bytes at a
/// time.
fn pump(s: &mut Slot, backend: &mut Vec<u8>, chunk: usize, now: u64) {
    loop {
        let offered = s.to_backend();
        if offered.is_empty() {
            return;
        }
        let n = offered.len().min(chunk);
        backend.extend_from_slice(&offered[..n]);
        s.backend_sent(n, now);
    }
}

/// What the client reads from `sent`: each record's type and content.
fn client_reads(client: &mut Client, sent: &[u8]) -> Vec<(ContentType, Vec<u8>)> {
    split_records(sent).iter().map(|r| unprotect(&mut client.app_read, r)).collect()
}

/// `http-wire`'s rewrite of `head` for the client at `A`.
fn rewritten(head: &[u8]) -> Vec<u8> {
    let parsed = http_wire::request_head(head).unwrap();
    let mut out = vec![0u8; http_wire::MAX_REWRITE];
    let n = http_wire::rewrite(&parsed, A, &mut out).unwrap();
    out.truncate(n);
    out
}

fn outcomes(next: &Next) -> Vec<Outcome> {
    next.outcomes.iter().collect()
}

/// A slot whose head `GET` was accepted at 3 s and whose backend
/// connected at 4 s; nothing pumped yet.
fn streaming() -> (std::boxed::Box<Slot>, Client, Vec<u8>) {
    let (mut s, mut client, mut out) = connected_slot();
    assert!(feed(&mut s, &mut client, GET, &mut out, 3 * S).connect);
    assert_eq!(s.backend_connected(4 * S), Next::default());
    assert_eq!(s.stage(), Some(Stage::Streaming));
    (s, client, out)
}

/// `request` refused with `status` at head time: the fixed response and
/// close_notify, no backend connect, the slot wiped and draining.
fn assert_refused(request: &[u8], status: http_wire::Status) {
    let (mut s, mut client, mut out) = connected_slot();
    let next = feed(&mut s, &mut client, request, &mut out, 3 * S);
    let shown = String::from_utf8_lossy(request);
    assert!(!next.connect && !next.abort_backend, "{shown}");
    assert_eq!(outcomes(&next), [Outcome::HttpRefused(status), Outcome::TlsClosed(Closed::SelfResponse)], "{shown}");
    assert_eq!(
        client_reads(&mut client, &out[..next.to_client]),
        [(ContentType::ApplicationData, http_wire::refusal_response(status).to_vec()), (ContentType::Alert, vec![1, 0])],
        "{shown}"
    );
    assert!(next.to_client <= MAX_CLIENT_OUT);
    assert_eq!(next.action, Action::None);
    assert!(s.is_zeroized() && s.stage().is_none() && s.to_backend().is_empty(), "{shown}");
    assert_eq!(s.drained(4 * S), Action::None, "close_notify drains, then the linger");
}

#[test]
fn get_reaches_the_backend_as_exactly_the_rewrite() {
    let (mut s, mut client, mut out) = connected_slot();
    let next = feed(&mut s, &mut client, GET, &mut out, 3 * S);
    assert_eq!(next, Next { connect: true, ..Next::default() });
    assert_eq!(s.stage(), Some(Stage::BackendConnect));
    assert!(s.to_backend().is_empty() && !s.reads_client(), "nothing moves before the connect");
    s.backend_connected(4 * S);
    let mut backend = Vec::new();
    pump(&mut s, &mut backend, usize::MAX, 4 * S);
    assert_eq!(backend, rewritten(GET));
    assert!(!contains(&backend, b"marker") && !contains(&backend, b"6.6.6.6"));
    assert!(s.reads_client());
}

#[test]
fn the_backend_response_streams_to_the_client_unparsed() {
    let (mut s, mut client, mut out) = streaming();
    pump(&mut s, &mut Vec::new(), usize::MAX, 4 * S);
    for part in [&b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"[..], b"not even http", &[0u8; BACKEND_CHUNK]] {
        let next = s.backend_data(part, &mut out, 5 * S);
        assert!(next.to_client <= MAX_CLIENT_OUT);
        assert_eq!(client_reads(&mut client, &out[..next.to_client]), [(ContentType::ApplicationData, part.to_vec())]);
    }
    // More than one record's worth is the PD's to split; given whole, it
    // ends the connection rather than truncating silently.
    let next = s.backend_data(&[0u8; BACKEND_CHUNK + 1], &mut out, 5 * S);
    assert_eq!((next.action, outcomes(&next)), (Action::Abort, vec![Outcome::TlsClosed(Closed::Error)]));
}

#[test]
fn post_bodies_of_0_1_and_max_body_reach_the_backend_exactly() {
    for len in [0, 1, http_wire::MAX_BODY] {
        let body: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let head = std::format!("POST /up HTTP/1.1\r\nHost: gw\r\nContent-Length: {len}\r\n\r\n");
        // Bytes past Content-Length (a pipelined request) never go on.
        let request = [head.as_bytes(), &body, b"GET /smuggled HTTP/1.1\r\n\r\n"].concat();
        let (mut s, mut client, mut out) = connected_slot();
        let mut records = request.chunks(tls_wire::MAX_PLAINTEXT);
        assert!(feed(&mut s, &mut client, records.next().unwrap(), &mut out, 3 * S).connect);
        s.backend_connected(3 * S);
        let mut backend = Vec::new();
        pump(&mut s, &mut backend, usize::MAX, 3 * S);
        for rec in records {
            assert!(s.reads_client());
            assert_eq!(feed(&mut s, &mut client, rec, &mut out, 3 * S), Next::default());
            assert!(s.to_backend().len() <= tls_wire::MAX_PLAINTEXT);
            // A backend socket with little room: taken a bit at a time.
            pump(&mut s, &mut backend, 1000, 3 * S);
        }
        assert_eq!(backend, [rewritten(head.as_bytes()), body].concat(), "body of {len}");
    }
}

#[test]
fn a_record_while_bytes_for_the_backend_wait_ends_the_connection() {
    let (mut s, mut client, mut out) = streaming();
    assert!(!s.reads_client());
    let next = feed(&mut s, &mut client, b"x", &mut out, 5 * S);
    assert_eq!((next.action, next.abort_backend), (Action::Abort, true));
    assert_eq!(outcomes(&next), [Outcome::TlsClosed(Closed::Error)]);
    assert!(s.is_zeroized());
}

#[test]
fn max_body_plus_one_is_413_at_head_time_without_connect() {
    let head = std::format!("POST / HTTP/1.1\r\nHost: gw\r\nContent-Length: {}\r\n\r\n", http_wire::MAX_BODY + 1);
    assert_refused(head.as_bytes(), http_wire::Status::ContentTooLarge);
}

#[test]
fn each_smuggling_form_is_refused_with_its_status_and_no_connect() {
    use http_wire::Status::*;
    let cases: [(&[u8], http_wire::Status); 10] = [
        (b"POST / HTTP/1.1\r\nHost: gw\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n", NotImplemented),
        (b"POST / HTTP/1.1\r\nHost: gw\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: x\r\n\r\n", NotImplemented),
        (b"POST / HTTP/1.1\r\nHost: gw\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n", BadRequest),
        (b"GET / HTTP/1.1\r\nHost: gw\r\nX-A: a\r\n b\r\n\r\n", BadRequest),
        (b"GET / HTTP/1.1\r\nHost: gw\r\nConnection: content-length\r\n\r\n", BadRequest),
        (b"GET / HTTP/1.1\r\nHost: gw\r\nX_Forwarded_For: 1.2.3.4\r\n\r\n", BadRequest),
        (b"GET / HTTP/1.1\nHost: gw\n\n", BadRequest),
        (b"POST / HTTP/1.1\r\nHost: gw\r\nExpect: 100-continue\r\n\r\n", ExpectationFailed),
        (b"CONNECT gw:443 HTTP/1.1\r\nHost: gw:443\r\n\r\n", NotImplemented),
        (b"GET http://gw/ HTTP/1.1\r\nHost: gw\r\n\r\n", NotImplemented),
    ];
    for (request, status) in cases {
        assert_refused(request, status);
    }
}

/// A head of exactly `len` bytes: the request line, Host, one padded
/// field, the blank line.
fn head_of(len: usize) -> Vec<u8> {
    let start = b"GET / HTTP/1.1\r\nHost: gw\r\nX-Pad: ";
    let pad = len - start.len() - 4;
    [&start[..], &vec![b'a'; pad], b"\r\n\r\n"].concat()
}

#[test]
fn head_over_8_kib_is_431_and_8_kib_is_accepted() {
    let (mut s, mut client, mut out) = connected_slot();
    let head = head_of(http_wire::MAX_HEAD);
    assert_eq!(feed(&mut s, &mut client, &head[..5000], &mut out, 3 * S), Next::default());
    assert!(feed(&mut s, &mut client, &head[5000..], &mut out, 3 * S).connect);

    // 8193 bytes with no end yet, over two records.
    let open = &head_of(http_wire::MAX_HEAD + 1)[..http_wire::MAX_HEAD + 1 - 4];
    let (mut s, mut client, mut out) = connected_slot();
    assert_eq!(feed(&mut s, &mut client, &open[..5000], &mut out, 3 * S), Next::default());
    let next = feed(&mut s, &mut client, &[&open[5000..], &b"aaaa"[..]].concat(), &mut out, 3 * S);
    assert!(!next.connect);
    assert_eq!(outcomes(&next)[0], Outcome::HttpRefused(http_wire::Status::HeaderFieldsTooLarge));
    assert_eq!(client_reads(&mut client, &out[..next.to_client])[0].1, http_wire::refusal_response(http_wire::Status::HeaderFieldsTooLarge));
    assert!(s.is_zeroized());
}

#[test]
fn backend_rst_mid_response_resets_the_client_without_close_notify() {
    let (mut s, _, mut out) = streaming();
    pump(&mut s, &mut Vec::new(), usize::MAX, 4 * S);
    s.backend_data(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npart", &mut out, 5 * S);
    out.fill(0xaa);
    let next = s.backend_rst(&mut out, 6 * S);
    assert_eq!((next.to_client, next.action, next.abort_backend), (0, Action::Abort, true));
    assert_eq!(outcomes(&next), [Outcome::TlsClosed(Closed::BackendRst)]);
    assert!(out.iter().all(|&b| b == 0xaa), "no close_notify sealed");
    assert!(s.is_zeroized());
    assert_eq!(s.abort_pass(Endpoint::Client, true), Action::None);
    assert_eq!(s.abort_pass(Endpoint::Backend, true), Action::Release);
}

#[test]
fn client_fin_before_the_response_ends_aborts_the_backend() {
    // While the backend connects, and once the response has started.
    let (mut s, mut client, mut out) = connected_slot();
    feed(&mut s, &mut client, GET, &mut out, 3 * S);
    let next = s.client_fin(4 * S);
    assert_eq!((next.action, next.abort_backend, next.to_client), (Action::Abort, true, 0));
    assert_eq!(outcomes(&next), [Outcome::TlsClosed(Closed::ClientClosed)]);
    assert!(s.is_zeroized());

    let (mut s, _, mut out) = streaming();
    pump(&mut s, &mut Vec::new(), usize::MAX, 4 * S);
    s.backend_data(b"HTTP/1.1 200 OK\r\n", &mut out, 5 * S);
    let next = s.client_fin(6 * S);
    assert_eq!((next.action, next.abort_backend, next.to_client), (Action::Abort, true, 0));
    assert_eq!(s.abort_pass(Endpoint::Client, true), Action::None, "the backend's RST is awaited too");
    assert_eq!(s.abort_pass(Endpoint::Backend, true), Action::Release);
}

#[test]
fn client_close_notify_before_the_response_ends_aborts_the_backend() {
    let (mut s, mut client, mut out) = streaming();
    pump(&mut s, &mut Vec::new(), usize::MAX, 4 * S);
    let close_notify = protect(&mut client.app_write, ContentType::Alert, &[1, 0]);
    let mut ctx = Ctx { cert: CERT, rng: &mut CountingRng::new(1), signer: &mut TestSigner { calls: 0 } };
    let next = s.client_record(&close_notify, &mut out, &mut ctx, 5 * S);
    assert_eq!((next.action, next.abort_backend, next.to_client), (Action::Abort, true, 0));
    assert_eq!(outcomes(&next), [Outcome::TlsClosed(Closed::ClientClosed)]);
    assert!(s.is_zeroized());
}

#[test]
fn clean_backend_fin_sends_close_notify_then_lingers_2_s_then_aborts() {
    let (mut s, mut client, mut out) = streaming();
    pump(&mut s, &mut Vec::new(), usize::MAX, 4 * S);
    let next = s.backend_data(b"HTTP/1.1 204 No Content\r\n\r\n", &mut out, 5 * S);
    client_reads(&mut client, &out[..next.to_client]);
    let next = s.backend_fin(&mut out, 6 * S);
    assert_eq!(client_reads(&mut client, &out[..next.to_client]), [(ContentType::Alert, vec![1, 0])]);
    assert_eq!((next.action, next.abort_backend), (Action::None, true));
    assert_eq!(outcomes(&next), [Outcome::TlsClosed(Closed::BackendFin)]);
    assert!(s.is_zeroized());
    // The backend's RST goes out while the client's close_notify drains.
    assert_eq!(s.abort_pass(Endpoint::Backend, true), Action::None);
    assert_eq!(s.drained(7 * S), Action::None);
    assert_eq!(s.timers(7 * S + CLOSE_LINGER_NS - 1, &mut out), Next::default());
    assert_eq!(s.timers(7 * S + CLOSE_LINGER_NS, &mut out), Next { action: Action::Abort, ..Next::default() });
    assert_eq!(s.abort_pass(Endpoint::Client, true), Action::Release);
}

#[test]
fn each_timeout_fires_through_the_proxy_and_wipes() {
    let mut s = slot_at(0, 0);
    let mut out = vec![0u8; 16 * 1024];
    let next = s.timers(HANDSHAKE_TIMEOUT_NS, &mut out);
    assert_eq!((next.action, outcomes(&next)), (Action::Abort, vec![Outcome::TlsTimeout(Timeout::Handshake)]));
    assert!(s.is_zeroized());

    // A partial head in the buffer.
    let (mut s, mut client, mut out) = connected_slot();
    feed(&mut s, &mut client, b"GET / HTTP/1.1\r\n", &mut out, 3 * S);
    assert!(!s.is_zeroized());
    assert_eq!(s.timers(HEAD_AT + HEAD_TIMEOUT_NS - 1, &mut out), Next::default());
    let next = s.timers(HEAD_AT + HEAD_TIMEOUT_NS, &mut out);
    assert_eq!((next.action, outcomes(&next)), (Action::Abort, vec![Outcome::TlsTimeout(Timeout::Head)]));
    assert!(s.is_zeroized());

    // Bytes still waiting for the backend.
    let (mut s, _, mut out) = streaming();
    assert!(!s.to_backend().is_empty());
    let next = s.timers(4 * S + IDLE_TIMEOUT_NS, &mut out);
    assert_eq!((next.action, next.abort_backend), (Action::Abort, true));
    assert_eq!(outcomes(&next), [Outcome::TlsTimeout(Timeout::Idle)]);
    assert!(s.is_zeroized() && s.to_backend().is_empty());
}

#[test]
fn activity_does_not_reset_the_head_timer_through_the_proxy() {
    let (mut s, mut client, mut out) = connected_slot();
    let mut t = 3 * S;
    while t < HEAD_AT + HEAD_TIMEOUT_NS {
        assert_eq!(feed(&mut s, &mut client, b"a", &mut out, t), Next::default());
        assert_eq!(s.timers(t, &mut out), Next::default());
        t += S / 2;
    }
    let next = s.timers(HEAD_AT + HEAD_TIMEOUT_NS, &mut out);
    assert_eq!((next.action, outcomes(&next)), (Action::Abort, vec![Outcome::TlsTimeout(Timeout::Head)]));
    assert!(s.is_zeroized());
}

#[test]
fn backend_connect_timeout_answers_502_and_wipes() {
    let (mut s, mut client, mut out) = connected_slot();
    assert!(feed(&mut s, &mut client, GET, &mut out, 3 * S).connect);
    assert_eq!(s.timers(3 * S + BACKEND_CONNECT_TIMEOUT_NS - 1, &mut out), Next::default());
    let next = s.timers(3 * S + BACKEND_CONNECT_TIMEOUT_NS, &mut out);
    assert_eq!(
        outcomes(&next),
        [Outcome::TlsTimeout(Timeout::BackendConnect), Outcome::BackendUnavailable, Outcome::TlsClosed(Closed::SelfResponse)]
    );
    assert_eq!(
        client_reads(&mut client, &out[..next.to_client]),
        [(ContentType::ApplicationData, BAD_GATEWAY.to_vec()), (ContentType::Alert, vec![1, 0])]
    );
    assert!(next.to_client <= MAX_CLIENT_OUT);
    assert_eq!((next.action, next.abort_backend, next.connect), (Action::None, true, false));
    assert!(s.is_zeroized());
    assert_eq!(s.abort_pass(Endpoint::Backend, false), Action::None);
    assert_eq!(s.drained(9 * S), Action::None);
    assert_eq!(s.timers(9 * S + CLOSE_LINGER_NS, &mut out).action, Action::Abort);
    assert_eq!(s.abort_pass(Endpoint::Client, true), Action::None, "the backend's RST still awaited");
    assert_eq!(s.abort_pass(Endpoint::Backend, true), Action::Release);
}

#[test]
fn a_refused_backend_connect_answers_502() {
    for fin in [false, true] {
        let (mut s, mut client, mut out) = connected_slot();
        feed(&mut s, &mut client, GET, &mut out, 3 * S);
        let next = if fin { s.backend_fin(&mut out, 4 * S) } else { s.backend_rst(&mut out, 4 * S) };
        assert_eq!(outcomes(&next), [Outcome::BackendUnavailable, Outcome::TlsClosed(Closed::SelfResponse)]);
        assert_eq!(client_reads(&mut client, &out[..next.to_client])[0].1, BAD_GATEWAY);
        assert!(next.abort_backend && s.is_zeroized());
    }
}

#[test]
fn lifetime_ends_a_streaming_connection_with_its_backend() {
    let (mut s, _, mut out) = streaming();
    pump(&mut s, &mut Vec::new(), usize::MAX, 4 * S);
    for t in (10..120).step_by(10) {
        s.backend_data(b"x", &mut out, t * S);
        assert_eq!(s.timers(t * S, &mut out), Next::default());
    }
    let next = s.timers(LIFETIME_NS, &mut out);
    assert_eq!((next.action, next.abort_backend), (Action::Abort, true));
    assert_eq!(outcomes(&next), [Outcome::TlsTimeout(Timeout::Lifetime)]);
    assert!(s.is_zeroized());
}

#[test]
fn events_after_the_close_do_nothing() {
    let (mut s, mut client, mut out) = streaming();
    s.client_fin(5 * S);
    assert_eq!(s.backend_data(b"late", &mut out, 5 * S), Next::default());
    assert_eq!(s.backend_fin(&mut out, 5 * S), Next::default());
    assert_eq!(s.backend_rst(&mut out, 5 * S), Next::default());
    assert_eq!(s.client_fin(5 * S), Next::default());
    assert_eq!(feed(&mut s, &mut client, b"late", &mut out, 5 * S), Next::default());
    assert!(s.is_zeroized());
}

/// C10: the backend's FIN counts only once its queued bytes are read; a
/// close without a FIN is a reset.
#[test]
fn backend_end_waits_for_the_receive_queue_to_drain() {
    use crate::conn::{backend_end, BackendEnd};
    assert_eq!(backend_end(true, 1, false), BackendEnd::Open);
    assert_eq!(backend_end(true, 0, false), BackendEnd::Fin);
    assert_eq!(backend_end(true, 1, true), BackendEnd::Open);
    assert_eq!(backend_end(false, 0, true), BackendEnd::Rst);
    assert_eq!(backend_end(false, 0, false), BackendEnd::Open);
}
