//! The host test client (M6 plan C7, T3): a TLS 1.3 client over libcrux on
//! the host (ML-KEM-768 keygen and decapsulation, X25519, P-256 verify)
//! that drives a [`Session`] or [`Slot`] record by record, so every refusal
//! path can be reached with a real handshake around it. The key schedule
//! and record protection are this crate's, checked independently by the
//! RFC 8448 and keylog fixture tests.

#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

use std::vec;
use std::vec::Vec;

use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768KeyPair};
use libcrux_sha2::{Digest, Sha256};
use tls_wire::{
    ALPN_HTTP11, ContentType, ECDSA_SECP256R1_SHA256, RECORD_HEADER_LEN, Refusal, SERVER_SHARE_LEN, TLS12, TLS13,
    TLS_CHACHA20_POLY1305_SHA256, X25519MLKEM768, ext, hs,
};

use crate::Secret;
use crate::handshake::{Buffers, Ctx, RX_BUF_LEN, Session, Signer, Step, TX_BUF_LEN};
use crate::record::RecordKey;
use crate::rng::{Rng, RngError};
use crate::schedule::testing::schedule_from_ikm;
use crate::schedule::verify_data;

/// The certificate the server sends: opaque to it (it parses nothing).
pub(crate) const CERT: &[u8] = &[0x30, 0x82, 0x01, 0x00, 0xa5, 0x5a, 0xa5, 0x5a];
/// The test server's P-256 key and the deterministic test nonce.
pub(crate) const SIGN_KEY: [u8; 32] = [0x17; 32];
const SIGN_NONCE: [u8; 32] = [0x29; 32];

/// Fills with a running counter from `next`: known bytes, never repeated.
pub(crate) struct CountingRng {
    pub(crate) next: u8,
    pub(crate) drawn: Vec<u8>,
}

impl CountingRng {
    pub(crate) fn new(start: u8) -> Self {
        Self { next: start, drawn: Vec::new() }
    }
}

impl Rng for CountingRng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        for b in out.iter_mut() {
            *b = self.next;
            self.next = self.next.wrapping_add(1);
        }
        self.drawn.extend_from_slice(out);
        Ok(())
    }
}

/// `key`'s TlsSign stand-in: the RFC 8446 section 4.4.3 server content,
/// signed with libcrux-p256.
pub(crate) struct TestSigner {
    pub(crate) calls: usize,
}

pub(crate) fn cv_content(hash: &[u8; 32]) -> Vec<u8> {
    let mut c = vec![0x20u8; 64];
    c.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    c.push(0);
    c.extend_from_slice(hash);
    c
}

impl Signer for TestSigner {
    fn sign(&mut self, transcript_hash: &[u8; 32]) -> Result<[u8; 64], Refusal> {
        self.calls += 1;
        let content = cv_content(transcript_hash);
        let mut sig = [0u8; 64];
        assert!(libcrux_p256::ecdsa_sign_p256_sha2(&mut sig, content.len() as u32, &content, &SIGN_KEY, &SIGN_NONCE));
        Ok(sig)
    }
}

pub(crate) fn sign_public() -> [u8; 64] {
    let mut xy = [0u8; 64];
    assert!(libcrux_p256::dh_initiator(&mut xy, &SIGN_KEY));
    xy
}

/// A plaintext record.
pub(crate) fn record(ty: ContentType, body: &[u8]) -> Vec<u8> {
    let mut r = vec![ty as u8, 3, 3];
    r.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    r.extend_from_slice(body);
    r
}

/// The records in `bytes`.
pub(crate) fn split_records(mut bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let n = RECORD_HEADER_LEN + usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
        out.push(bytes[..n].to_vec());
        bytes = &bytes[n..];
    }
    out
}

/// A protected record of `content` with inner type `ty`, sealed with `key`.
pub(crate) fn protect(key: &mut RecordKey, ty: ContentType, content: &[u8]) -> Vec<u8> {
    let mut scratch = vec![0u8; content.len() + 1];
    scratch[..content.len()].copy_from_slice(content);
    let mut out = vec![0u8; content.len() + 64];
    let n = key.seal(ty, &mut scratch, content.len(), &mut out).unwrap();
    out.truncate(n);
    out
}

/// Opens a protected record: (inner type, content).
pub(crate) fn unprotect(key: &mut RecordKey, rec: &[u8]) -> (ContentType, Vec<u8>) {
    let mut plain = vec![0u8; rec.len()];
    let inner = key.open(rec[..5].try_into().unwrap(), &rec[5..], &mut plain).unwrap();
    let (ty, content) = tls_wire::record::inner_plaintext(inner).unwrap();
    (ty, content.to_vec())
}

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

fn ext_block(ty: u16, data: &[u8]) -> Vec<u8> {
    let mut v = ty.to_be_bytes().to_vec();
    v.extend_from_slice(&vec16(data));
    v
}

/// What the client offers beyond the profile's minimum.
#[derive(Default, Clone, Copy)]
pub(crate) struct Offer {
    pub(crate) early_data: bool,
    pub(crate) alpn: bool,
}

/// One client: its key-exchange keys, transcript and record keys.
pub(crate) struct Client {
    kem: MlKem768KeyPair,
    x25519: [u8; 32],
    transcript: Sha256,
    pub(crate) hs_write: RecordKey,
    hs_read: RecordKey,
    pub(crate) app_write: RecordKey,
    pub(crate) app_read: RecordKey,
    client_hs: Secret<32>,
    pub(crate) client_ap: Secret<32>,
    pub(crate) server_ap: Secret<32>,
    finished_hash: [u8; 32],
    pub(crate) alpn_selected: bool,
}

impl Client {
    pub(crate) fn new(seed: u8) -> Self {
        let kem = mlkem768::generate_key_pair([seed; 64]);
        let mut x25519 = [seed.wrapping_add(1); 32];
        libcrux_curve25519::clamp(&mut x25519);
        Self {
            kem,
            x25519,
            transcript: Sha256::new(),
            hs_write: RecordKey::none(),
            hs_read: RecordKey::none(),
            app_write: RecordKey::none(),
            app_read: RecordKey::none(),
            client_hs: Secret::zero(),
            client_ap: Secret::zero(),
            server_ap: Secret::zero(),
            finished_hash: [0; 32],
            alpn_selected: false,
        }
    }

    pub(crate) fn share(&self) -> Vec<u8> {
        let mut share = self.kem.public_key().as_slice().to_vec();
        let mut public = [0u8; 32];
        libcrux_curve25519::secret_to_public(&mut public, &self.x25519);
        share.extend_from_slice(&public);
        share
    }

    /// The hybrid secret this client derives from a server share.
    pub(crate) fn ikm_for(&self, share: &[u8; SERVER_SHARE_LEN]) -> [u8; 64] {
        let ct = MlKem768Ciphertext::from(<&[u8; 1088]>::try_from(&share[..1088]).unwrap());
        let kem_ss = mlkem768::decapsulate(self.kem.private_key(), &ct);
        let mut x_ss = [0u8; 32];
        assert!(libcrux_curve25519::ecdh(&mut x_ss, share[1088..].try_into().unwrap(), &self.x25519).is_ok());
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(&kem_ss);
        ikm[32..].copy_from_slice(&x_ss);
        ikm
    }

    /// The ClientHello message (header included), added to the transcript.
    pub(crate) fn client_hello(&mut self, offer: Offer) -> Vec<u8> {
        let mut body = TLS12.to_be_bytes().to_vec();
        body.extend_from_slice(&[0xc1; 32]);
        body.extend_from_slice(&vec8(&[0x5e; 32]));
        body.extend_from_slice(&vec16(&TLS_CHACHA20_POLY1305_SHA256.to_be_bytes()));
        body.extend_from_slice(&vec8(&[0]));
        let mut exts = Vec::new();
        exts.extend(ext_block(ext::SUPPORTED_VERSIONS, &vec8(&TLS13.to_be_bytes())));
        exts.extend(ext_block(ext::SUPPORTED_GROUPS, &vec16(&X25519MLKEM768.to_be_bytes())));
        let mut entry = X25519MLKEM768.to_be_bytes().to_vec();
        entry.extend_from_slice(&vec16(&self.share()));
        exts.extend(ext_block(ext::KEY_SHARE, &vec16(&entry)));
        exts.extend(ext_block(ext::SIGNATURE_ALGORITHMS, &vec16(&ECDSA_SECP256R1_SHA256.to_be_bytes())));
        if offer.alpn {
            exts.extend(ext_block(ext::ALPN, &vec16(&vec8(ALPN_HTTP11))));
        }
        if offer.early_data {
            exts.extend(ext_block(ext::EARLY_DATA, &[]));
        }
        body.extend_from_slice(&vec16(&exts));
        let mut msg = vec![hs::CLIENT_HELLO];
        msg.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        self.transcript.update(&msg);
        msg
    }

    fn hash(&self) -> [u8; 32] {
        let mut h = [0u8; 32];
        self.transcript.finish(&mut h);
        h
    }

    /// Reads the server's flight: decapsulates, derives, checks the
    /// CertificateVerify signature and the server Finished.
    pub(crate) fn read_flight(&mut self, flight: &[u8]) {
        let recs = split_records(flight);
        assert_eq!(recs[0][0], ContentType::Handshake as u8);
        let sh = &recs[0][5..];
        assert_eq!(sh[0], hs::SERVER_HELLO);
        self.transcript.update(sh);
        let share: &[u8; SERVER_SHARE_LEN] = sh[sh.len() - SERVER_SHARE_LEN..].try_into().unwrap();
        let ikm = self.ikm_for(share);
        let ks = schedule_from_ikm(&ikm, &self.hash()).unwrap();
        self.hs_read = RecordKey::new(ks.server_handshake()).unwrap();
        self.hs_write = RecordKey::new(ks.client_handshake()).unwrap();
        let server_hs = Secret::copy_from(ks.server_handshake().as_bytes());

        let mut msgs = Vec::new();
        for rec in &recs[1..] {
            let (ty, content) = unprotect(&mut self.hs_read, rec);
            assert_eq!(ty, ContentType::Handshake);
            msgs.push(content);
        }
        assert_eq!(msgs.iter().map(|m| m[0]).collect::<Vec<_>>(), [
            hs::ENCRYPTED_EXTENSIONS,
            hs::CERTIFICATE,
            hs::CERTIFICATE_VERIFY,
            hs::FINISHED
        ]);
        self.alpn_selected = msgs[0].len() > 6;
        self.transcript.update(&msgs[0]);
        assert_eq!(&msgs[1][11..11 + CERT.len()], CERT);
        self.transcript.update(&msgs[1]);
        let (r, s) = der_r_s(&msgs[2][8..]);
        let content = cv_content(&self.hash());
        assert!(libcrux_p256::ecdsa_verif_p256_sha2(content.len() as u32, &content, &sign_public(), &r, &s));
        self.transcript.update(&msgs[2]);
        assert_eq!(&msgs[3][4..], &verify_data(&server_hs, &self.hash()).unwrap());
        self.transcript.update(&msgs[3]);
        self.finished_hash = self.hash();
        let app = ks.application(&self.finished_hash).unwrap();
        self.client_hs = app.client_hs;
        self.app_read = RecordKey::new(&app.server).unwrap();
        self.app_write = RecordKey::new(&app.client).unwrap();
        self.client_ap = app.client;
        self.server_ap = app.server;
    }

    /// The client Finished message.
    pub(crate) fn finished_message(&self) -> Vec<u8> {
        let mut m = vec![hs::FINISHED, 0, 0, 32];
        m.extend_from_slice(&verify_data(&self.client_hs, &self.finished_hash).unwrap());
        m
    }

    /// The client Finished, sealed under the client handshake key.
    pub(crate) fn finished(&mut self) -> Vec<u8> {
        let m = self.finished_message();
        protect(&mut self.hs_write, ContentType::Handshake, &m)
    }

    /// Application data under the client application key.
    pub(crate) fn app(&mut self, data: &[u8]) -> Vec<u8> {
        protect(&mut self.app_write, ContentType::ApplicationData, data)
    }

    /// A handshake message under the client application key.
    pub(crate) fn app_handshake(&mut self, msg: &[u8]) -> Vec<u8> {
        protect(&mut self.app_write, ContentType::Handshake, msg)
    }
}

/// r and s, 32 bytes each, from a DER ECDSA-Sig-Value.
fn der_r_s(der: &[u8]) -> ([u8; 32], [u8; 32]) {
    assert_eq!(der[0], 0x30);
    let mut at = 2;
    let mut out = [[0u8; 32]; 2];
    for v in &mut out {
        assert_eq!(der[at], 2);
        let len = usize::from(der[at + 1]);
        let int = &der[at + 2..at + 2 + len];
        let int = if int.len() == 33 { &int[1..] } else { int };
        v[32 - int.len()..].copy_from_slice(int);
        at += 2 + len;
    }
    (out[0], out[1])
}

/// A session with its buffers and context, for driving record by record.
pub(crate) struct Server {
    pub(crate) session: Session,
    pub(crate) rx: Vec<u8>,
    pub(crate) tx: Vec<u8>,
    pub(crate) out: Vec<u8>,
    pub(crate) rng: CountingRng,
    pub(crate) signer: TestSigner,
}

impl Server {
    pub(crate) fn new() -> Self {
        Self {
            session: Session::new(),
            rx: vec![0; RX_BUF_LEN],
            tx: vec![0; TX_BUF_LEN],
            out: vec![0; 16 * 1024],
            rng: CountingRng::new(0x40),
            signer: TestSigner { calls: 0 },
        }
    }

    /// One record in; on a refusal the session seals the alert and wipes,
    /// as the slot does.
    pub(crate) fn feed(&mut self, rec: &[u8]) -> Result<Step, Refusal> {
        let mut bufs = Buffers { rx: &mut self.rx, tx: &mut self.tx, out: &mut self.out };
        let mut ctx = Ctx { cert: CERT, rng: &mut self.rng, signer: &mut self.signer };
        let r = self.session.on_record(rec, &mut bufs, &mut ctx);
        if let Err(e) = r {
            self.session.fail(e, &mut bufs);
        }
        r
    }

    /// The bytes `written` by the last call.
    pub(crate) fn sent(&self, step: Step) -> Vec<u8> {
        self.out[..step.written].to_vec()
    }

    /// The buffers are zero after a wipe.
    pub(crate) fn buffers_zero(&self) -> bool {
        self.rx.iter().chain(&self.tx).all(|&b| b == 0)
    }
}

/// A server and client through the client Finished: Connected.
pub(crate) fn connected(offer: Offer) -> (Server, Client) {
    let mut server = Server::new();
    let mut client = Client::new(3);
    let ch = client.client_hello(offer);
    let step = server.feed(&record(ContentType::Handshake, &ch)).unwrap();
    let flight = server.sent(step);
    client.read_flight(&flight);
    let step = server.feed(&client.finished()).unwrap();
    assert_eq!(step.event, crate::handshake::Event::Connected);
    (server, client)
}
