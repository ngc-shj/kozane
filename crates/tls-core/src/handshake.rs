//! The server state machine (M6 plan C7): AwaitClientHello →
//! AwaitClientFinished → Connected → Closed. One call per received record;
//! anything the state does not expect is a [`Refusal`], after which
//! [`Session::fail`] seals the alert and wipes every key.
//!
//! The client Finished is verified with the constant-time `ct::ct_eq` (S9);
//! this is the file check-pins' P11 anchors the `finished`/`verify_data`
//! compare tripwire on.

use libcrux_sha2::{Digest, Sha256};
use tls_wire::framing::Reassembler;
use tls_wire::hello::{ClientHello, client_hello};
use tls_wire::record::{alert, change_cipher_spec, header, inner_plaintext};
use tls_wire::{Alert, ContentType, HASH_LEN, MAX_PLAINTEXT, RECORD_HEADER_LEN, Refusal, emit, hs};

use crate::hybrid::{HybridSecret, scrub_session_stack};
use crate::record::RecordKey;
use crate::rng::Rng;
use crate::schedule::{KeySchedule, next_traffic_secret, verify_data};
use crate::{Secret, wipe};

/// Undecryptable records skipped in total while early_data is ignored
/// (section 4.2.10; M6 plan C6, S11g).
pub const MAX_EARLY_SKIP: usize = 16 * 1024;
/// Largest content of one server record (M6 plan C10: server records are at
/// most 4 KiB); the tx buffer holds that, its type byte and the tag.
pub const MAX_SERVER_RECORD: usize = 4 * 1024;
/// The tx buffer every server record is built in.
pub const TX_BUF_LEN: usize = MAX_SERVER_RECORD + 256;
/// The rx buffer a protected record is decrypted into.
pub const RX_BUF_LEN: usize = tls_wire::MAX_CIPHERTEXT;

/// `tlskey`'s TlsSign oracle as the PD reaches it (C5, C12): r ‖ s over the
/// server CertificateVerify content of a transcript hash.
pub trait Signer {
    fn sign(&mut self, transcript_hash: &[u8; HASH_LEN]) -> Result<[u8; 64], Refusal>;
}

/// What a handshake needs beyond the record: the certificate (one DER), the
/// randomness and the signer.
pub struct Ctx<'a, R: Rng, S: Signer> {
    pub cert: &'a [u8],
    pub rng: &'a mut R,
    pub signer: &'a mut S,
}

/// The buffers a call works in: `rx` receives decrypted plaintext, `tx`
/// builds server records' plaintext (wiped after sealing), `out` takes the
/// records to send.
pub struct Buffers<'a> {
    pub rx: &'a mut [u8],
    pub tx: &'a mut [u8],
    pub out: &'a mut [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    AwaitClientHello,
    AwaitClientFinished,
    Connected,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Nothing for the caller (a record skipped, a message incomplete, a
    /// CCS, a KeyUpdate).
    None,
    /// The server's flight is in `out`.
    Flight,
    /// The client Finished verified: application data may flow.
    Connected,
    /// `rx[..n]` holds application data.
    AppData(usize),
    /// The client sent close_notify.
    CloseNotify,
}

/// One call's result: bytes written to `out` and what happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step {
    pub written: usize,
    pub event: Event,
}

impl Step {
    const fn none() -> Self {
        Self { written: 0, event: Event::None }
    }
}

pub struct Session {
    state: State,
    /// No record received yet: the first may carry version 0x0301.
    first_record: bool,
    transcript: Sha256,
    reasm: Reassembler,
    read: RecordKey,
    write: RecordKey,
    /// The client's current traffic secret: handshake, then application.
    read_secret: Secret<HASH_LEN>,
    write_secret: Secret<HASH_LEN>,
    /// client_application_traffic_secret_0 until the client Finished.
    pending_read: Secret<HASH_LEN>,
    /// Transcript hash through the server Finished: the client Finished's.
    finished_hash: [u8; HASH_LEN],
    ccs_seen: bool,
    early_data: bool,
    early_skipped: usize,
    /// A record has deprotected under the client handshake key: no more
    /// early_data skipping.
    deprotected: bool,
    /// The client asked for our KeyUpdate (one flag, no queue).
    update_requested: bool,
    peer_closed: bool,
}

/// The hybrid exchange, the ServerHello (in the clear, into `out`) and the
/// key schedule from the transcript through it: (the schedule, bytes
/// written). The ephemeral, the ML-KEM randomness, both component secrets
/// and every copy of the hybrid secret (the moves, HKDF-Extract's HMAC)
/// stay in this call's frames, which the caller scrubs; only the schedule
/// leaves. Public only for the ct-harness, whose `hello-depth` run checks
/// that these frames lie within the scrub (M6 code review T5); the
/// handshake is its one production caller.
#[inline(never)]
pub fn hello_keys<R: Rng>(
    transcript: &mut Sha256,
    hello: &[u8],
    ch: &ClientHello<'_>,
    out: &mut [u8],
    rng: &mut R,
) -> Result<(KeySchedule, usize), Refusal> {
    let (shared, share) = HybridSecret::exchange(ch.key_share, rng)?;
    transcript.update(hello);
    let mut random = [0u8; 32];
    rng.fill(&mut random).map_err(|_| Refusal::Internal)?;
    let (sh_head, sh_rest) = out.split_at_mut_checked(RECORD_HEADER_LEN).ok_or(Refusal::Internal)?;
    let sh_len = emit::server_hello(sh_rest, &random, ch.session_id, &share)?;
    sh_head.copy_from_slice(&emit::record_header(ContentType::Handshake, sh_len)?);
    transcript.update(sh_rest.get(..sh_len).ok_or(Refusal::Internal)?);
    let mut hello_hash = [0u8; HASH_LEN];
    transcript.finish(&mut hello_hash);
    let ks = KeySchedule::new(shared, &hello_hash)?;
    Ok((ks, RECORD_HEADER_LEN.checked_add(sh_len).ok_or(Refusal::Internal)?))
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        Self {
            state: State::AwaitClientHello,
            first_record: true,
            transcript: Sha256::new(),
            reasm: Reassembler::new(),
            read: RecordKey::none(),
            write: RecordKey::none(),
            read_secret: Secret::zero(),
            write_secret: Secret::zero(),
            pending_read: Secret::zero(),
            finished_hash: [0; HASH_LEN],
            ccs_seen: false,
            early_data: false,
            early_skipped: 0,
            deprotected: false,
            update_requested: false,
            peer_closed: false,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// One whole record (header and body) from the client.
    pub fn on_record<R: Rng, S: Signer>(
        &mut self,
        record: &[u8],
        bufs: &mut Buffers<'_>,
        ctx: &mut Ctx<'_, R, S>,
    ) -> Result<Step, Refusal> {
        if self.state == State::Closed || self.peer_closed {
            return Err(Refusal::Closed);
        }
        let (head, body) = record.split_first_chunk::<RECORD_HEADER_LEN>().ok_or(Refusal::Decode)?;
        let h = header(head, self.first_record)?;
        if h.len != body.len() {
            return Err(Refusal::Decode);
        }
        self.first_record = false;
        match (self.state, h.content_type) {
            (State::AwaitClientHello, ContentType::Handshake) => self.on_hello_record(body, bufs, ctx),
            (State::AwaitClientFinished, ContentType::ChangeCipherSpec) => {
                // Once, between ClientHello and the client Finished, and not
                // inside a fragmented handshake message (M6 plan C6, S11a).
                if self.ccs_seen || !self.reasm.is_empty() {
                    return Err(Refusal::UnexpectedChangeCipherSpec);
                }
                change_cipher_spec(body)?;
                self.ccs_seen = true;
                Ok(Step::none())
            }
            (_, ContentType::ChangeCipherSpec) => Err(Refusal::UnexpectedChangeCipherSpec),
            (State::AwaitClientFinished | State::Connected, ContentType::ApplicationData) => {
                self.on_protected(head, body, bufs)
            }
            // A client that could not use our ServerHello answers in the
            // clear; any other plaintext alert is out of place.
            (State::AwaitClientFinished, ContentType::Alert) => {
                alert(body)?;
                Err(Refusal::PeerAlert)
            }
            _ => Err(Refusal::UnexpectedMessage),
        }
    }

    fn on_hello_record<R: Rng, S: Signer>(
        &mut self,
        body: &[u8],
        bufs: &mut Buffers<'_>,
        ctx: &mut Ctx<'_, R, S>,
    ) -> Result<Step, Refusal> {
        self.reasm.push(body)?;
        // Anything but a ClientHello is refused from its first byte, not
        // buffered until complete.
        if self.reasm.first_type() != Some(hs::CLIENT_HELLO) {
            return Err(Refusal::UnexpectedMessage);
        }
        let Some(msg) = self.reasm.peek()? else { return Ok(Step::none()) };
        // The ClientHello must end with its record: the key changes after.
        if msg.bytes.len() != self.reasm.len() {
            return Err(Refusal::NotAtRecordBoundary);
        }
        let ch = client_hello(msg.body)?;
        // Every copy of the exchange's secrets and of the hybrid secret is
        // made in `hello_keys`' frames; the scrub below them runs as soon
        // as it returns, whatever it returned (M6 plan C7, S-R3-2).
        let keys = hello_keys(&mut self.transcript, msg.bytes, &ch, bufs.out, ctx.rng);
        scrub_session_stack();
        let (ks, mut written) = keys?;
        self.early_data = ch.early_data;
        let msg_len = msg.bytes.len();
        let alpn = ch.alpn;
        self.reasm.consume(msg_len);

        let mut hs_write = RecordKey::new(ks.server_handshake())?;
        self.read = RecordKey::new(ks.client_handshake())?;

        // EncryptedExtensions, Certificate, CertificateVerify, Finished:
        // one protected record each.
        let n = emit::encrypted_extensions(bufs.tx, alpn)?;
        written = self.seal_flight(&mut hs_write, bufs, n, written)?;
        let n = emit::certificate(bufs.tx, ctx.cert)?;
        written = self.seal_flight(&mut hs_write, bufs, n, written)?;
        let r_s = ctx.signer.sign(&self.hash())?;
        let n = emit::certificate_verify(bufs.tx, &r_s)?;
        written = self.seal_flight(&mut hs_write, bufs, n, written)?;
        let fin = verify_data(ks.server_handshake(), &self.hash())?;
        let n = emit::finished(bufs.tx, &fin)?;
        written = self.seal_flight(&mut hs_write, bufs, n, written)?;
        hs_write.wipe();

        self.finished_hash = self.hash();
        // The server handshake secret goes with the schedule here, once the
        // application secrets exist (M6 plan C8, T-N4).
        let app = ks.application(&self.finished_hash)?;
        self.read_secret = app.client_hs;
        self.pending_read = app.client;
        self.write = RecordKey::new(&app.server)?;
        self.write_secret = app.server;
        self.state = State::AwaitClientFinished;
        Ok(Step { written, event: Event::Flight })
    }

    /// Adds `tx[..n]` (one handshake message) to the transcript and seals it
    /// into `out` after `at`.
    fn seal_flight(&mut self, key: &mut RecordKey, bufs: &mut Buffers<'_>, n: usize, at: usize) -> Result<usize, Refusal> {
        if n > MAX_SERVER_RECORD {
            return Err(Refusal::Internal);
        }
        self.transcript.update(bufs.tx.get(..n).ok_or(Refusal::Internal)?);
        let out = bufs.out.get_mut(at..).ok_or(Refusal::Internal)?;
        let sealed = key.seal(ContentType::Handshake, bufs.tx, n, out)?;
        at.checked_add(sealed).ok_or(Refusal::Internal)
    }

    fn hash(&self) -> [u8; HASH_LEN] {
        let mut h = [0u8; HASH_LEN];
        self.transcript.finish(&mut h);
        h
    }

    fn on_protected(&mut self, head: &[u8; RECORD_HEADER_LEN], body: &[u8], bufs: &mut Buffers<'_>) -> Result<Step, Refusal> {
        let plain = match self.read.open(head, body, bufs.rx) {
            Ok(p) => p,
            Err(Refusal::BadRecordMac) if self.may_skip(body.len()) => {
                // Ignored early data (4.2.10): skipped without advancing the
                // read sequence number.
                self.early_skipped = self.early_skipped.saturating_add(body.len());
                return Ok(Step::none());
            }
            Err(e) => return Err(e),
        };
        self.deprotected = true;
        let n = plain.len();
        let (ty, content) = inner_plaintext(plain)?;
        let content_len = content.len();
        if ty != ContentType::Handshake && !self.reasm.is_empty() {
            // Handshake messages may not be interleaved with other records.
            return Err(Refusal::UnexpectedMessage);
        }
        let r = match ty {
            ContentType::Handshake => {
                let r = self.reasm.push(content);
                wipe(bufs.rx.get_mut(..n).unwrap_or(&mut []));
                r?;
                self.on_messages()
            }
            ContentType::Alert => {
                let (_, desc) = alert(content)?;
                wipe(bufs.rx.get_mut(..n).unwrap_or(&mut []));
                if desc == Alert::CloseNotify as u8 && self.state == State::Connected {
                    self.peer_closed = true;
                    Ok(Step { written: 0, event: Event::CloseNotify })
                } else {
                    Err(Refusal::PeerAlert)
                }
            }
            ContentType::ApplicationData if self.state == State::Connected => {
                // The padding and type byte after the content are plaintext
                // too; only the content is handed on.
                wipe(bufs.rx.get_mut(content_len..n).unwrap_or(&mut []));
                Ok(Step { written: 0, event: Event::AppData(content_len) })
            }
            _ => Err(Refusal::UnexpectedMessage),
        };
        if r.is_err() {
            wipe(bufs.rx.get_mut(..n).unwrap_or(&mut []));
        }
        r
    }

    /// Early data may be skipped only when the ClientHello offered it,
    /// before any record has deprotected, and up to 16 KiB in total.
    fn may_skip(&self, len: usize) -> bool {
        self.state == State::AwaitClientFinished
            && self.early_data
            && !self.deprotected
            && self.early_skipped.checked_add(len).is_some_and(|t| t <= MAX_EARLY_SKIP)
    }

    fn on_messages(&mut self) -> Result<Step, Refusal> {
        let mut step = Step::none();
        while let Some(msg) = self.reasm.peek()? {
            let (msg_type, len) = (msg.msg_type, msg.bytes.len());
            match (self.state, msg_type) {
                (State::AwaitClientFinished, hs::FINISHED) => {
                    let ok = check_finished(msg.body, &self.read_secret, &self.finished_hash)?;
                    self.reasm.consume(len);
                    if !self.reasm.is_empty() {
                        return Err(Refusal::NotAtRecordBoundary);
                    }
                    if !ok {
                        return Err(Refusal::DecryptError);
                    }
                    // The client handshake secret is wiped once the Finished
                    // verifies (M6 plan C8, T-N4).
                    self.read = RecordKey::new(&self.pending_read)?;
                    self.read_secret = core::mem::replace(&mut self.pending_read, Secret::zero());
                    self.transcript = Sha256::new();
                    self.finished_hash = [0; HASH_LEN];
                    self.state = State::Connected;
                    step = Step { written: 0, event: Event::Connected };
                }
                (State::Connected, hs::KEY_UPDATE) => {
                    let request = match msg.body {
                        [0] => false,
                        [1] => true,
                        [_] => return Err(Refusal::KeyUpdateValue),
                        _ => return Err(Refusal::Decode),
                    };
                    self.reasm.consume(len);
                    if !self.reasm.is_empty() {
                        return Err(Refusal::NotAtRecordBoundary);
                    }
                    // The superseded secret and key are wiped by the
                    // assignments (section 7.2; M6 plan C8).
                    let next = next_traffic_secret(&self.read_secret)?;
                    self.read = RecordKey::new(&next)?;
                    self.read_secret = next;
                    self.update_requested |= request;
                }
                _ => return Err(Refusal::UnexpectedMessage),
            }
        }
        Ok(step)
    }

    /// Seals `data` (at most [`MAX_SERVER_RECORD`] bytes) as one application
    /// record into `out`, preceded by our KeyUpdate if the client asked for
    /// one; the write key then updates once (S11d).
    pub fn seal_app(&mut self, data: &[u8], bufs: &mut Buffers<'_>) -> Result<usize, Refusal> {
        if self.state != State::Connected || data.len() > MAX_SERVER_RECORD {
            return Err(Refusal::Internal);
        }
        let mut at = self.flush_key_update(bufs)?;
        bufs.tx.get_mut(..data.len()).ok_or(Refusal::Internal)?.copy_from_slice(data);
        let out = bufs.out.get_mut(at..).ok_or(Refusal::Internal)?;
        at = at.checked_add(self.write.seal(ContentType::ApplicationData, bufs.tx, data.len(), out)?).ok_or(Refusal::Internal)?;
        Ok(at)
    }

    /// Our pending KeyUpdate, if any, into `out`.
    pub fn flush_key_update(&mut self, bufs: &mut Buffers<'_>) -> Result<usize, Refusal> {
        if !self.update_requested || self.state != State::Connected {
            return Ok(0);
        }
        let n = emit::key_update(bufs.tx, false)?;
        let written = self.write.seal(ContentType::Handshake, bufs.tx, n, bufs.out)?;
        let next = next_traffic_secret(&self.write_secret)?;
        self.write = RecordKey::new(&next)?;
        self.write_secret = next;
        self.update_requested = false;
        Ok(written)
    }

    /// close_notify sealed into `out`, then every key and buffer wiped
    /// (M6 plan C8: seal, wipe, then the caller transmits).
    pub fn close(&mut self, bufs: &mut Buffers<'_>) -> usize {
        let n = self.seal_alert(Alert::CloseNotify, bufs).unwrap_or(0);
        self.wipe(bufs);
        n
    }

    /// The refusal's alert (if any) sealed into `out` under the current
    /// write key, or in the clear before there is one; then every key and
    /// buffer wiped. Returns the bytes written.
    pub fn fail(&mut self, refusal: Refusal, bufs: &mut Buffers<'_>) -> usize {
        let n = refusal.alert().and_then(|a| self.seal_alert(a, bufs).ok()).unwrap_or(0);
        self.wipe(bufs);
        n
    }

    fn seal_alert(&mut self, desc: Alert, bufs: &mut Buffers<'_>) -> Result<usize, Refusal> {
        let body = emit::alert(desc);
        if self.write.is_zeroized() {
            let head = emit::record_header(ContentType::Alert, body.len())?;
            let out = bufs.out.get_mut(..RECORD_HEADER_LEN.saturating_add(body.len())).ok_or(Refusal::Internal)?;
            let (h, b) = out.split_at_mut(RECORD_HEADER_LEN);
            h.copy_from_slice(&head);
            b.copy_from_slice(&body);
            return Ok(out.len());
        }
        bufs.tx.get_mut(..body.len()).ok_or(Refusal::Internal)?.copy_from_slice(&body);
        self.write.seal(ContentType::Alert, bufs.tx, body.len(), bufs.out)
    }

    /// Every secret, key and buffer of the connection zeroed; Closed.
    pub fn wipe(&mut self, bufs: &mut Buffers<'_>) {
        self.wipe_state();
        wipe(bufs.rx);
        wipe(bufs.tx);
    }

    /// A fresh session in place, as [`Session::new`] makes one, with every
    /// key and secret of the old one zeroed: the PD's slots are static and
    /// too large to rebuild on its stack.
    pub fn reset(&mut self) {
        self.wipe_state();
        self.state = State::AwaitClientHello;
        self.first_record = true;
        self.peer_closed = false;
    }

    fn wipe_state(&mut self) {
        self.read.wipe();
        self.write.wipe();
        self.read_secret.wipe();
        self.write_secret.wipe();
        self.pending_read.wipe();
        self.finished_hash = [0; HASH_LEN];
        self.reasm.wipe();
        self.transcript = Sha256::new();
        self.ccs_seen = false;
        self.early_data = false;
        self.early_skipped = 0;
        self.deprotected = false;
        self.update_requested = false;
        self.state = State::Closed;
    }

    /// No key, secret or handshake byte left, and Closed (the wipe's check).
    pub fn is_zeroized(&self) -> bool {
        self.state == State::Closed
            && self.read.is_zeroized()
            && self.write.is_zeroized()
            && self.read_secret.is_zero()
            && self.write_secret.is_zero()
            && self.pending_read.is_zero()
            && self.finished_hash.iter().all(|&b| b == 0)
            && self.reasm.is_zeroized()
    }
}

/// The client Finished: 32 bytes, compared in constant time with the
/// verify_data the client handshake secret gives over the transcript
/// through the server Finished. A wrong length is malformed.
fn check_finished(finished: &[u8], client_hs: &Secret<HASH_LEN>, transcript_hash: &[u8; HASH_LEN]) -> Result<bool, Refusal> {
    if finished.len() != HASH_LEN {
        return Err(Refusal::Decode);
    }
    let expected_verify_data = verify_data(client_hs, transcript_hash)?;
    Ok(ct::ct_eq(&expected_verify_data, finished))
}

const _: () = assert!(MAX_SERVER_RECORD + 1 + crate::record::RECORD_TAG_LEN <= TX_BUF_LEN);
const _: () = assert!(MAX_SERVER_RECORD <= MAX_PLAINTEXT);
