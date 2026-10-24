//! The proxy flow over a [`Slot`] (M6 plan C9, C10). After the handshake
//! the request head is collected (at most 8 KiB) and parsed by
//! `http-wire`: refused, `tls` answers with the refusal's fixed response
//! and close_notify; accepted, the head is rewritten for the backend and a
//! backend connect is asked for. Once connected, the rewritten head and
//! exactly `Content-Length` body bytes go to the backend, and the backend's
//! bytes are sealed to the client unparsed until its FIN.
//!
//! The PD reports each event through one method, which answers with a
//! [`Next`]: records to queue on the client socket, whether to open the
//! backend connection or abort the backend socket, the slot's [`Action`],
//! and the [`Outcome`]s to audit. Bytes for the backend are pulled instead:
//! [`Slot::to_backend`] and [`Slot::backend_sent`], so the backend socket's
//! room bounds them. Flow control is the PD's:
//! - a client record only while [`Slot::reads_client`] (the bytes the last
//!   one carried for the backend have gone);
//! - a call that may write to the client only with [`MAX_CLIENT_OUT`]
//!   bytes free on the client socket and in `out`;
//! - backend bytes in chunks of at most [`BACKEND_CHUNK`];
//! - the backend's FIN only once its received bytes have all been passed
//!   on, the client's FIN only once its complete records have been read.
//!
//! The backend being unreachable (its connect refused or reset, or the
//! connect timeout) is answered with 502 Bad Gateway, a response `tls`
//! generates in full, so it ends with close_notify; one `BackendUnavailable`
//! outcome covers every cause. The backend's RST once connected is a
//! truncation: the client gets a RST without close_notify.

use http_wire::{Status, head_end, refusal_response, request_head, rewrite};
use tls_wire::RECORD_HEADER_LEN;

use super::{Action, CloseCause, Closed, Phase, Slot, Span, Stage, Timeout};
use super::{BACKEND_CONNECT_TIMEOUT_NS, HEAD_BUF_LEN, LIFETIME_NS, REWRITE_BUF_LEN};
use crate::handshake::{Ctx, Event, MAX_SERVER_RECORD, Signer};
use crate::record::RECORD_TAG_LEN;
use crate::rng::Rng;
use crate::wipe;
use tls_wire::Refusal;

/// The response to a request the backend could not be reached for.
pub const BAD_GATEWAY: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 12\r\nConnection: close\r\n\r\nBad Gateway\n";

/// Most backend bytes one [`Slot::backend_data`] call seals: one record.
pub const BACKEND_CHUNK: usize = MAX_SERVER_RECORD;

/// A sealed record's bytes beyond its content: header, inner type, tag.
const SEALED_OVERHEAD: usize = RECORD_HEADER_LEN + 1 + RECORD_TAG_LEN;
/// Most bytes one call after the handshake writes to the client: our
/// pending KeyUpdate (4 + 1 bytes), one record of at most
/// [`MAX_SERVER_RECORD`] (a backend chunk or a whole self-generated
/// response), and close_notify (2 bytes).
pub const MAX_CLIENT_OUT: usize = 3 * SEALED_OVERHEAD + 5 + MAX_SERVER_RECORD + 2;

// Every accepted head fits the head buffer, and its rewrite plus the body
// bytes that came with it (both within the head's 8 KiB) the rewrite one.
const _: () = assert!(HEAD_BUF_LEN == http_wire::MAX_HEAD);
const _: () = assert!(REWRITE_BUF_LEN >= http_wire::MAX_REWRITE);
const _: () = assert!(BAD_GATEWAY.len() <= MAX_SERVER_RECORD);

/// What `tls` audits about a connection (M6 plan C10's closed kinds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// `TLS_REFUSED_BASE + refusal`: the session refused a record.
    TlsRefused(Refusal),
    /// `TLS_CLOSED_BASE + reason`.
    TlsClosed(Closed),
    /// `HTTP_REFUSED_BASE + status index`.
    HttpRefused(Status),
    /// `TLS_TIMEOUT_BASE + stage`.
    TlsTimeout(Timeout),
    /// The backend refused, reset or timed out the connect: 502.
    BackendUnavailable,
}

/// The outcomes of one call, in the order they happened (at most three: a
/// connect timeout, the backend unavailable, the self response's close).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Outcomes([Option<Outcome>; 3]);

impl Outcomes {
    fn push(&mut self, o: Outcome) {
        if let Some(free) = self.0.iter_mut().find(|o| o.is_none()) {
            *free = Some(o);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = Outcome> + '_ {
        self.0.iter().flatten().copied()
    }
}

/// What one event asks of the PD, in this order: queue `out[..to_client]`
/// on the client socket; open the backend connection (`connect`: a backend
/// socket from `TLS_PORTS`, round-robin) or abort the backend socket
/// (`abort_backend`: then report its passes with [`Slot::abort_pass`]);
/// carry out `action` on the client socket; audit `outcomes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Next {
    pub to_client: usize,
    pub connect: bool,
    pub abort_backend: bool,
    pub action: Action,
    pub outcomes: Outcomes,
}

impl Slot {
    /// Whether the PD may hand over the next client record: during the
    /// handshake and the head, and while streaming once the bytes the last
    /// record carried for the backend have gone. Not while the backend
    /// connects: the client waits in its socket.
    pub fn reads_client(&self) -> bool {
        match self.stage() {
            Some(Stage::Handshake | Stage::Head) => true,
            Some(Stage::Streaming) => self.pending_rewrite.is_empty() && self.pending_rx.is_empty(),
            Some(Stage::BackendConnect) | None => false,
        }
    }

    /// The bytes to queue on the backend socket next, once connected: the
    /// rewritten head with the body bytes that came with it, then each
    /// body record's bytes up to `Content-Length`.
    pub fn to_backend(&self) -> &[u8] {
        if self.stage() != Some(Stage::Streaming) {
            return &[];
        }
        let (buf, span) = if self.pending_rewrite.is_empty() {
            (&self.rx[..], self.pending_rx)
        } else {
            (&self.rewrite[..], self.pending_rewrite)
        };
        buf.get(span.at..span.end).unwrap_or(&[])
    }

    /// The first `n` bytes of [`Slot::to_backend`] are queued on the
    /// backend socket: wiped here, the rest stays.
    pub fn backend_sent(&mut self, n: usize, now: u64) {
        if self.stage() != Some(Stage::Streaming) || n == 0 {
            return;
        }
        let (buf, span) = if self.pending_rewrite.is_empty() {
            (&mut self.rx[..], &mut self.pending_rx)
        } else {
            (&mut self.rewrite[..], &mut self.pending_rewrite)
        };
        let to = span.at.saturating_add(n).min(span.end);
        wipe(buf.get_mut(span.at..to).unwrap_or(&mut []));
        span.at = to;
        self.activity(now);
    }

    /// One complete client record (only while [`Slot::reads_client`]):
    /// the handshake, the head (refused or rewritten, then `connect`), the
    /// body for the backend, the client's close_notify.
    pub fn client_record<R: Rng, S: Signer>(
        &mut self,
        record: &[u8],
        out: &mut [u8],
        ctx: &mut Ctx<'_, R, S>,
        now: u64,
    ) -> Next {
        self.driven(|slot, next| {
            if slot.stage().is_none() {
                return;
            }
            if !slot.reads_client() {
                // The record buffer still holds bytes for the backend (or
                // they wait for the connect): a record now would overwrite
                // them, so the request would not reach the backend whole.
                return slot.end(CloseCause::Error, Closed::Error, now, next);
            }
            match slot.on_record(record, out, ctx, now) {
                Err(failed) => {
                    next.to_client = failed.written;
                    next.outcomes.push(Outcome::TlsRefused(failed.refusal));
                }
                Ok(step) => {
                    next.to_client = step.written;
                    match step.event {
                        Event::AppData(n) => match slot.stage() {
                            Some(Stage::Head) => slot.head_data(n, out, now, next),
                            Some(Stage::Streaming) => slot.body_data(n),
                            _ => wipe(slot.rx.get_mut(..n).unwrap_or(&mut [])),
                        },
                        Event::CloseNotify => slot.end(CloseCause::ClientClosed, Closed::ClientClosed, now, next),
                        Event::None | Event::Flight | Event::Connected => {}
                    }
                }
            }
        })
    }

    /// The client's FIN while the connection is open: before the response
    /// ended, so the backend is aborted with it.
    pub fn client_fin(&mut self, now: u64) -> Next {
        self.driven(|slot, next| slot.end(CloseCause::ClientClosed, Closed::ClientClosed, now, next))
    }

    /// The client socket closed under the connection (the peer's RST or a
    /// TCP timeout).
    pub fn client_gone(&mut self, now: u64) -> Next {
        self.driven(|slot, next| slot.end(CloseCause::Error, Closed::PeerReset, now, next))
    }

    /// The PD could not carry out what it was asked (a send that did not
    /// fit): abort.
    pub fn error(&mut self, now: u64) -> Next {
        self.driven(|slot, next| slot.end(CloseCause::Error, Closed::Error, now, next))
    }

    /// The backend socket reached Established.
    pub fn backend_connected(&mut self, now: u64) -> Next {
        self.driven(|slot, _| {
            if slot.stage() == Some(Stage::BackendConnect) {
                slot.advance(now);
                slot.activity(now);
            }
        })
    }

    /// Backend bytes, at most [`BACKEND_CHUNK`], sealed to the client.
    pub fn backend_data(&mut self, data: &[u8], out: &mut [u8], now: u64) -> Next {
        self.driven(|slot, next| {
            if slot.stage() != Some(Stage::Streaming) || data.is_empty() {
                return;
            }
            match slot.seal_app(data, out) {
                Ok(n) => {
                    next.to_client = n;
                    slot.activity(now);
                }
                Err(_) => slot.end(CloseCause::Error, Closed::Error, now, next),
            }
        })
    }

    /// The backend's FIN, every byte before it passed on: the response is
    /// complete, close_notify follows it. Before the connect completed, the
    /// backend is unavailable.
    pub fn backend_fin(&mut self, out: &mut [u8], now: u64) -> Next {
        self.driven(|slot, next| match slot.stage() {
            Some(Stage::Streaming) => {
                let (n, action) = slot.close(CloseCause::BackendFin, out, now);
                next.to_client = n;
                next.action = action;
                next.outcomes.push(Outcome::TlsClosed(Closed::BackendFin));
            }
            Some(Stage::BackendConnect) => slot.unavailable(out, now, next),
            _ => {}
        })
    }

    /// The backend socket reset (or closed without a FIN): while connecting
    /// the backend is unavailable (502); once connected the response is
    /// truncated, so the client gets a RST without close_notify.
    pub fn backend_rst(&mut self, out: &mut [u8], now: u64) -> Next {
        self.driven(|slot, next| match slot.stage() {
            Some(Stage::Streaming) => slot.end(CloseCause::BackendRst, Closed::BackendRst, now, next),
            Some(Stage::BackendConnect) => slot.unavailable(out, now, next),
            _ => {}
        })
    }

    /// The timers at `now` ([`Slot::tick`]), except that the backend
    /// connect timeout is answered with 502 rather than a RST: nothing of
    /// the response has gone yet.
    pub fn timers(&mut self, now: u64, out: &mut [u8]) -> Next {
        self.driven(|slot, next| {
            let connect_expired = match slot.phase {
                Phase::Open { stage: Stage::BackendConnect, since } => {
                    now.saturating_sub(since) >= BACKEND_CONNECT_TIMEOUT_NS
                        && now.saturating_sub(slot.accepted) < LIFETIME_NS
                }
                _ => false,
            };
            if connect_expired {
                next.outcomes.push(Outcome::TlsTimeout(Timeout::BackendConnect));
                return slot.unavailable(out, now, next);
            }
            let (action, timeout) = slot.tick(now);
            next.action = action;
            if let Some(t) = timeout {
                next.outcomes.push(Outcome::TlsTimeout(t));
            }
        })
    }

    /// Runs `f`, telling the PD to abort the backend socket if `f` did.
    fn driven(&mut self, f: impl FnOnce(&mut Self, &mut Next)) -> Next {
        let had_backend = self.backend_open;
        let mut next = Next::default();
        f(self, &mut next);
        next.abort_backend = had_backend && !self.backend_open;
        next
    }

    /// Ends an open connection at once: wiped, both sockets aborted,
    /// nothing more to the client.
    fn end(&mut self, cause: CloseCause, closed: Closed, now: u64, next: &mut Next) {
        if self.stage().is_none() {
            return;
        }
        next.to_client = 0;
        next.action = self.close(cause, &mut [], now).1;
        next.outcomes.push(Outcome::TlsClosed(closed));
    }

    /// `resp` sealed after the `next.to_client` bytes already in `out`,
    /// then close_notify (C10: a response `tls` generated in full).
    fn respond(&mut self, resp: &[u8], out: &mut [u8], now: u64, next: &mut Next) {
        let at = next.to_client;
        let rest = out.get_mut(at..).unwrap_or(&mut []);
        match self.seal_app(resp, rest) {
            Ok(n) => {
                let (m, action) = self.close(CloseCause::SelfResponse, rest.get_mut(n..).unwrap_or(&mut []), now);
                next.to_client = at.saturating_add(n).saturating_add(m);
                next.action = action;
                next.outcomes.push(Outcome::TlsClosed(Closed::SelfResponse));
            }
            Err(_) => self.end(CloseCause::Error, Closed::Error, now, next),
        }
    }

    fn unavailable(&mut self, out: &mut [u8], now: u64, next: &mut Next) {
        next.outcomes.push(Outcome::BackendUnavailable);
        self.respond(BAD_GATEWAY, out, now, next);
    }

    /// `rx[..n]` of the head stage into the head buffer; a complete head
    /// refused or rewritten.
    fn head_data(&mut self, n: usize, out: &mut [u8], now: u64, next: &mut Next) {
        let data = self.rx.get_mut(..n).unwrap_or(&mut []);
        let room = self.head.get_mut(self.head_len..).unwrap_or(&mut []);
        let moved = data.len().min(room.len());
        if let (Some(dst), Some(src)) = (room.get_mut(..moved), data.get_mut(..moved)) {
            dst.copy_from_slice(src);
            wipe(src);
        }
        self.head_len = self.head_len.saturating_add(moved);
        let head = self.head.get(..self.head_len).unwrap_or(&[]);
        let parsed = match head_end(head) {
            // The head buffer is MAX_HEAD long, so a head still open took
            // the whole record.
            Ok(None) => return wipe(self.rx.get_mut(..n).unwrap_or(&mut [])),
            Ok(Some(end)) => request_head(head.get(..end).unwrap_or(head))
                .and_then(|h| rewrite(&h, self.source, &mut self.rewrite).map(|len| (end, len, h.content_length))),
            Err(e) => Err(e),
        };
        let refused = match parsed {
            Ok((end, len, content_length)) => match self.forward(end, len, content_length, n, moved) {
                Some(()) => {
                    self.advance(now);
                    next.connect = true;
                    return;
                }
                // Not reached: the rewrite grows the head by at most
                // REWRITE_GROWTH and the rewrite buffer holds MAX_REWRITE.
                None => Status::HeaderFieldsTooLarge,
            },
            Err(e) => e.status(),
        };
        next.outcomes.push(Outcome::HttpRefused(refused));
        self.respond(refusal_response(refused), out, now, next);
    }

    /// An accepted head of `end` bytes, rewritten into `rewrite[..len]`:
    /// the body bytes that came with it (after the head in the head buffer,
    /// then the record's bytes from `moved` the head buffer had no room
    /// for) kept up to `content_length`, the rest wiped. None if they do
    /// not fit the rewrite buffer.
    fn forward(&mut self, end: usize, len: usize, content_length: usize, n: usize, moved: usize) -> Option<()> {
        let early = self.head_len.saturating_sub(end).min(content_length);
        let src = self.head.get(end..end.checked_add(early)?)?;
        self.rewrite.get_mut(len..len.checked_add(early)?)?.copy_from_slice(src);
        wipe(&mut self.head);
        self.head_len = 0;
        let left = content_length.saturating_sub(early);
        let rest = n.saturating_sub(moved).min(left);
        let rest_end = moved.saturating_add(rest);
        wipe(self.rx.get_mut(rest_end..n).unwrap_or(&mut []));
        self.pending_rewrite = Span { at: 0, end: len.saturating_add(early) };
        self.pending_rx = Span { at: moved, end: rest_end };
        self.body_left = left.saturating_sub(rest);
        Some(())
    }

    /// `rx[..n]` while streaming: up to the body still due goes to the
    /// backend; bytes past `Content-Length` are wiped, never forwarded.
    fn body_data(&mut self, n: usize) {
        let take = n.min(self.body_left);
        self.body_left = self.body_left.saturating_sub(take);
        wipe(self.rx.get_mut(take..n).unwrap_or(&mut []));
        self.pending_rx = Span { at: 0, end: take };
    }
}
