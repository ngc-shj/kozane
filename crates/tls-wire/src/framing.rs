//! Handshake message framing (RFC 8446 section 5.1; M6 plan C6, F23,
//! S11b): a message may span several records and several messages may
//! share one; a message is at most [`MAX_HANDSHAKE`] bytes with its header.
//! Whether a message must end at a record boundary is the caller's rule
//! (`tls-core`: ClientHello, client Finished and KeyUpdate precede a key
//! change), checked with [`Reassembler::is_empty`] after taking it.

use crate::{HANDSHAKE_HEADER_LEN, MAX_HANDSHAKE, Refusal};

/// One complete handshake message at the front of the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
    pub msg_type: u8,
    pub body: &'a [u8],
    /// Header and body: what the transcript hashes and `consume` removes.
    pub bytes: &'a [u8],
}

/// Handshake bytes received so far and not yet taken. Holds no secret, but
/// is wiped with the connection's other buffers.
pub struct Reassembler {
    buf: [u8; MAX_HANDSHAKE],
    len: usize,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub const fn new() -> Self {
        Self { buf: [0; MAX_HANDSHAKE], len: 0 }
    }

    /// Appends one record's handshake content. A zero-length fragment is
    /// malformed (section 5.1).
    pub fn push(&mut self, fragment: &[u8]) -> Result<(), Refusal> {
        if fragment.is_empty() {
            return Err(Refusal::Decode);
        }
        let end = self.len.checked_add(fragment.len()).filter(|&e| e <= MAX_HANDSHAKE).ok_or(Refusal::HandshakeTooLong)?;
        self.buf.get_mut(self.len..end).ok_or(Refusal::HandshakeTooLong)?.copy_from_slice(fragment);
        self.len = end;
        Ok(())
    }

    /// The first message if it is complete. A header announcing more than
    /// [`MAX_HANDSHAKE`] is refused at once, before its body arrives.
    pub fn peek(&self) -> Result<Option<Message<'_>>, Refusal> {
        let held = self.buf.get(..self.len).ok_or(Refusal::Internal)?;
        let Some((&msg_type, rest)) = held.split_first() else { return Ok(None) };
        let Some([a, b, c]) = rest.get(..3) else { return Ok(None) };
        let body_len = u32::from_be_bytes([0, *a, *b, *c]) as usize;
        let total = body_len.checked_add(HANDSHAKE_HEADER_LEN).filter(|&t| t <= MAX_HANDSHAKE).ok_or(Refusal::HandshakeTooLong)?;
        let Some(bytes) = held.get(..total) else { return Ok(None) };
        let body = bytes.get(HANDSHAKE_HEADER_LEN..).ok_or(Refusal::Internal)?;
        Ok(Some(Message { msg_type, body, bytes }))
    }

    /// Removes the first `n` bytes (a message `peek` returned).
    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.len);
        self.buf.copy_within(n..self.len, 0);
        let left = self.len.saturating_sub(n);
        if let Some(stale) = self.buf.get_mut(left..self.len) {
            stale.fill(0);
        }
        self.len = left;
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The type of the first message, complete or not.
    pub fn first_type(&self) -> Option<u8> {
        self.buf.get(..self.len).and_then(|held| held.first().copied())
    }

    /// Bytes held: complete messages and the start of the next.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn wipe(&mut self) {
        self.buf.fill(0);
        self.len = 0;
    }

    /// Nothing held and every byte zero (the slot wipe's check).
    pub fn is_zeroized(&self) -> bool {
        self.len == 0 && self.buf.iter().all(|&b| b == 0)
    }
}
