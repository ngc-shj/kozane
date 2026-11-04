//! Netlink framing, in-tree (D6): requests built attribute by attribute,
//! replies checked for errno, sequence and port. Layouts are the kernel
//! uapi's (`linux/netlink.h`): `nlmsghdr` is len u32, type u16, flags u16,
//! seq u32, pid u32; an attribute is len u16, type u16, payload, padded to
//! 4. Every request carries `NLM_F_ACK`, and a call ends only at its ack.

use std::io;
use std::os::fd::{AsFd, OwnedFd};

use crate::sys;

pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLMSG_ERROR: u16 = 0x2;
pub const NLMSG_DONE: u16 = 0x3;
pub const NLA_F_NESTED: u16 = 0x8000;
const NLA_TYPE_MASK: u16 = 0x3fff;
pub const HDR_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NlError {
    /// The kernel refused the request with this errno.
    Errno(i32),
    /// A reply for another request.
    Seq { got: u32, want: u32 },
    /// A reply for another socket, or not from the kernel.
    Port { got: u32, want: u32 },
    /// A reply that does not parse.
    Malformed,
    /// A request too long for netlink's u16 attribute lengths.
    TooLong,
    Io(io::ErrorKind),
}

impl std::fmt::Display for NlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NlError::Errno(e) => write!(f, "{}", io::Error::from_raw_os_error(*e)),
            NlError::Seq { got, want } => write!(f, "reply sequence {got}, want {want}"),
            NlError::Port { got, want } => write!(f, "reply port {got}, want {want}"),
            NlError::Malformed => f.write_str("malformed reply"),
            NlError::TooLong => f.write_str("request too long"),
            NlError::Io(k) => write!(f, "{k}"),
        }
    }
}

fn pad4(n: usize) -> usize {
    n.checked_next_multiple_of(4).unwrap_or(usize::MAX)
}

/// One request. Its buffer may hold keys, so it is wiped on drop.
pub struct Msg {
    buf: Vec<u8>,
    nests: Vec<usize>,
    too_long: bool,
}

impl Msg {
    /// A request of type `ty`; `NLM_F_REQUEST | NLM_F_ACK` are always set.
    pub fn new(ty: u16, flags: u16) -> Self {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&[0; 4]);
        buf.extend_from_slice(&ty.to_ne_bytes());
        buf.extend_from_slice(&(flags | NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        buf.extend_from_slice(&[0; 8]);
        Self { buf, nests: Vec::new(), too_long: false }
    }

    /// The family header (`ifinfomsg`, `genlmsghdr`, ...), padded to 4.
    /// Appends `bytes`. The buffer may already hold a key, so it never
    /// reallocates in place: a larger buffer is taken, the old one copied
    /// and wiped, then freed (M9 Phase 2 self-check F1).
    fn put(&mut self, bytes: &[u8]) {
        let need = self.buf.len().saturating_add(bytes.len());
        if need > self.buf.capacity() {
            let mut grown = Vec::with_capacity(need.max(self.buf.capacity().saturating_mul(2)));
            grown.extend_from_slice(&self.buf);
            secret::wipe(&mut self.buf);
            self.buf = grown;
        }
        self.buf.extend_from_slice(bytes);
    }

    fn pad(&mut self) {
        let n = pad4(self.buf.len()).saturating_sub(self.buf.len());
        self.put([0u8; 3].get(..n).unwrap_or_default());
    }

    pub fn header(&mut self, bytes: &[u8]) -> &mut Self {
        self.put(bytes);
        self.pad();
        self
    }

    pub fn attr(&mut self, ty: u16, data: &[u8]) -> &mut Self {
        let Some(len) = data.len().checked_add(4).and_then(|n| u16::try_from(n).ok()) else {
            self.too_long = true;
            return self;
        };
        self.put(&len.to_ne_bytes());
        self.put(&ty.to_ne_bytes());
        self.put(data);
        self.pad();
        self
    }

    pub fn u8(&mut self, ty: u16, v: u8) -> &mut Self {
        self.attr(ty, &[v])
    }

    pub fn u16(&mut self, ty: u16, v: u16) -> &mut Self {
        self.attr(ty, &v.to_ne_bytes())
    }

    pub fn u32(&mut self, ty: u16, v: u32) -> &mut Self {
        self.attr(ty, &v.to_ne_bytes())
    }

    /// A NUL-terminated string.
    pub fn str(&mut self, ty: u16, s: &str) -> &mut Self {
        let mut v = Vec::with_capacity(s.len().saturating_add(1));
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        self.attr(ty, &v)
    }

    /// Opens a nested attribute (`NLA_F_NESTED` set); `end` closes it.
    pub fn nest(&mut self, ty: u16) -> &mut Self {
        self.nests.push(self.buf.len());
        self.put(&[0; 2]);
        self.put(&(ty | NLA_F_NESTED).to_ne_bytes());
        self
    }

    pub fn end(&mut self) -> &mut Self {
        let Some(at) = self.nests.pop() else {
            self.too_long = true;
            return self;
        };
        match self.buf.len().checked_sub(at).and_then(|n| u16::try_from(n).ok()) {
            Some(len) => {
                if let Some(d) = self.buf.get_mut(at..at.saturating_add(2)) {
                    d.copy_from_slice(&len.to_ne_bytes());
                }
            }
            None => self.too_long = true,
        }
        self
    }

    /// The finished bytes with `seq` and `pid` set.
    pub fn finish(&mut self, seq: u32, pid: u32) -> Result<&[u8], NlError> {
        if self.too_long || !self.nests.is_empty() {
            return Err(NlError::TooLong);
        }
        let len = u32::try_from(self.buf.len()).map_err(|_| NlError::TooLong)?;
        let h = self.buf.get_mut(..HDR_LEN).ok_or(NlError::TooLong)?;
        h.get_mut(0..4).ok_or(NlError::TooLong)?.copy_from_slice(&len.to_ne_bytes());
        h.get_mut(8..12).ok_or(NlError::TooLong)?.copy_from_slice(&seq.to_ne_bytes());
        h.get_mut(12..16).ok_or(NlError::TooLong)?.copy_from_slice(&pid.to_ne_bytes());
        Ok(&self.buf)
    }
}

impl Drop for Msg {
    fn drop(&mut self) {
        secret::wipe(&mut self.buf);
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

pub fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

/// What one reply datagram held for a request.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reply {
    /// Each data message's payload (after `nlmsghdr`).
    pub data: Vec<Vec<u8>>,
    /// The ack arrived: the request is done.
    pub acked: bool,
}

/// Parses one datagram of replies to request `seq` on port `port`. Any
/// message for another sequence or port, an errno, or a short message is
/// an error.
pub fn parse_reply(buf: &[u8], seq: u32, port: u32) -> Result<Reply, NlError> {
    let mut out = Reply::default();
    let mut at = 0usize;
    while at < buf.len() {
        let m = buf.get(at..).ok_or(NlError::Malformed)?;
        let len = usize::try_from(u32_at(m, 0).ok_or(NlError::Malformed)?).map_err(|_| NlError::Malformed)?;
        if len < HDR_LEN || len > m.len() {
            return Err(NlError::Malformed);
        }
        let ty = u16_at(m, 4).ok_or(NlError::Malformed)?;
        let got_seq = u32_at(m, 8).ok_or(NlError::Malformed)?;
        let got_pid = u32_at(m, 12).ok_or(NlError::Malformed)?;
        if got_seq != seq {
            return Err(NlError::Seq { got: got_seq, want: seq });
        }
        if got_pid != port {
            return Err(NlError::Port { got: got_pid, want: port });
        }
        let payload = m.get(HDR_LEN..len).ok_or(NlError::Malformed)?;
        match ty {
            NLMSG_ERROR => {
                let raw = u32_at(payload, 0).ok_or(NlError::Malformed)?;
                let errno = i32::from_ne_bytes(raw.to_ne_bytes());
                if errno != 0 {
                    return Err(NlError::Errno(errno.checked_neg().ok_or(NlError::Malformed)?));
                }
                out.acked = true;
            }
            NLMSG_DONE => return Err(NlError::Malformed),
            _ => out.data.push(payload.to_vec()),
        }
        at = at.checked_add(pad4(len)).ok_or(NlError::Malformed)?;
        if out.acked && at < buf.len() {
            return Err(NlError::Malformed);
        }
    }
    Ok(out)
}

/// Iterates `(type, payload)` over the attributes in `b`, the nested flag
/// stripped. Stops at the first malformed one.
pub fn attrs(b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut at = 0usize;
    std::iter::from_fn(move || {
        let rest = b.get(at..)?;
        let len = usize::from(u16_at(rest, 0)?);
        let ty = u16_at(rest, 2)? & NLA_TYPE_MASK;
        let payload = rest.get(4..len)?;
        at = at.checked_add(pad4(len))?;
        Some((ty, payload))
    })
}

/// A request/ack round trip; the tests replace the socket.
pub trait Transport {
    /// Sends `msg` and returns the data messages that came before its ack.
    fn call(&mut self, msg: &mut Msg) -> Result<Vec<Vec<u8>>, NlError>;
}

/// A netlink socket of one protocol.
pub struct Socket {
    fd: OwnedFd,
    port: u32,
    seq: u32,
    buf: Vec<u8>,
}

impl Socket {
    pub fn open(protocol: libc::c_int) -> io::Result<Self> {
        let (fd, port) = sys::netlink(protocol)?;
        Ok(Self { fd, port, seq: 0, buf: vec![0u8; 32 * 1024] })
    }
}

impl Transport for Socket {
    fn call(&mut self, msg: &mut Msg) -> Result<Vec<Vec<u8>>, NlError> {
        self.seq = self.seq.wrapping_add(1);
        let bytes = msg.finish(self.seq, self.port)?;
        sys::netlink_send(self.fd.as_fd(), bytes).map_err(|e| NlError::Io(e.kind()))?;
        let mut data = Vec::new();
        loop {
            let (n, from) = sys::netlink_recv(self.fd.as_fd(), &mut self.buf).map_err(|e| NlError::Io(e.kind()))?;
            if from != 0 {
                secret::wipe(&mut self.buf);
                return Err(NlError::Port { got: from, want: 0 });
            }
            let r = match self.buf.get(..n) {
                Some(b) => parse_reply(b, self.seq, self.port),
                None => Err(NlError::Malformed),
            };
            secret::wipe(&mut self.buf);
            let r = r?;
            data.extend(r.data);
            if r.acked {
                return Ok(data);
            }
        }
    }
}
