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
//!
//! Integers are little-endian.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use wg_wire::{INITIATION_LEN, RESPONSE_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub ip: [u8; 4],
    pub port: u16,
}

const EP_LEN: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed;

fn put(out: &mut [u8], at: &mut usize, data: &[u8]) -> Option<()> {
    let end = at.checked_add(data.len())?;
    out.get_mut(*at..end)?.copy_from_slice(data);
    *at = end;
    Some(())
}

fn take<'a, const N: usize>(b: &'a [u8], at: &mut usize) -> Result<&'a [u8; N], Malformed> {
    let end = at.checked_add(N).ok_or(Malformed)?;
    let f = b.get(*at..end).ok_or(Malformed)?.try_into().map_err(|_| Malformed)?;
    *at = end;
    Ok(f)
}

fn put_ep(out: &mut [u8], at: &mut usize, ep: &Endpoint) -> Option<()> {
    put(out, at, &ep.ip)?;
    put(out, at, &ep.port.to_le_bytes())
}

fn take_ep(b: &[u8], at: &mut usize) -> Result<Endpoint, Malformed> {
    let ip = *take::<4>(b, at)?;
    let port = u16::from_le_bytes(*take::<2>(b, at)?);
    Ok(Endpoint { ip, port })
}

fn rest(b: &[u8], at: usize) -> Result<&[u8], Malformed> {
    b.get(at..).ok_or(Malformed)
}

fn exact(b: &[u8], at: usize) -> Result<(), Malformed> {
    if at == b.len() { Ok(()) } else { Err(Malformed) }
}

/// ingress → hs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Initiation<'a> {
    pub src: Endpoint,
    pub msg: &'a [u8; INITIATION_LEN],
}

pub const INITIATION_MSG_LEN: usize = EP_LEN + INITIATION_LEN;

impl<'a> Initiation<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut at = 0;
        put_ep(out, &mut at, &self.src)?;
        put(out, &mut at, self.msg)?;
        Some(at)
    }

    pub fn decode(b: &'a [u8]) -> Result<Self, Malformed> {
        let mut at = 0;
        let src = take_ep(b, &mut at)?;
        let msg = take::<INITIATION_LEN>(b, &mut at)?;
        exact(b, at)?;
        Ok(Self { src, msg })
    }
}

/// hs → ingress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response<'a> {
    pub dst: Endpoint,
    pub msg: &'a [u8; RESPONSE_LEN],
}

impl<'a> Response<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut at = 0;
        put_ep(out, &mut at, &self.dst)?;
        put(out, &mut at, self.msg)?;
        Some(at)
    }

    pub fn decode(b: &'a [u8]) -> Result<Self, Malformed> {
        let mut at = 0;
        let dst = take_ep(b, &mut at)?;
        let msg = take::<RESPONSE_LEN>(b, &mut at)?;
        exact(b, at)?;
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

impl<'a> Install<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut at = 0;
        put(out, &mut at, &self.peer.to_le_bytes())?;
        put(out, &mut at, &self.local_index.to_le_bytes())?;
        put(out, &mut at, &self.remote_index.to_le_bytes())?;
        put(out, &mut at, self.send)?;
        put(out, &mut at, self.recv)?;
        Some(at)
    }

    pub fn decode(b: &'a [u8]) -> Result<Self, Malformed> {
        let mut at = 0;
        let peer = u16::from_le_bytes(*take::<2>(b, &mut at)?);
        let local_index = u32::from_le_bytes(*take::<4>(b, &mut at)?);
        let remote_index = u32::from_le_bytes(*take::<4>(b, &mut at)?);
        let send = take::<32>(b, &mut at)?;
        let recv = take::<32>(b, &mut at)?;
        exact(b, at)?;
        Ok(Self { peer, local_index, remote_index, send, recv })
    }
}

/// ingress → data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transport<'a> {
    pub src: Endpoint,
    pub msg: &'a [u8],
}

impl<'a> Transport<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut at = 0;
        put_ep(out, &mut at, &self.src)?;
        put(out, &mut at, self.msg)?;
        Some(at)
    }

    pub fn decode(b: &'a [u8]) -> Result<Self, Malformed> {
        let mut at = 0;
        let src = take_ep(b, &mut at)?;
        Ok(Self { src, msg: rest(b, at)? })
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

const TAG_OUTBOUND: u8 = 1;
const TAG_ENDPOINT: u8 = 2;

impl<'a> ToIngress<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut at = 0;
        match self {
            ToIngress::Outbound { peer, msg } => {
                put(out, &mut at, &[TAG_OUTBOUND])?;
                put(out, &mut at, &peer.to_le_bytes())?;
                put(out, &mut at, msg)?;
            }
            ToIngress::EndpointUpdate { peer, endpoint } => {
                put(out, &mut at, &[TAG_ENDPOINT])?;
                put(out, &mut at, &peer.to_le_bytes())?;
                put_ep(out, &mut at, endpoint)?;
            }
        }
        Some(at)
    }

    pub fn decode(b: &'a [u8]) -> Result<Self, Malformed> {
        let mut at = 0;
        let [tag] = *take::<1>(b, &mut at)?;
        let peer = u16::from_le_bytes(*take::<2>(b, &mut at)?);
        match tag {
            TAG_OUTBOUND => Ok(ToIngress::Outbound { peer, msg: rest(b, at)? }),
            TAG_ENDPOINT => {
                let endpoint = take_ep(b, &mut at)?;
                exact(b, at)?;
                Ok(ToIngress::EndpointUpdate { peer, endpoint })
            }
            _ => Err(Malformed),
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Every decoder is total, and whatever decodes re-encodes to the
    /// same bytes (so no field is silently dropped).
    #[kani::proof]
    #[kani::unwind(20)]
    fn small_decoders_are_total_and_round_trip() {
        let buf: [u8; 16] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let b = buf.get(..len).unwrap_or(&[]);
        let mut out = [0u8; 16];
        if let Ok(m) = ToIngress::decode(b) {
            kani::cover!(matches!(m, ToIngress::Outbound { .. }));
            kani::cover!(matches!(m, ToIngress::EndpointUpdate { .. }));
            assert!(m.encode(&mut out) == Some(len) && out.get(..len) == Some(b));
        }
        if let Ok(m) = Transport::decode(b) {
            kani::cover!(!m.msg.is_empty());
            assert!(m.encode(&mut out) == Some(len) && out.get(..len) == Some(b));
        }
    }
}

#[cfg(test)]
mod tests;
