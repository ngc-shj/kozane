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
//! | ingress → pq    | `RpDatagram`: peer ip[4] port[2] msg[176 or 1092]   |
//! | pq → ingress    | `RpReply`, one per input: tag 1 `Reply` index[1] msg[1132 or 64]; tag 2 `NoReply` |
//! | pq → hs         | `PskInstall`: peer[2] osk[32] (secret)              |
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

/// ingress → pq (the source) and pq → ingress (the destination): a
/// Rosenpass message. Only InitHello and InitConf travel inbound, and only
/// RespHello and EmptyData outbound, so the length is one of four (M3 plan
/// C3/C4); anything else is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpDatagram<'a> {
    pub peer: Endpoint,
    pub msg: &'a [u8],
}

/// Wire lengths of the Rosenpass messages a responder exchanges.
pub const RP_LENS: [usize; 4] = [1092, 1132, 176, 64];

impl<'a> RpDatagram<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if !RP_LENS.contains(&self.msg.len()) {
            return None;
        }
        let mut at = 0;
        put_ep(out, &mut at, &self.peer)?;
        put(out, &mut at, self.msg)?;
        Some(at)
    }

    pub fn decode(b: &'a [u8]) -> Result<Self, Malformed> {
        let mut at = 0;
        let peer = take_ep(b, &mut at)?;
        let msg = rest(b, at)?;
        if !RP_LENS.contains(&msg.len()) {
            return Err(Malformed);
        }
        Ok(Self { peer, msg })
    }
}

/// pq → ingress: the completion record of one input (M3b plan C3). `pq`
/// sends exactly one per input it took, in input order, before returning
/// the input's buffer; `ingress` pairs it with its own record of that
/// forward. There is no endpoint: the reply goes where `ingress` recorded
/// the forward came from, so `pq` cannot aim it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpReply<'a> {
    /// A RespHello or an EmptyData. `index` is the configured peer an
    /// EmptyData belongs to, `RP_NO_PEER` otherwise; `ingress` range-checks
    /// it.
    Reply { index: u8, msg: &'a [u8] },
    /// The input was refused, dropped or unreadable: nothing to send.
    NoReply,
}

/// `RpReply::Reply`'s `index` when no configured peer is named.
pub const RP_NO_PEER: u8 = 0xff;

/// The reply lengths a responder sends: RespHello, EmptyData.
pub const RP_REPLY_LENS: [usize; 2] = [1132, 64];

const TAG_REPLY: u8 = 1;
const TAG_NO_REPLY: u8 = 2;

impl<'a> RpReply<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut at = 0;
        match *self {
            RpReply::Reply { index, msg } => {
                if !RP_REPLY_LENS.contains(&msg.len()) {
                    return None;
                }
                put(out, &mut at, &[TAG_REPLY, index])?;
                put(out, &mut at, msg)?;
            }
            RpReply::NoReply => put(out, &mut at, &[TAG_NO_REPLY])?,
        }
        Some(at)
    }

    pub fn decode(b: &'a [u8]) -> Result<Self, Malformed> {
        let mut at = 0;
        match take::<1>(b, &mut at)? {
            [TAG_REPLY] => {
                let [index] = *take::<1>(b, &mut at)?;
                let msg = rest(b, at)?;
                if !RP_REPLY_LENS.contains(&msg.len()) {
                    return Err(Malformed);
                }
                Ok(RpReply::Reply { index, msg })
            }
            [TAG_NO_REPLY] => {
                exact(b, at)?;
                Ok(RpReply::NoReply)
            }
            _ => Err(Malformed),
        }
    }
}

/// pq → hs: a fresh Rosenpass OSK for `peer`, the WireGuard PSK under L8.
/// Secret, so the receiving buffer is zeroed once copied out; not
/// `Debug`/`Clone`/`Copy`, nor `PartialEq` (no variable-time `==` on the
/// OSK).
pub struct PskInstall<'a> {
    pub peer: u16,
    pub osk: &'a [u8; 32],
}

pub const PSK_INSTALL_LEN: usize = 2 + 32;

impl<'a> PskInstall<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut at = 0;
        put(out, &mut at, &self.peer.to_le_bytes())?;
        put(out, &mut at, self.osk)?;
        Some(at)
    }

    pub fn decode(b: &'a [u8]) -> Result<Self, Malformed> {
        let mut at = 0;
        let peer = u16::from_le_bytes(*take::<2>(b, &mut at)?);
        let osk = take::<32>(b, &mut at)?;
        exact(b, at)?;
        Ok(Self { peer, osk })
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
mod proofs;

#[cfg(test)]
mod tests;
