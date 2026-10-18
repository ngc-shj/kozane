//! `inner` decision logic (plan C13): the gateway's inside-LAN face. It
//! answers ARP for the inside address, forwards IPv4 from static neighbors
//! (source IP and MAC must both match one) towards the tunnel, and frames
//! decrypted packets for a static neighbor. No ARP cache: every address
//! comes from the compiled configuration (law L6). Pure and total, so it
//! is unit-tested and proved on the host; the PD only moves bytes.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use wire::{ArpOp, ArpPacket, Body, DropReason, EthAddrs, Frame, Ip4Packet, Ipv4, Mac};

#[derive(Debug, Clone, Copy)]
pub struct Config<'a> {
    pub mac: Mac,
    pub ipv4: Ipv4,
    /// Static (IP, MAC) pairs of inside hosts.
    pub neighbors: &'a [(Ipv4, Mac)],
}

impl Config<'_> {
    fn neighbor_mac(&self, ip: &Ipv4) -> Option<Mac> {
        self.neighbors.iter().find(|(i, _)| i == ip).map(|(_, m)| *m)
    }

    fn is_neighbor(&self, ip: &Ipv4, mac: &Mac) -> bool {
        self.neighbor_mac(ip) == Some(*mac)
    }
}

/// Result of a frame received on the inside NIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FromLan<'a> {
    /// ARP reply of this many bytes was written to `out`.
    ArpReplied(usize),
    /// IPv4 datagram to send through the tunnel, verbatim.
    Forward(&'a [u8]),
    Dropped(DropReason),
    NotForUs,
    /// Addressed to the gateway itself; nothing listens on the inside.
    NoService,
    /// Source IP/MAC is not a static neighbor pair, or claims to be us.
    Spoofed,
}

/// Result of a decrypted packet to deliver on the inside NIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToLan {
    /// Frame of this many bytes was written to `out`.
    Emitted(usize),
    Dropped(DropReason),
    /// Destination is not a static neighbor.
    UnknownNeighbor,
    /// `out` cannot hold the frame.
    NoBuffer,
}

const BROADCAST: Mac = [0xff; 6];

pub fn from_lan<'a>(cfg: &Config<'_>, frame: &'a [u8], out: &mut [u8]) -> FromLan<'a> {
    let f = match wire::parse_frame_ip(frame) {
        Ok(f) => f,
        Err(r) => return FromLan::Dropped(r),
    };
    match f.body {
        Body::Arp(a) => arp(cfg, &f.eth, &a, out),
        Body::Ipv4(p) => ipv4(cfg, &f.eth, &p),
        // `parse_frame_ip` never yields it.
        Body::Udp4(_) => FromLan::NoService,
    }
}

fn arp<'a>(cfg: &Config<'_>, eth: &EthAddrs, a: &ArpPacket, out: &mut [u8]) -> FromLan<'a> {
    if (eth.dst != cfg.mac && eth.dst != BROADCAST) || a.tpa != cfg.ipv4 {
        return FromLan::NotForUs;
    }
    if a.sha != eth.src || !cfg.is_neighbor(&a.spa, &a.sha) {
        return FromLan::Spoofed;
    }
    if a.op != ArpOp::Request {
        return FromLan::NoService;
    }
    let reply = Frame {
        eth: EthAddrs { src: cfg.mac, dst: a.sha },
        body: Body::Arp(ArpPacket { op: ArpOp::Reply, sha: cfg.mac, spa: cfg.ipv4, tha: a.sha, tpa: a.spa }),
    };
    match wire::emit(&reply, out) {
        Ok(n) => FromLan::ArpReplied(n),
        Err(_) => FromLan::NoService,
    }
}

fn ipv4<'a>(cfg: &Config<'_>, eth: &EthAddrs, p: &Ip4Packet<'a>) -> FromLan<'a> {
    if eth.dst != cfg.mac {
        return FromLan::NotForUs;
    }
    if !cfg.is_neighbor(&p.src, &eth.src) {
        return FromLan::Spoofed;
    }
    if p.dst == cfg.ipv4 {
        return FromLan::NoService;
    }
    FromLan::Forward(p.packet)
}

pub fn to_lan(cfg: &Config<'_>, packet: &[u8], out: &mut [u8]) -> ToLan {
    let p = match wire::parse_ipv4_packet(packet) {
        Ok(p) => p,
        Err(r) => return ToLan::Dropped(r),
    };
    let Some(dst) = cfg.neighbor_mac(&p.dst) else {
        return ToLan::UnknownNeighbor;
    };
    let frame = Frame { eth: EthAddrs { src: cfg.mac, dst }, body: Body::Ipv4(p) };
    match wire::emit(&frame, out) {
        Ok(n) => ToLan::Emitted(n),
        Err(_) => ToLan::NoBuffer,
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    const CFG: Config<'static> = Config {
        mac: [0x52, 0x54, 0, 0x12, 0x34, 0x57],
        ipv4: [10, 99, 0, 1],
        neighbors: &[([10, 99, 0, 2], [0x02, 0, 0, 0, 0x99, 0x02])],
    };

    /// `from_lan` never panics, never claims more bytes than `out` holds,
    /// and only forwards a datagram whose source is a static neighbor.
    #[kani::proof]
    #[kani::unwind(66)]
    fn from_lan_is_total_and_forwards_only_neighbors() {
        let buf: [u8; 64] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 64);
        let frame = buf.get(..len).unwrap_or(&[]);
        let mut out = [0u8; 64];
        let o = from_lan(&CFG, frame, &mut out);
        if let FromLan::ArpReplied(n) = o {
            assert!(n <= out.len());
        }
        if let FromLan::Forward(p) = o {
            let src_mac = frame.get(6..12);
            let src_ip = p.get(12..16);
            assert!(src_mac == Some(&CFG.neighbors[0].1[..]) && src_ip == Some(&CFG.neighbors[0].0[..]));
        }
        kani::cover!(matches!(o, FromLan::ArpReplied(_)));
        kani::cover!(matches!(o, FromLan::Forward(_)));
        kani::cover!(o == FromLan::Spoofed);
        kani::cover!(o == FromLan::NotForUs);
        kani::cover!(o == FromLan::NoService);
    }

    /// `to_lan` never panics and only addresses static neighbors.
    #[kani::proof]
    #[kani::unwind(66)]
    fn to_lan_is_total_and_addresses_only_neighbors() {
        let buf: [u8; 48] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 48);
        let mut out = [0u8; 64];
        let o = to_lan(&CFG, buf.get(..len).unwrap_or(&[]), &mut out);
        if let ToLan::Emitted(n) = o {
            assert!(n <= out.len());
            assert!(out.get(..6) == Some(&CFG.neighbors[0].1[..]));
        }
        kani::cover!(matches!(o, ToLan::Emitted(_)));
        kani::cover!(o == ToLan::UnknownNeighbor);
    }
}

#[cfg(test)]
mod tests;
