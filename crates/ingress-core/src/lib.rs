//! `ingress` v1 decision logic: answer ARP for our address and echo UDP on
//! one port; everything else is dropped with a reason. Pure and total, so it
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

use wire::{ArpOp, ArpPacket, Body, DropReason, EthAddrs, Frame, Ipv4, Mac, Udp4};

#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub mac: Mac,
    pub ipv4: Ipv4,
    pub echo_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Reply of this many bytes was written to `out`.
    ArpReplied(usize),
    UdpEchoed(usize),
    Dropped(DropReason),
    NotForUs,
    NoService,
}

const BROADCAST: Mac = [0xff; 6];

pub fn respond(cfg: &Config, frame: &[u8], out: &mut [u8]) -> Outcome {
    let f = match wire::parse_frame(frame) {
        Ok(f) => f,
        Err(r) => return Outcome::Dropped(r),
    };
    match f.body {
        Body::Arp(a) => arp(cfg, &f.eth, &a, out),
        Body::Udp4(u) => udp(cfg, &f.eth, &u, out),
    }
}

fn arp(cfg: &Config, eth: &EthAddrs, a: &ArpPacket, out: &mut [u8]) -> Outcome {
    if (eth.dst != cfg.mac && eth.dst != BROADCAST) || a.tpa != cfg.ipv4 {
        return Outcome::NotForUs;
    }
    if a.op != ArpOp::Request {
        return Outcome::NoService;
    }
    let reply = Frame {
        eth: EthAddrs { src: cfg.mac, dst: a.sha },
        body: Body::Arp(ArpPacket { op: ArpOp::Reply, sha: cfg.mac, spa: cfg.ipv4, tha: a.sha, tpa: a.spa }),
    };
    match wire::emit(&reply, out) {
        Ok(n) => Outcome::ArpReplied(n),
        // `out` too small: treat as no service rather than panic.
        Err(_) => Outcome::NoService,
    }
}

fn udp(cfg: &Config, eth: &EthAddrs, u: &Udp4<'_>, out: &mut [u8]) -> Outcome {
    if eth.dst != cfg.mac || u.dst != cfg.ipv4 {
        return Outcome::NotForUs;
    }
    if u.dport != cfg.echo_port {
        return Outcome::NoService;
    }
    let reply = Frame {
        eth: EthAddrs { src: cfg.mac, dst: eth.src },
        body: Body::Udp4(Udp4 { src: cfg.ipv4, dst: u.src, sport: u.dport, dport: u.sport, payload: u.payload }),
    };
    match wire::emit(&reply, out) {
        Ok(n) => Outcome::UdpEchoed(n),
        Err(_) => Outcome::NoService,
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// `respond` never panics and never claims more bytes than `out` holds.
    #[kani::proof]
    #[kani::unwind(66)]
    fn respond_is_total_and_bounded() {
        let cfg = Config { mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56], ipv4: [10, 0, 2, 15], echo_port: 7 };
        let buf: [u8; 64] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 64);
        let mut out = [0u8; 64];
        let o = respond(&cfg, buf.get(..len).unwrap_or(&[]), &mut out);
        if let Outcome::ArpReplied(n) | Outcome::UdpEchoed(n) = o {
            assert!(n <= out.len());
        }
        kani::cover!(matches!(o, Outcome::ArpReplied(_)));
        kani::cover!(matches!(o, Outcome::UdpEchoed(_)));
        kani::cover!(o == Outcome::NotForUs);
        kani::cover!(o == Outcome::NoService);
    }
}

#[cfg(test)]
mod tests;
