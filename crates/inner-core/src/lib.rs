//! `inner` decision logic (plan C13): the gateway's inside-LAN face. It
//! answers ARP for the inside address, forwards IPv4 from static neighbors
//! (source IP and MAC must both match one) towards the tunnel, and frames
//! decrypted packets for a static neighbor. Both directions are routed hops:
//! TTL is decremented and TTL <= 1 is dropped (`wire::forward_ipv4`). No ARP cache: every address
//! comes from the compiled configuration (law L6). Pure and total, so it
//! is unit-tested and proved on the host; the PD only moves bytes.
//!
//! The HTTPS backend link (M6 plan C4) is the one exception to "nothing
//! listens on the inside": `tls` reaches exactly one backend address and
//! port from its own ports, and only that backend's segments to those
//! ports reach `tls`. Both are local delivery, not routed hops, so the TTL
//! is left alone.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use wire::{ArpOp, ArpPacket, Body, DropReason, EthAddrs, Frame, IPPROTO_TCP, Ip4Packet, Ipv4, Mac};

#[derive(Debug, Clone, Copy)]
pub struct Config<'a> {
    pub mac: Mac,
    pub ipv4: Ipv4,
    /// Static (IP, MAC) pairs of inside hosts.
    pub neighbors: &'a [(Ipv4, Mac)],
    /// The HTTPS backend's address and TCP port; the address is a static
    /// neighbor inside the inside prefix (config-validated).
    pub backend: (Ipv4, u16),
    /// `tls`'s inside TCP ports: start and count, start nonzero and
    /// start + count <= 65536 (config-validated).
    pub tls_ports: (u16, u16),
}

impl Config<'_> {
    fn neighbor_mac(&self, ip: &Ipv4) -> Option<Mac> {
        self.neighbors.iter().find(|(i, _)| i == ip).map(|(_, m)| *m)
    }

    fn is_neighbor(&self, ip: &Ipv4, mac: &Mac) -> bool {
        self.neighbor_mac(ip) == Some(*mac)
    }

    fn is_tls_port(&self, port: u16) -> bool {
        let (start, count) = self.tls_ports;
        port.checked_sub(start).is_some_and(|offset| offset < count)
    }
}

/// Result of a frame received on the inside NIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FromLan {
    /// ARP reply of this many bytes was written to `out`.
    ArpReplied(usize),
    /// IPv4 datagram of this many bytes, written to `out` with its TTL
    /// decremented, to send through the tunnel.
    Forward(usize),
    Dropped(DropReason),
    NotForUs,
    /// TCP segment of this many bytes from the backend's address and port
    /// to one of `tls`'s ports, written to `out` unchanged (local delivery,
    /// TTL kept), for `tls`.
    Tls(usize),
    /// Addressed to the gateway itself, and not the backend answering `tls`.
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

/// Result of a segment from `tls` for the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FromTls {
    /// Frame of this many bytes was written to `out`.
    Emitted(usize),
    /// Malformed IPv4 or TCP.
    Dropped(DropReason),
    /// Valid, but not TCP from our address and one of `tls`'s ports to the
    /// backend's address and port.
    Refused,
    /// The backend is not a static neighbor (config validation rules it out).
    UnknownNeighbor,
    /// `out` cannot hold the frame.
    NoBuffer,
}

/// The audit reason for `FromTls::Refused`: the one `ingress` gives a
/// refused `tls` segment (plan C2); the audit line's source PD tells the
/// two gates apart.
pub const TLS_REFUSED: DropReason = DropReason::TcpEgressRefused;

const BROADCAST: Mac = [0xff; 6];

pub fn from_lan(cfg: &Config<'_>, frame: &[u8], out: &mut [u8]) -> FromLan {
    let f = match wire::parse_frame_ip(frame) {
        Ok(f) => f,
        Err(r) => return FromLan::Dropped(r),
    };
    match f.body {
        Body::Arp(a) => arp(cfg, &f.eth, &a, out),
        Body::Ipv4(p) => ipv4(cfg, &f.eth, &p, out),
        // `parse_frame_ip` never yields it.
        Body::Udp4(_) => FromLan::NoService,
    }
}

fn arp(cfg: &Config<'_>, eth: &EthAddrs, a: &ArpPacket, out: &mut [u8]) -> FromLan {
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

fn ipv4(cfg: &Config<'_>, eth: &EthAddrs, p: &Ip4Packet<'_>, out: &mut [u8]) -> FromLan {
    if eth.dst != cfg.mac {
        return FromLan::NotForUs;
    }
    if !cfg.is_neighbor(&p.src, &eth.src) {
        return FromLan::Spoofed;
    }
    if p.dst == cfg.ipv4 {
        return local(cfg, p, out);
    }
    match wire::forward_ipv4(p.packet, out) {
        Ok(n) => FromLan::Forward(n),
        Err(r) => FromLan::Dropped(r),
    }
}

/// A datagram from a neighbor to the gateway itself: only the backend's
/// segments from its port to one of `tls`'s ports are delivered.
fn local(cfg: &Config<'_>, p: &Ip4Packet<'_>, out: &mut [u8]) -> FromLan {
    if p.proto != IPPROTO_TCP {
        return FromLan::NoService;
    }
    let t = match wire::parse_tcp(p) {
        Ok(t) => t,
        Err(r) => return FromLan::Dropped(r),
    };
    let (backend_ip, backend_port) = cfg.backend;
    if p.src != backend_ip || t.src_port != backend_port || !cfg.is_tls_port(t.dst_port) {
        return FromLan::NoService;
    }
    let n = p.packet.len();
    let Some(dst) = out.get_mut(..n) else {
        return FromLan::Dropped(DropReason::TooLong);
    };
    dst.copy_from_slice(p.packet);
    FromLan::Tls(n)
}

pub fn to_lan(cfg: &Config<'_>, packet: &[u8], out: &mut [u8]) -> ToLan {
    let mut hop = [0u8; wire::MAX_FRAME];
    let p = match wire::forward_ipv4(packet, &mut hop) {
        Ok(n) => match wire::parse_ipv4_packet(hop.get(..n).unwrap_or(&[])) {
            Ok(p) => p,
            Err(r) => return ToLan::Dropped(r),
        },
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

/// The one gate for what `tls` sends inside (M6 plan C4, S2): a packet
/// from `tln` leaves only as a valid IPv4/TCP datagram of at most 1500
/// bytes, both checksums right, from our address and one of `tls`'s ports
/// to exactly the backend's address and port, framed to the backend's
/// static MAC. `tls` is the origin, so the TTL is left alone.
pub fn from_tls(cfg: &Config<'_>, packet: &[u8], out: &mut [u8]) -> FromTls {
    if packet.len() > wire::MAX_FRAME - wire::ETH_HDR {
        return FromTls::Dropped(DropReason::TooLong);
    }
    let p = match wire::parse_ipv4_packet(packet) {
        Ok(p) => p,
        Err(r) => return FromTls::Dropped(r),
    };
    if p.proto != IPPROTO_TCP {
        return FromTls::Refused;
    }
    let t = match wire::parse_tcp(&p) {
        Ok(t) => t,
        Err(r) => return FromTls::Dropped(r),
    };
    let (backend_ip, backend_port) = cfg.backend;
    if p.src != cfg.ipv4 || !cfg.is_tls_port(t.src_port) || p.dst != backend_ip || t.dst_port != backend_port {
        return FromTls::Refused;
    }
    let Some(dst) = cfg.neighbor_mac(&p.dst) else {
        return FromTls::UnknownNeighbor;
    };
    let frame = Frame { eth: EthAddrs { src: cfg.mac, dst }, body: Body::Ipv4(p) };
    match wire::emit(&frame, out) {
        Ok(n) => FromTls::Emitted(n),
        Err(_) => FromTls::NoBuffer,
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    const CFG: Config<'static> = Config {
        mac: [0x52, 0x54, 0, 0x12, 0x34, 0x57],
        ipv4: [10, 99, 0, 1],
        neighbors: &[([10, 99, 0, 2], [0x02, 0, 0, 0, 0x99, 0x02])],
        backend: ([10, 99, 0, 2], 8080),
        tls_ports: (40000, 1024),
    };

    /// `port` lies in `CFG.tls_ports`, written independently of
    /// `Config::is_tls_port`.
    fn in_tls_ports(port: u16) -> bool {
        let (start, count) = CFG.tls_ports;
        u32::from(port) >= u32::from(start) && u32::from(port) < u32::from(start) + u32::from(count)
    }

    fn be16(b: &[u8], at: usize) -> u16 {
        u16::from_be_bytes([b[at], b[at + 1]])
    }

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
        if let FromLan::Forward(n) = o {
            assert!(n <= out.len());
            let src_mac = frame.get(6..12);
            let src_ip = out.get(12..16);
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

    /// `from_lan` hands `tls` only the backend's TCP segments from its port
    /// to our address and one of `tls`'s ports, from the backend's static
    /// MAC, byte for byte as received (TTL kept). Checked on the bytes
    /// written, not through the parsers.
    #[kani::proof]
    #[kani::unwind(66)]
    fn from_lan_delivers_to_tls_only_backend_segments() {
        let buf: [u8; 64] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 64);
        let frame = buf.get(..len).unwrap_or(&[]);
        let mut out = [0u8; 64];
        let o = from_lan(&CFG, frame, &mut out);
        if let FromLan::Tls(n) = o {
            // An Ethernet header, a 20-byte IPv4 header and a TCP header.
            assert!(n >= 40 && wire::ETH_HDR + n <= frame.len());
            assert!(out[..n] == frame[wire::ETH_HDR..wire::ETH_HDR + n]);
            assert!(frame[..6] == CFG.mac && frame[6..12] == CFG.neighbors[0].1);
            assert!(out[0] == 0x45 && out[9] == IPPROTO_TCP);
            assert!(out[12..16] == CFG.backend.0 && out[16..20] == CFG.ipv4);
            assert!(be16(&out, 20) == CFG.backend.1 && in_tls_ports(be16(&out, 22)));
        }
        // The backend's SYN-ACK reaches `tls`.
        kani::cover!(matches!(o, FromLan::Tls(_)) && out[33] & 0x3f == wire::TCP_SYN | wire::TCP_ACK);
        kani::cover!(o == FromLan::NoService);
    }

    /// `from_tls` emits only TCP from our address and one of `tls`'s ports
    /// to exactly the backend's address and port, framed from our MAC to
    /// the backend's static MAC, the datagram unchanged (TTL kept).
    #[kani::proof]
    #[kani::unwind(66)]
    fn from_tls_emits_only_to_the_backend() {
        let buf: [u8; 64] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 64);
        let packet = buf.get(..len).unwrap_or(&[]);
        let mut out = [0u8; 80];
        let o = from_tls(&CFG, packet, &mut out);
        if let FromTls::Emitted(n) = o {
            assert!(n <= out.len() && n >= wire::ETH_HDR + 40);
            let ip = &out[wire::ETH_HDR..n];
            assert!(packet.get(..ip.len()) == Some(ip));
            assert!(out[..6] == CFG.neighbors[0].1 && out[6..12] == CFG.mac);
            assert!(out[12..14] == [0x08, 0x00]);
            assert!(ip[0] == 0x45 && ip[9] == IPPROTO_TCP);
            assert!(ip[12..16] == CFG.ipv4 && ip[16..20] == CFG.backend.0);
            assert!(in_tls_ports(be16(ip, 20)) && be16(ip, 22) == CFG.backend.1);
        }
        // A legitimate connection request leaves.
        kani::cover!(matches!(o, FromTls::Emitted(n) if n > 47 && out[47] & 0x3f == wire::TCP_SYN));
        kani::cover!(o == FromTls::Refused);
    }
}

#[cfg(test)]
mod tests;
