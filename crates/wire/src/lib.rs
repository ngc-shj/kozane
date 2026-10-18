//! Ethernet / ARP / IPv4 / UDP parsing and emission for untrusted frames.
//!
//! `parse_frame` is total: every input yields either a `Frame` or a
//! `DropReason`, and it never panics (proved by the Kani harnesses in
//! `proofs`). It accepts only the narrow subset `ingress` needs: no VLANs,
//! no IPv4 options, no fragments. `parse_frame_ip` is the inside-NIC
//! variant: same rules, but any IPv4 protocol, kept verbatim for forwarding.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

pub type Mac = [u8; 6];
pub type Ipv4 = [u8; 4];

pub const ETH_HDR: usize = 14;
pub const ARP_LEN: usize = 28;
pub const IPV4_HDR: usize = 20;
pub const UDP_HDR: usize = 8;
/// Largest frame we emit or accept (no jumbo frames, no FCS).
pub const MAX_FRAME: usize = 1514;
pub const MAX_UDP_PAYLOAD: usize = MAX_FRAME - ETH_HDR - IPV4_HDR - UDP_HDR;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const IPPROTO_UDP: u8 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthAddrs {
    pub src: Mac,
    pub dst: Mac,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOp {
    Request,
    Reply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    pub op: ArpOp,
    pub sha: Mac,
    pub spa: Ipv4,
    pub tha: Mac,
    pub tpa: Ipv4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Udp4<'a> {
    pub src: Ipv4,
    pub dst: Ipv4,
    pub sport: u16,
    pub dport: u16,
    pub payload: &'a [u8],
}

/// A validated IPv4 datagram of any protocol. `packet` is the datagram
/// exactly as received (header included, Ethernet padding removed), so it
/// can be forwarded without re-encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ip4Packet<'a> {
    pub src: Ipv4,
    pub dst: Ipv4,
    pub proto: u8,
    pub packet: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body<'a> {
    Arp(ArpPacket),
    Udp4(Udp4<'a>),
    /// Only from `parse_frame_ip`.
    Ipv4(Ip4Packet<'a>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub eth: EthAddrs,
    pub body: Body<'a>,
}

/// Declares `DropReason` and `DropReason::ALL` from one list, so a variant
/// cannot be added without also being in `ALL`.
macro_rules! drop_reasons {
    ($($name:ident = $code:literal,)+) => {
        /// Why a frame was dropped. Values are stable: they appear in audit events.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u16)]
        pub enum DropReason {
            $($name = $code,)+
        }

        impl DropReason {
            pub const ALL: &'static [DropReason] = &[$(DropReason::$name,)+];
        }
    };
}

drop_reasons! {
    TooShort = 1,
    TooLong = 2,
    EthBadSrc = 3,
    UnknownEtherType = 4,
    ArpMalformed = 5,
    ArpBadSender = 6,
    Ipv4Version = 7,
    Ipv4Options = 8,
    Ipv4Fragment = 9,
    Ipv4BadLength = 10,
    Ipv4BadChecksum = 11,
    Ipv4BadSrc = 12,
    NotUdp = 13,
    UdpBadLength = 14,
    UdpBadChecksum = 15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitError {
    TooSmall,
    /// The frame would not be accepted by `parse_frame` (bad source address,
    /// oversized payload), so it is refused rather than emitted.
    Invalid,
}

fn mac_is_valid_src(m: &Mac) -> bool {
    // Group bit set means multicast/broadcast; all-zero is unassigned.
    m[0] & 1 == 0 && *m != [0; 6]
}

fn ipv4_is_valid_src(a: &Ipv4) -> bool {
    // Not unspecified, broadcast, multicast (224/4) or loopback (127/8).
    *a != [0; 4] && *a != [255; 4] && (a[0] & 0xf0) != 0xe0 && a[0] != 127
}

fn get<const N: usize>(b: &[u8], at: usize) -> Option<[u8; N]> {
    let end = at.checked_add(N)?;
    b.get(at..end)?.try_into().ok()
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    get::<2>(b, at).map(u16::from_be_bytes)
}

/// One's-complement sum folded to 16 bits, over `data` plus an initial sum.
fn csum_add(mut sum: u32, data: &[u8]) -> u32 {
    let (pairs, rest) = data.as_chunks::<2>();
    for pair in pairs {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes(*pair)));
    }
    if let [last] = rest {
        sum = sum.wrapping_add(u32::from(*last) << 8);
    }
    sum
}

fn csum_fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff).wrapping_add(sum >> 16);
    }
    !(sum as u16)
}

fn udp_pseudo_sum(src: &Ipv4, dst: &Ipv4, udp_len: u16) -> u32 {
    let mut sum = csum_add(0, src);
    sum = csum_add(sum, dst);
    sum = sum.wrapping_add(u32::from(IPPROTO_UDP));
    sum.wrapping_add(u32::from(udp_len))
}

/// Outside NIC: ARP or IPv4/UDP.
pub fn parse_frame(b: &[u8]) -> Result<Frame<'_>, DropReason> {
    parse_eth(b, false)
}

/// Inside NIC: ARP or IPv4 of any protocol (as `Body::Ipv4`).
pub fn parse_frame_ip(b: &[u8]) -> Result<Frame<'_>, DropReason> {
    parse_eth(b, true)
}

fn parse_eth(b: &[u8], any_ip: bool) -> Result<Frame<'_>, DropReason> {
    if b.len() > MAX_FRAME {
        return Err(DropReason::TooLong);
    }
    let (Some(dst), Some(src), Some(ethertype)) = (get::<6>(b, 0), get::<6>(b, 6), be16(b, 12))
    else {
        return Err(DropReason::TooShort);
    };
    if !mac_is_valid_src(&src) {
        return Err(DropReason::EthBadSrc);
    }
    let eth = EthAddrs { src, dst };
    let rest = b.get(ETH_HDR..).ok_or(DropReason::TooShort)?;
    let body = match ethertype {
        ETHERTYPE_ARP => Body::Arp(parse_arp(rest)?),
        ETHERTYPE_IPV4 if any_ip => Body::Ipv4(parse_ipv4_packet(rest)?),
        ETHERTYPE_IPV4 => Body::Udp4(parse_ipv4_udp(rest)?),
        _ => return Err(DropReason::UnknownEtherType),
    };
    Ok(Frame { eth, body })
}

fn parse_arp(b: &[u8]) -> Result<ArpPacket, DropReason> {
    if b.len() < ARP_LEN {
        return Err(DropReason::TooShort);
    }
    let (Some(htype), Some(ptype), Some([hlen, plen]), Some(op)) =
        (be16(b, 0), be16(b, 2), get::<2>(b, 4), be16(b, 6))
    else {
        return Err(DropReason::TooShort);
    };
    let op = match op {
        1 => ArpOp::Request,
        2 => ArpOp::Reply,
        _ => return Err(DropReason::ArpMalformed),
    };
    if htype != 1 || ptype != ETHERTYPE_IPV4 || hlen != 6 || plen != 4 {
        return Err(DropReason::ArpMalformed);
    }
    let (Some(sha), Some(spa), Some(tha), Some(tpa)) =
        (get::<6>(b, 8), get::<4>(b, 14), get::<6>(b, 18), get::<4>(b, 24))
    else {
        return Err(DropReason::TooShort);
    };
    if !mac_is_valid_src(&sha) || !ipv4_is_valid_src(&spa) {
        return Err(DropReason::ArpBadSender);
    }
    Ok(ArpPacket { op, sha, spa, tha, tpa })
}

/// Validates an IPv4 header (no options, no fragments, checksum, sane
/// source) and returns the datagram trimmed to its total length. Also the
/// entry point for decrypted tunnel payloads.
pub fn parse_ipv4_packet(b: &[u8]) -> Result<Ip4Packet<'_>, DropReason> {
    let (hdr, packet) = ipv4_header(b)?;
    let (Some(src), Some(dst), Some([proto])) = (get::<4>(hdr, 12), get::<4>(hdr, 16), get::<1>(hdr, 9)) else {
        return Err(DropReason::TooShort);
    };
    Ok(Ip4Packet { src, dst, proto, packet })
}

/// Shared IPv4 checks; returns (header, datagram up to total_len).
fn ipv4_header(b: &[u8]) -> Result<(&[u8], &[u8]), DropReason> {
    let hdr = b.get(..IPV4_HDR).ok_or(DropReason::TooShort)?;
    let (Some([ver_ihl, _tos]), Some(total_len), Some(frag)) = (get::<2>(hdr, 0), be16(hdr, 2), be16(hdr, 6))
    else {
        return Err(DropReason::TooShort);
    };
    if ver_ihl >> 4 != 4 {
        return Err(DropReason::Ipv4Version);
    }
    if ver_ihl & 0x0f != 5 {
        return Err(DropReason::Ipv4Options);
    }
    // Reserved bit, MF, and fragment offset must all be zero; DF is allowed.
    if frag & 0xbfff != 0 {
        return Err(DropReason::Ipv4Fragment);
    }
    let total_len = usize::from(total_len);
    // Trailing bytes beyond total_len are Ethernet padding and are ignored.
    if total_len < IPV4_HDR || total_len > b.len() {
        return Err(DropReason::Ipv4BadLength);
    }
    if csum_fold(csum_add(0, hdr)) != 0 {
        return Err(DropReason::Ipv4BadChecksum);
    }
    let src = get::<4>(hdr, 12).ok_or(DropReason::TooShort)?;
    if !ipv4_is_valid_src(&src) {
        return Err(DropReason::Ipv4BadSrc);
    }
    Ok((hdr, b.get(..total_len).ok_or(DropReason::Ipv4BadLength)?))
}

fn parse_ipv4_udp(b: &[u8]) -> Result<Udp4<'_>, DropReason> {
    let Ip4Packet { src, dst, proto, packet } = parse_ipv4_packet(b)?;
    if proto != IPPROTO_UDP {
        return Err(DropReason::NotUdp);
    }
    let udp = packet.get(IPV4_HDR..).ok_or(DropReason::Ipv4BadLength)?;
    let (Some(sport), Some(dport), Some(udp_len), Some(udp_csum)) =
        (be16(udp, 0), be16(udp, 2), be16(udp, 4), be16(udp, 6))
    else {
        return Err(DropReason::UdpBadLength);
    };
    if usize::from(udp_len) != udp.len() || udp.len() < UDP_HDR {
        return Err(DropReason::UdpBadLength);
    }
    // A zero checksum means "not computed" in IPv4.
    if udp_csum != 0 && csum_fold(csum_add(udp_pseudo_sum(&src, &dst, udp_len), udp)) != 0 {
        return Err(DropReason::UdpBadChecksum);
    }
    let payload = udp.get(UDP_HDR..).ok_or(DropReason::UdpBadLength)?;
    Ok(Udp4 { src, dst, sport, dport, payload })
}

/// Writes `f` into `out` and returns the frame length. Checksums are computed.
pub fn emit(f: &Frame<'_>, out: &mut [u8]) -> Result<usize, EmitError> {
    if !mac_is_valid_src(&f.eth.src) {
        return Err(EmitError::Invalid);
    }
    let len = match &f.body {
        Body::Arp(a) => {
            if !mac_is_valid_src(&a.sha) || !ipv4_is_valid_src(&a.spa) {
                return Err(EmitError::Invalid);
            }
            ETH_HDR + ARP_LEN
        }
        Body::Udp4(u) => {
            if !ipv4_is_valid_src(&u.src) || u.payload.len() > MAX_UDP_PAYLOAD {
                return Err(EmitError::Invalid);
            }
            (ETH_HDR + IPV4_HDR + UDP_HDR).saturating_add(u.payload.len())
        }
        Body::Ipv4(p) => {
            // Emitted verbatim, so it must be exactly what the parser yields.
            if p.packet.len() > MAX_FRAME - ETH_HDR || parse_ipv4_packet(p.packet) != Ok(*p) {
                return Err(EmitError::Invalid);
            }
            ETH_HDR.saturating_add(p.packet.len())
        }
    };
    let out = out.get_mut(..len).ok_or(EmitError::TooSmall)?;
    let mut w = Writer { buf: out, at: 0 };
    w.put(&f.eth.dst);
    w.put(&f.eth.src);
    match &f.body {
        Body::Arp(a) => {
            w.put(&ETHERTYPE_ARP.to_be_bytes());
            w.put(&[0, 1, 0x08, 0x00, 6, 4]);
            let op: u16 = match a.op {
                ArpOp::Request => 1,
                ArpOp::Reply => 2,
            };
            w.put(&op.to_be_bytes());
            w.put(&a.sha);
            w.put(&a.spa);
            w.put(&a.tha);
            w.put(&a.tpa);
        }
        Body::Udp4(u) => {
            // Payload is bounded by MAX_UDP_PAYLOAD above, so these fit in u16.
            let udp_len = u16::try_from(UDP_HDR.saturating_add(u.payload.len()))
                .map_err(|_| EmitError::Invalid)?;
            let total_len = u16::try_from((IPV4_HDR + UDP_HDR).saturating_add(u.payload.len()))
                .map_err(|_| EmitError::Invalid)?;
            w.put(&ETHERTYPE_IPV4.to_be_bytes());
            let ip_start = w.at;
            w.put(&[0x45, 0]);
            w.put(&total_len.to_be_bytes());
            w.put(&[0, 0, 0x40, 0, 64, IPPROTO_UDP, 0, 0]);
            w.put(&u.src);
            w.put(&u.dst);
            let udp_start = w.at;
            w.put(&u.sport.to_be_bytes());
            w.put(&u.dport.to_be_bytes());
            w.put(&udp_len.to_be_bytes());
            w.put(&[0, 0]);
            w.put(u.payload);
            let ip_csum = csum_fold(csum_add(0, w.slice(ip_start, IPV4_HDR)));
            w.patch(ip_start.saturating_add(10), ip_csum);
            let mut udp_csum = csum_fold(csum_add(
                udp_pseudo_sum(&u.src, &u.dst, udp_len),
                w.slice(udp_start, usize::from(udp_len)),
            ));
            // An all-zero result is transmitted as 0xffff (RFC 768).
            if udp_csum == 0 {
                udp_csum = 0xffff;
            }
            w.patch(udp_start.saturating_add(6), udp_csum);
        }
        Body::Ipv4(p) => {
            w.put(&ETHERTYPE_IPV4.to_be_bytes());
            w.put(p.packet);
        }
    }
    Ok(len)
}

/// Sequential writer over a buffer whose size was checked by the caller;
/// out-of-range writes are silently ignored rather than panicking, and the
/// round-trip proof would catch any resulting corruption.
struct Writer<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn put(&mut self, data: &[u8]) {
        let end = self.at.saturating_add(data.len());
        if let Some(dst) = self.buf.get_mut(self.at..end) {
            dst.copy_from_slice(data);
        }
        self.at = end;
    }

    fn slice(&self, start: usize, len: usize) -> &[u8] {
        self.buf.get(start..start.saturating_add(len)).unwrap_or(&[])
    }

    fn patch(&mut self, at: usize, v: u16) {
        if let Some(dst) = self.buf.get_mut(at..at.saturating_add(2)) {
            dst.copy_from_slice(&v.to_be_bytes());
        }
    }
}

/// Property shared by the Kani harness and the bolero target: parsing never
/// panics, and anything accepted re-emits to an equal frame.
#[cfg(any(test, kani))]
pub fn check(bytes: &[u8]) {
    let mut out = [0u8; MAX_FRAME];
    let _ = check_into(bytes, &mut out);
    let _ = check_ip_into(bytes, &mut out);
}

/// `check` with a caller-supplied output buffer (the Kani harness uses a
/// small one to keep the problem tractable). Returns the parse result.
#[cfg(any(test, kani))]
#[allow(clippy::panic)]
pub fn check_into<'a>(bytes: &'a [u8], out: &mut [u8]) -> Result<Frame<'a>, DropReason> {
    let r = parse_frame(bytes);
    if let Ok(f) = r {
        match emit(&f, out) {
            Ok(n) => assert!(out.get(..n).map(parse_frame) == Some(Ok(f))),
            Err(_) => panic!("accepted frames must be emittable"),
        }
    }
    r
}

/// `check_into` for the inside-NIC parser.
#[cfg(any(test, kani))]
#[allow(clippy::panic)]
pub fn check_ip_into<'a>(bytes: &'a [u8], out: &mut [u8]) -> Result<Frame<'a>, DropReason> {
    let r = parse_frame_ip(bytes);
    if let Ok(f) = r {
        match emit(&f, out) {
            Ok(n) => assert!(out.get(..n).map(parse_frame_ip) == Some(Ok(f))),
            Err(_) => panic!("accepted frames must be emittable"),
        }
    }
    r
}

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests;
