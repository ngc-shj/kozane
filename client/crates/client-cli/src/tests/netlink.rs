//! Byte layouts against the kernel uapi headers (`linux/netlink.h`,
//! `linux/rtnetlink.h`, `linux/if_link.h`, `linux/if_addr.h`,
//! `linux/genetlink.h`, `linux/wireguard.h`), written out by hand, and the
//! reply checks. The real kernel is the integration test's oracle.

use crate::conf::Cidr;
use crate::netlink::{Msg, NlError, attrs, parse_reply};
use crate::{rtnl, wg};

fn le16(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}

/// `nlmsghdr` for these tests: seq 7, pid 9.
fn hdr(len: u16, ty: u16, flags: u16) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&le16(len));
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(&le16(ty));
    v.extend_from_slice(&le16(flags));
    v.extend_from_slice(&[7, 0, 0, 0, 9, 0, 0, 0]);
    v
}

fn bytes(mut m: Msg) -> Vec<u8> {
    m.finish(7, 9).unwrap().to_vec()
}

#[test]
fn get_link_layout() {
    let mut want = hdr(40, 18, 0x5); // RTM_GETLINK, REQUEST|ACK
    want.extend_from_slice(&[0; 16]); // ifinfomsg
    want.extend_from_slice(&[8, 0, 3, 0, b'k', b'z', b'0', 0]); // IFLA_IFNAME
    assert_eq!(bytes(rtnl::get_link("kz0")), want);
}

#[test]
fn new_wireguard_link_layout() {
    // RTM_NEWLINK, REQUEST|ACK|EXCL|CREATE
    let mut want = hdr(60, 16, 0x605);
    want.extend_from_slice(&[0; 16]);
    want.extend_from_slice(&[8, 0, 3, 0, b'k', b'z', b'0', 0]);
    // IFLA_LINKINFO | NLA_F_NESTED, holding IFLA_INFO_KIND "wireguard\0"
    want.extend_from_slice(&[20, 0, 18, 0x80, 14, 0, 1, 0]);
    want.extend_from_slice(b"wireguard\0\0\0");
    assert_eq!(bytes(rtnl::new_wireguard("kz0")), want);
}

#[test]
fn mark_up_and_delete_layouts() {
    // IFLA_IFALIAS "kozane-psk\0" on index 5.
    let mut want = hdr(48, 16, 0x5);
    want.extend_from_slice(&[0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    want.extend_from_slice(&[15, 0, 20, 0]);
    want.extend_from_slice(b"kozane-psk\0\0");
    assert_eq!(bytes(rtnl::set_mark(5)), want);
    // ifi_flags = ifi_change = IFF_UP.
    let mut want = hdr(32, 16, 0x5);
    want.extend_from_slice(&[0, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]);
    assert_eq!(bytes(rtnl::set_up(5)), want);
    let mut want = hdr(32, 17, 0x5); // RTM_DELLINK
    want.extend_from_slice(&[0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(bytes(rtnl::del_link(5)), want);
}

#[test]
fn address_and_route_layouts() {
    let a = Cidr { addr: "10.1.0.2".parse().unwrap(), len: 24 };
    let mut want = hdr(40, 20, 0x605); // RTM_NEWADDR
    want.extend_from_slice(&[2, 24, 0, 0, 5, 0, 0, 0]); // ifaddrmsg: AF_INET /24
    want.extend_from_slice(&[8, 0, 2, 0, 10, 1, 0, 2]); // IFA_LOCAL
    want.extend_from_slice(&[8, 0, 1, 0, 10, 1, 0, 2]); // IFA_ADDRESS
    assert_eq!(bytes(rtnl::new_addr(5, &a)), want);

    let r = Cidr { addr: "fd00::".parse().unwrap(), len: 64 };
    let mut want = hdr(56, 24, 0x605); // RTM_NEWROUTE
    // rtmsg: AF_INET6, /64, src 0, tos 0, RT_TABLE_MAIN, RTPROT_BOOT,
    // RT_SCOPE_LINK, RTN_UNICAST, flags 0.
    want.extend_from_slice(&[10, 64, 0, 0, 254, 3, 253, 1, 0, 0, 0, 0]);
    want.extend_from_slice(&[20, 0, 1, 0, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // RTA_DST
    want.extend_from_slice(&[8, 0, 4, 0, 5, 0, 0, 0]); // RTA_OIF
    assert_eq!(bytes(rtnl::new_route(5, &r)), want);
}

#[test]
fn get_family_layout() {
    let mut want = hdr(36, 0x10, 0x5); // GENL_ID_CTRL
    want.extend_from_slice(&[3, 1, 0, 0]); // CTRL_CMD_GETFAMILY
    want.extend_from_slice(&[14, 0, 2, 0]); // CTRL_ATTR_FAMILY_NAME
    want.extend_from_slice(b"wireguard\0\0\0");
    assert_eq!(bytes(wg::get_family()), want);
}

fn key(b: u8) -> [u8; 32] {
    [b; 32]
}

#[test]
fn remove_peer_layout() {
    let mut want = hdr(80, 30, 0x5); // the wireguard family id, 30 here
    want.extend_from_slice(&[1, 1, 0, 0]); // WG_CMD_SET_DEVICE, version 1
    want.extend_from_slice(&[8, 0, 1, 0, 5, 0, 0, 0]); // WGDEVICE_A_IFINDEX
    want.extend_from_slice(&[52, 0, 8, 0x80]); // WGDEVICE_A_PEERS | NESTED
    want.extend_from_slice(&[48, 0, 0, 0x80]); // peer 0 | NESTED
    want.extend_from_slice(&[36, 0, 1, 0]); // WGPEER_A_PUBLIC_KEY
    want.extend_from_slice(&key(0xaa));
    want.extend_from_slice(&[8, 0, 3, 0, 1, 0, 0, 0]); // WGPEER_A_FLAGS: REMOVE_ME
    assert_eq!(bytes(wg::remove_peer(30, 5, &key(0xaa))), want);
}

#[test]
fn set_psk_layout() {
    let mut want = hdr(116, 30, 0x5);
    want.extend_from_slice(&[1, 1, 0, 0]);
    want.extend_from_slice(&[8, 0, 1, 0, 5, 0, 0, 0]);
    want.extend_from_slice(&[88, 0, 8, 0x80, 84, 0, 0, 0x80]);
    want.extend_from_slice(&[36, 0, 1, 0]);
    want.extend_from_slice(&key(0xaa));
    want.extend_from_slice(&[36, 0, 2, 0]); // WGPEER_A_PRESHARED_KEY
    want.extend_from_slice(&key(0x55));
    want.extend_from_slice(&[8, 0, 3, 0, 4, 0, 0, 0]); // WGPEER_F_UPDATE_ONLY
    assert_eq!(bytes(wg::set_psk(30, 5, &key(0xaa), &key(0x55))), want);
}

#[test]
fn configure_layout() {
    let ep = "192.0.2.1:51820".parse().unwrap();
    let ips = [Cidr { addr: "10.2.0.0".parse().unwrap(), len: 24 }];
    let peer = wg::Peer { public: &key(0xaa), endpoint: &ep, allowed_ips: &ips };
    let mut want = hdr(204, 30, 0x5);
    want.extend_from_slice(&[1, 1, 0, 0]);
    want.extend_from_slice(&[8, 0, 1, 0, 5, 0, 0, 0]);
    want.extend_from_slice(&[36, 0, 3, 0]); // WGDEVICE_A_PRIVATE_KEY
    want.extend_from_slice(&key(0x11));
    want.extend_from_slice(&[6, 0, 6, 0, 0x6d, 0xca, 0, 0]); // WGDEVICE_A_LISTEN_PORT 51821
    want.extend_from_slice(&[132, 0, 8, 0x80, 128, 0, 0, 0x80]);
    want.extend_from_slice(&[36, 0, 1, 0]);
    want.extend_from_slice(&key(0xaa));
    want.extend_from_slice(&[36, 0, 2, 0]);
    want.extend_from_slice(&key(0x55));
    // WGPEER_A_ENDPOINT: sockaddr_in, AF_INET, port 51820 big-endian.
    want.extend_from_slice(&[20, 0, 4, 0, 2, 0, 0xca, 0x6c, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
    want.extend_from_slice(&[32, 0, 9, 0x80, 28, 0, 0, 0x80]); // WGPEER_A_ALLOWEDIPS, entry 0
    want.extend_from_slice(&[6, 0, 1, 0, 2, 0, 0, 0]); // WGALLOWEDIP_A_FAMILY
    want.extend_from_slice(&[8, 0, 2, 0, 10, 2, 0, 0]); // WGALLOWEDIP_A_IPADDR
    want.extend_from_slice(&[5, 0, 3, 0, 24, 0, 0, 0]); // WGALLOWEDIP_A_CIDR_MASK
    assert_eq!(bytes(wg::configure(30, 5, &key(0x11), 51821, &peer, &key(0x55))), want);
}

#[test]
fn ipv6_endpoint_is_sockaddr_in6() {
    let ep: std::net::SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
    let mut want = vec![10, 0, 0xca, 0x6c, 0, 0, 0, 0];
    want.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    want.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(wg::sockaddr(&ep), want);
}

#[test]
fn no_request_carries_device_flags() {
    // WGDEVICE_A_FLAGS (5) is the only way to replace the peer list.
    let ep = "192.0.2.1:51820".parse().unwrap();
    let peer = wg::Peer { public: &key(1), endpoint: &ep, allowed_ips: &[] };
    for m in [
        wg::configure(30, 5, &key(2), 1, &peer, &key(3)),
        wg::set_psk(30, 5, &key(1), &key(3)),
        wg::remove_peer(30, 5, &key(1)),
        wg::add_peer(30, 5, &peer, &key(3)),
    ] {
        let b = bytes(m);
        assert!(attrs(&b[20..]).all(|(t, _)| t != 5));
    }
}

#[test]
fn an_unterminated_nest_is_refused() {
    let mut m = Msg::new(16, 0);
    m.nest(1);
    assert_eq!(m.finish(1, 1).unwrap_err(), NlError::TooLong);
    let mut m = Msg::new(16, 0);
    m.attr(1, &vec![0; 70000]);
    assert_eq!(m.finish(1, 1).unwrap_err(), NlError::TooLong);
}

/// An `NLMSG_ERROR` for request `seq` on `pid` with `errno`.
fn ack(seq: u32, pid: u32, errno: i32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&36u32.to_ne_bytes());
    v.extend_from_slice(&2u16.to_ne_bytes());
    v.extend_from_slice(&0x100u16.to_ne_bytes()); // NLM_F_CAPPED
    v.extend_from_slice(&seq.to_ne_bytes());
    v.extend_from_slice(&pid.to_ne_bytes());
    v.extend_from_slice(&(-errno).to_ne_bytes());
    v.extend_from_slice(&[0; 16]);
    v
}

fn data(seq: u32, pid: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&u32::try_from(16 + payload.len()).unwrap().to_ne_bytes());
    v.extend_from_slice(&16u16.to_ne_bytes());
    v.extend_from_slice(&0u16.to_ne_bytes());
    v.extend_from_slice(&seq.to_ne_bytes());
    v.extend_from_slice(&pid.to_ne_bytes());
    v.extend_from_slice(payload);
    v
}

#[test]
fn a_zero_errno_is_the_ack() {
    let r = parse_reply(&ack(3, 77, 0), 3, 77).unwrap();
    assert!(r.acked && r.data.is_empty());
}

#[test]
fn data_then_ack_in_one_datagram() {
    let mut b = data(3, 77, &[1, 2, 3, 4]);
    b.extend_from_slice(&ack(3, 77, 0));
    let r = parse_reply(&b, 3, 77).unwrap();
    assert!(r.acked);
    assert_eq!(r.data, vec![vec![1, 2, 3, 4]]);
}

#[test]
fn an_errno_is_an_error() {
    assert_eq!(parse_reply(&ack(3, 77, libc::ENODEV), 3, 77), Err(NlError::Errno(libc::ENODEV)), "kzc-psk: scrub unconfirmed");
}

#[test]
fn another_sequence_or_port_is_an_error() {
    assert_eq!(parse_reply(&ack(4, 77, 0), 3, 77), Err(NlError::Seq { got: 4, want: 3 }));
    assert_eq!(parse_reply(&ack(3, 78, 0), 3, 77), Err(NlError::Port { got: 78, want: 77 }));
}

#[test]
fn a_short_or_trailing_reply_is_malformed() {
    let a = ack(3, 77, 0);
    assert_eq!(parse_reply(&a[..20], 3, 77), Err(NlError::Malformed));
    assert_eq!(parse_reply(&a[..10], 3, 77), Err(NlError::Malformed));
    let mut two = a.clone();
    two.extend_from_slice(&a);
    assert_eq!(parse_reply(&two, 3, 77), Err(NlError::Malformed));
}

#[test]
fn parses_a_link_reply() {
    let mut m = Msg::new(16, 0);
    m.header(&rtnl::ifinfomsg(12, 0, 0))
        .str(rtnl::IFLA_IFNAME, "kz0")
        .str(rtnl::IFLA_IFALIAS, rtnl::MARK)
        .nest(rtnl::IFLA_LINKINFO)
        .str(rtnl::IFLA_INFO_KIND, "wireguard")
        .end();
    let b = m.finish(0, 0).unwrap().to_vec();
    let l = rtnl::parse_link(&b[16..]).unwrap();
    assert_eq!(l, rtnl::Link { index: 12, name: "kz0".into(), alias: Some("kozane-psk".into()), kind: Some("wireguard".into()) });
}

#[test]
fn a_message_that_outgrows_its_first_buffer_keeps_every_attribute() {
    // Past the first 256-byte allocation the buffer is replaced (the old one
    // wiped), not grown in place: the encoding must come out the same.
    let mut m = Msg::new(16, 0);
    let mut want = Vec::new();
    for i in 0..40u8 {
        m.attr(1, &[i; 13]);
        want.extend_from_slice(&le16(17));
        want.extend_from_slice(&le16(1));
        want.extend_from_slice(&[i; 13]);
        want.extend_from_slice(&[0; 3]);
    }
    let got = bytes(m);
    assert!(got.len() > 256);
    assert_eq!(&got[16..], &want[..]);
}
