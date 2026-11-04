//! Generic netlink for WireGuard: the family lookup
//! (`CTRL_CMD_GETFAMILY`, `linux/genetlink.h`) and `WG_CMD_SET_DEVICE`
//! (`linux/wireguard.h`). Only the private key, the listen port and the one
//! peer are ever set; the device flags attribute is never sent, so no
//! request replaces the peer list (D6).

use std::net::SocketAddr;

use crate::conf::Cidr;
use crate::netlink::{self, Msg};
use crate::rtnl::{addr_bytes, family};

pub const GENL_ID_CTRL: u16 = 0x10;
pub const CTRL_CMD_GETFAMILY: u8 = 3;
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;

pub const WG_GENL_NAME: &str = "wireguard";
pub const WG_GENL_VERSION: u8 = 1;
pub const WG_CMD_SET_DEVICE: u8 = 1;

pub const WGDEVICE_A_IFINDEX: u16 = 1;
pub const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
pub const WGDEVICE_A_LISTEN_PORT: u16 = 6;
pub const WGDEVICE_A_PEERS: u16 = 8;

pub const WGPEER_A_PUBLIC_KEY: u16 = 1;
pub const WGPEER_A_PRESHARED_KEY: u16 = 2;
pub const WGPEER_A_FLAGS: u16 = 3;
pub const WGPEER_A_ENDPOINT: u16 = 4;
pub const WGPEER_A_ALLOWEDIPS: u16 = 9;

pub const WGPEER_F_REMOVE_ME: u32 = 1 << 0;
pub const WGPEER_F_UPDATE_ONLY: u32 = 1 << 2;

pub const WGALLOWEDIP_A_FAMILY: u16 = 1;
pub const WGALLOWEDIP_A_IPADDR: u16 = 2;
pub const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

/// `struct genlmsghdr`: cmd u8, version u8, reserved u16.
fn genl(family: u16, cmd: u8, version: u8) -> Msg {
    let mut m = Msg::new(family, 0);
    m.header(&[cmd, version, 0, 0]);
    m
}

pub fn get_family() -> Msg {
    let mut m = genl(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1);
    m.str(CTRL_ATTR_FAMILY_NAME, WG_GENL_NAME);
    m
}

/// The family id from a `CTRL_CMD_GETFAMILY` reply payload.
pub fn parse_family(payload: &[u8]) -> Option<u16> {
    netlink::attrs(payload.get(4..)?)
        .find(|(t, _)| *t == CTRL_ATTR_FAMILY_ID)
        .and_then(|(_, v)| Some(u16::from_ne_bytes(v.try_into().ok()?)))
}

/// `struct sockaddr_in` / `sockaddr_in6`, as `WGPEER_A_ENDPOINT` takes
/// it: family in host order, port and address in network order.
pub fn sockaddr(a: &SocketAddr) -> Vec<u8> {
    let mut v = Vec::with_capacity(28);
    v.extend_from_slice(&u16::from(family(&a.ip())).to_ne_bytes());
    v.extend_from_slice(&a.port().to_be_bytes());
    match a {
        SocketAddr::V4(a) => {
            v.extend_from_slice(&a.ip().octets());
            v.extend_from_slice(&[0; 8]);
        }
        SocketAddr::V6(a) => {
            v.extend_from_slice(&a.flowinfo().to_be_bytes());
            v.extend_from_slice(&a.ip().octets());
            v.extend_from_slice(&a.scope_id().to_ne_bytes());
        }
    }
    v
}

/// The gateway peer as `kzc-psk` adds it: key, PSK, endpoint, allowed IPs.
pub struct Peer<'a> {
    pub public: &'a [u8; 32],
    pub endpoint: &'a SocketAddr,
    pub allowed_ips: &'a [Cidr],
}

fn put_peer(m: &mut Msg, p: &Peer<'_>, psk: &[u8; 32]) {
    m.nest(0).attr(WGPEER_A_PUBLIC_KEY, p.public).attr(WGPEER_A_PRESHARED_KEY, psk);
    m.attr(WGPEER_A_ENDPOINT, &sockaddr(p.endpoint)).nest(WGPEER_A_ALLOWEDIPS);
    for c in p.allowed_ips {
        m.nest(0)
            .u16(WGALLOWEDIP_A_FAMILY, u16::from(family(&c.addr)))
            .attr(WGALLOWEDIP_A_IPADDR, &addr_bytes(&c.addr))
            .u8(WGALLOWEDIP_A_CIDR_MASK, c.len)
            .end();
    }
    m.end().end();
}

/// The device's first configuration: private key, listen port, and the
/// peer, created with its PSK in this same request, so it never exists
/// without one (S4.4).
pub fn configure(fam: u16, index: u32, private: &[u8; 32], port: u16, peer: &Peer<'_>, psk: &[u8; 32]) -> Msg {
    let mut m = genl(fam, WG_CMD_SET_DEVICE, WG_GENL_VERSION);
    m.u32(WGDEVICE_A_IFINDEX, index).attr(WGDEVICE_A_PRIVATE_KEY, private).u16(WGDEVICE_A_LISTEN_PORT, port);
    m.nest(WGDEVICE_A_PEERS);
    put_peer(&mut m, peer, psk);
    m.end();
    m
}

/// A new PSK on the existing peer (`WGPEER_F_UPDATE_ONLY`: never creates
/// one).
pub fn set_psk(fam: u16, index: u32, public: &[u8; 32], psk: &[u8; 32]) -> Msg {
    let mut m = genl(fam, WG_CMD_SET_DEVICE, WG_GENL_VERSION);
    m.u32(WGDEVICE_A_IFINDEX, index).nest(WGDEVICE_A_PEERS).nest(0);
    m.attr(WGPEER_A_PUBLIC_KEY, public).attr(WGPEER_A_PRESHARED_KEY, psk).u32(WGPEER_A_FLAGS, WGPEER_F_UPDATE_ONLY);
    m.end().end();
    m
}

/// Removes the peer, and with it every live keypair (S1.11).
pub fn remove_peer(fam: u16, index: u32, public: &[u8; 32]) -> Msg {
    let mut m = genl(fam, WG_CMD_SET_DEVICE, WG_GENL_VERSION);
    m.u32(WGDEVICE_A_IFINDEX, index).nest(WGDEVICE_A_PEERS).nest(0);
    m.attr(WGPEER_A_PUBLIC_KEY, public).u32(WGPEER_A_FLAGS, WGPEER_F_REMOVE_ME);
    m.end().end();
    m
}

/// Re-adds the removed peer with a fresh PSK.
pub fn add_peer(fam: u16, index: u32, peer: &Peer<'_>, psk: &[u8; 32]) -> Msg {
    let mut m = genl(fam, WG_CMD_SET_DEVICE, WG_GENL_VERSION);
    m.u32(WGDEVICE_A_IFINDEX, index).nest(WGDEVICE_A_PEERS);
    put_peer(&mut m, peer, psk);
    m.end();
    m
}
