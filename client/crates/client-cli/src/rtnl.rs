//! rtnetlink requests for the one interface `kzc-psk` owns: create, mark,
//! bring up, address, routes, delete. Layouts from `linux/rtnetlink.h`,
//! `linux/if_link.h` and `linux/if_addr.h`.

use std::net::IpAddr;

use crate::conf::Cidr;
use crate::netlink::{self, Msg, NLM_F_CREATE, NLM_F_EXCL};

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_NEWROUTE: u16 = 24;

pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_LINKINFO: u16 = 18;
pub const IFLA_IFALIAS: u16 = 20;
pub const IFLA_INFO_KIND: u16 = 1;
pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const RTA_DST: u16 = 1;
pub const RTA_OIF: u16 = 4;

pub const IFF_UP: u32 = 0x1;
const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RTN_UNICAST: u8 = 1;

/// The mark on an interface `kzc-psk` created (`IFLA_IFALIAS`).
pub const MARK: &str = "kozane-psk";
pub const KIND: &str = "wireguard";

pub fn family(addr: &IpAddr) -> u8 {
    if addr.is_ipv4() { AF_INET } else { AF_INET6 }
}

pub fn addr_bytes(addr: &IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// `struct ifinfomsg`: family u8, pad u8, type u16, index i32, flags u32,
/// change u32.
pub fn ifinfomsg(index: u32, flags: u32, change: u32) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0] = AF_UNSPEC;
    h[4..8].copy_from_slice(&index.to_ne_bytes());
    h[8..12].copy_from_slice(&flags.to_ne_bytes());
    h[12..16].copy_from_slice(&change.to_ne_bytes());
    h
}

/// The link named `name` (an ENODEV reply means there is none).
pub fn get_link(name: &str) -> Msg {
    let mut m = Msg::new(RTM_GETLINK, 0);
    m.header(&ifinfomsg(0, 0, 0)).str(IFLA_IFNAME, name);
    m
}

/// A new WireGuard link `name`; `NLM_F_EXCL`, so an existing one fails.
pub fn new_wireguard(name: &str) -> Msg {
    let mut m = Msg::new(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL);
    m.header(&ifinfomsg(0, 0, 0)).str(IFLA_IFNAME, name).nest(IFLA_LINKINFO).str(IFLA_INFO_KIND, KIND).end();
    m
}

/// Sets the mark. The kernel ignores `IFLA_IFALIAS` in a creating
/// `RTM_NEWLINK`, so the mark is its own request.
pub fn set_mark(index: u32) -> Msg {
    let mut m = Msg::new(RTM_NEWLINK, 0);
    m.header(&ifinfomsg(index, 0, 0)).str(IFLA_IFALIAS, MARK);
    m
}

pub fn set_up(index: u32) -> Msg {
    let mut m = Msg::new(RTM_NEWLINK, 0);
    m.header(&ifinfomsg(index, IFF_UP, IFF_UP));
    m
}

pub fn del_link(index: u32) -> Msg {
    let mut m = Msg::new(RTM_DELLINK, 0);
    m.header(&ifinfomsg(index, 0, 0));
    m
}

pub fn del_link_name(name: &str) -> Msg {
    let mut m = Msg::new(RTM_DELLINK, 0);
    m.header(&ifinfomsg(0, 0, 0)).str(IFLA_IFNAME, name);
    m
}

/// `struct ifaddrmsg`: family, prefixlen, flags, scope (u8 each), index
/// u32.
pub fn new_addr(index: u32, a: &Cidr) -> Msg {
    let mut h = [0u8; 8];
    h[0] = family(&a.addr);
    h[1] = a.len;
    h[3] = RT_SCOPE_UNIVERSE;
    h[4..8].copy_from_slice(&index.to_ne_bytes());
    let bytes = addr_bytes(&a.addr);
    let mut m = Msg::new(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL);
    m.header(&h).attr(IFA_LOCAL, &bytes).attr(IFA_ADDRESS, &bytes);
    m
}

/// `struct rtmsg`: family, dst_len, src_len, tos, table, protocol, scope,
/// type (u8 each), flags u32. A link-scope unicast route in the main
/// table, `NLM_F_EXCL`, so another route to the prefix is never replaced.
pub fn new_route(index: u32, dst: &Cidr) -> Msg {
    let h = [family(&dst.addr), dst.len, 0, 0, RT_TABLE_MAIN, RTPROT_BOOT, RT_SCOPE_LINK, RTN_UNICAST, 0, 0, 0, 0];
    let mut m = Msg::new(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL);
    m.header(&h).attr(RTA_DST, &addr_bytes(&dst.addr)).u32(RTA_OIF, index);
    m
}

/// What `kzc-psk` needs from an `RTM_NEWLINK` reply.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub alias: Option<String>,
    pub kind: Option<String>,
}

fn c_string(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(b.get(..end).unwrap_or(&[])).into_owned()
}

/// Parses a link message's payload (`ifinfomsg` and attributes).
pub fn parse_link(payload: &[u8]) -> Option<Link> {
    let index = netlink::u32_at(payload, 4)?;
    let mut link = Link { index, ..Link::default() };
    for (ty, v) in netlink::attrs(payload.get(16..)?) {
        match ty {
            IFLA_IFNAME => link.name = c_string(v),
            IFLA_IFALIAS => link.alias = Some(c_string(v)),
            IFLA_LINKINFO => {
                link.kind = netlink::attrs(v).find(|(t, _)| *t == IFLA_INFO_KIND).map(|(_, k)| c_string(k));
            }
            _ => {}
        }
    }
    Some(link)
}
