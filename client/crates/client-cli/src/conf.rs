//! `/etc/kozane/client.conf` (M9 plan C10): one `key = value` per line,
//! `#` comment lines and blank lines, parsed in-tree. Every key is
//! required, once; an unknown key, a repeat or a bad value refuses the
//! whole file, in both binaries.

use std::net::{IpAddr, SocketAddr};

use crate::b64;

pub const PATH: &str = "/etc/kozane/client.conf";
/// A bound on the file, checked before parsing.
pub const MAX_LEN: u64 = 16 * 1024;
const IFNAMSIZ: usize = 16;

/// An address with a prefix length, `ip/len`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub len: u8,
}

impl Cidr {
    fn max_len(addr: &IpAddr) -> u8 {
        if addr.is_ipv4() { 32 } else { 128 }
    }

    /// `addr` with every bit past `len` cleared.
    pub fn network(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(a) => {
                let mask = u32::MAX.checked_shl(32u32.saturating_sub(u32::from(self.len))).unwrap_or(0);
                IpAddr::V4((u32::from(a) & mask).into())
            }
            IpAddr::V6(a) => {
                let mask = u128::MAX.checked_shl(128u32.saturating_sub(u32::from(self.len))).unwrap_or(0);
                IpAddr::V6((u128::from(a) & mask).into())
            }
        }
    }

    fn parse(s: &str) -> Result<Self, String> {
        let (a, l) = s.split_once('/').ok_or_else(|| format!("{s:?}: want ip/len"))?;
        let addr: IpAddr = a.parse().map_err(|_| format!("{s:?}: bad address"))?;
        // Digits only: `u8::from_str` would also take a leading `+`.
        if l.is_empty() || !l.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("{s:?}: bad prefix length"));
        }
        let len: u8 = l.parse().map_err(|_| format!("{s:?}: bad prefix length"))?;
        if len > Self::max_len(&addr) {
            return Err(format!("{s:?}: prefix length too long"));
        }
        Ok(Self { addr, len })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conf {
    /// The WireGuard interface `kzc-psk` creates.
    pub interface: String,
    /// The interface's own address.
    pub address: Cidr,
    pub wg_listen_port: u16,
    /// The gateway's WireGuard endpoint.
    pub wg_endpoint: SocketAddr,
    /// `kzc`'s Rosenpass UDP port.
    pub rp_listen_port: u16,
    /// The gateway's Rosenpass endpoint.
    pub rp_endpoint: SocketAddr,
    pub gw_wg_pub: [u8; 32],
    /// The gateway's pinned McEliece key, a raw `SPK_LEN` file.
    pub gw_rp_pub_path: String,
    /// The prefixes routed to the gateway peer.
    pub allowed_ips: Vec<Cidr>,
}

const KEYS: [&str; 9] = [
    "interface",
    "address",
    "wg_listen_port",
    "wg_endpoint",
    "rp_listen_port",
    "rp_endpoint",
    "gw_wg_pub",
    "gw_rp_pub_path",
    "allowed_ips",
];

fn interface(v: &str) -> Result<String, String> {
    let ok = !v.is_empty()
        && v.len() < IFNAMSIZ
        && v != "."
        && v != ".."
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    if ok { Ok(v.to_string()) } else { Err(format!("interface: bad name {v:?}")) }
}

fn port(key: &str, v: &str) -> Result<u16, String> {
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{key}: bad port {v:?}"));
    }
    match v.parse::<u16>() {
        Ok(p) if p != 0 => Ok(p),
        _ => Err(format!("{key}: bad port {v:?}")),
    }
}

fn endpoint(key: &str, v: &str) -> Result<SocketAddr, String> {
    let a: SocketAddr = v.parse().map_err(|_| format!("{key}: want ip:port, got {v:?}"))?;
    if a.port() == 0 || a.ip().is_unspecified() {
        return Err(format!("{key}: bad endpoint {v:?}"));
    }
    Ok(a)
}

fn allowed_ips(v: &str) -> Result<Vec<Cidr>, String> {
    let mut out: Vec<Cidr> = Vec::new();
    for item in v.split(',') {
        let c = Cidr::parse(item.trim()).map_err(|e| format!("allowed_ips: {e}"))?;
        if c.network() != c.addr {
            return Err(format!("allowed_ips: {item:?} has host bits set"));
        }
        // A default route through the tunnel would carry the tunnel's own
        // packets; that needs policy routing, which kzc-psk does not set.
        if c.len == 0 {
            return Err(format!("allowed_ips: {item:?}: a default route is not supported"));
        }
        if out.contains(&c) {
            return Err(format!("allowed_ips: {item:?} repeated"));
        }
        out.push(c);
    }
    Ok(out)
}

fn path(v: &str) -> Result<String, String> {
    if !v.starts_with('/') || v.contains('\0') {
        return Err(format!("gw_rp_pub_path: want an absolute path, got {v:?}"));
    }
    Ok(v.to_string())
}

impl Conf {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut vals: [Option<&str>; KEYS.len()] = [None; KEYS.len()];
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let lineno = n.saturating_add(1);
            let (k, v) = line.split_once('=').ok_or_else(|| format!("line {lineno}: want key = value"))?;
            let (k, v) = (k.trim(), v.trim());
            let at = KEYS.iter().position(|&x| x == k).ok_or_else(|| format!("line {lineno}: unknown key {k:?}"))?;
            if v.is_empty() {
                return Err(format!("line {lineno}: {k}: empty value"));
            }
            let slot = vals.get_mut(at).ok_or("internal")?;
            if slot.replace(v).is_some() {
                return Err(format!("line {lineno}: {k}: repeated"));
            }
        }
        let get = |k: &str| -> Result<&str, String> {
            KEYS.iter().position(|&x| x == k).and_then(|i| vals.get(i).copied().flatten()).ok_or(format!("{k}: missing"))
        };
        let address = Cidr::parse(get("address")?).map_err(|e| format!("address: {e}"))?;
        if address.addr.is_unspecified() || address.len == 0 {
            return Err("address: want a host address".into());
        }
        Ok(Self {
            interface: interface(get("interface")?)?,
            address,
            wg_listen_port: port("wg_listen_port", get("wg_listen_port")?)?,
            wg_endpoint: endpoint("wg_endpoint", get("wg_endpoint")?)?,
            rp_listen_port: port("rp_listen_port", get("rp_listen_port")?)?,
            rp_endpoint: endpoint("rp_endpoint", get("rp_endpoint")?)?,
            gw_wg_pub: b64::decode32(get("gw_wg_pub")?).ok_or("gw_wg_pub: want a base64 32-byte key")?,
            gw_rp_pub_path: path(get("gw_rp_pub_path")?)?,
            allowed_ips: allowed_ips(get("allowed_ips")?)?,
        })
    }
}
