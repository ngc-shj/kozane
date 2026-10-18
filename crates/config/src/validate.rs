// Shared by build.rs (via `include!`) and the crate's tests, so the checks
// that reject a configuration at build time are unit-tested directly.
// Plain std; never compiled into a PD.

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    pub gateway: RawGateway,
    #[serde(default)]
    pub neighbors: Vec<RawNeighbor>,
    pub peers: Vec<RawPeer>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawGateway {
    pub public_key: String,
    pub listen_port: u16,
    pub outside_ip: String,
    pub outside_mac: String,
    pub outside_router_mac: String,
    pub inside_ip: String,
    pub inside_mac: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawNeighbor {
    pub ip: String,
    pub mac: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPeer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefix {
    pub addr: [u8; 4],
    pub len: u8,
}

impl Prefix {
    fn range(&self) -> (u32, u32) {
        let a = u32::from_be_bytes(self.addr);
        let mask = if self.len == 0 { 0 } else { u32::MAX << (32 - u32::from(self.len)) };
        let lo = a & mask;
        (lo, lo | !mask)
    }
}

#[derive(Debug)]
pub struct Checked {
    pub gateway_public: [u8; 32],
    pub listen_port: u16,
    pub outside_ip: [u8; 4],
    pub outside_mac: [u8; 6],
    pub outside_router_mac: [u8; 6],
    pub inside_ip: [u8; 4],
    pub inside_mac: [u8; 6],
    pub neighbors: Vec<([u8; 4], [u8; 6])>,
    pub peers: Vec<([u8; 32], Vec<Prefix>)>,
}

pub fn decode_key(s: &str) -> Result<[u8; 32], String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if s.len() != 44 || !s.ends_with('=') {
        return Err(format!("key {s:?}: expected 44 base64 characters for 32 bytes"));
    }
    let mut bits: u32 = 0;
    let mut n = 0;
    let mut out = Vec::with_capacity(32);
    for c in s.trim_end_matches('=').bytes() {
        let v = ALPHABET.iter().position(|a| *a == c).ok_or_else(|| format!("key {s:?}: not base64"))?;
        bits = (bits << 6) | v as u32;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    out.try_into().map_err(|_| format!("key {s:?}: does not decode to 32 bytes"))
}

pub fn parse_ip(s: &str) -> Result<[u8; 4], String> {
    let a: std::net::Ipv4Addr = s.parse().map_err(|_| format!("bad IPv4 address {s:?}"))?;
    Ok(a.octets())
}

pub fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("bad MAC {s:?}"));
    }
    let mut out = [0u8; 6];
    for (o, p) in out.iter_mut().zip(parts) {
        *o = u8::from_str_radix(p, 16).map_err(|_| format!("bad MAC {s:?}"))?;
    }
    if out[0] & 1 != 0 || out == [0; 6] {
        return Err(format!("MAC {s:?} must be a unicast, non-zero address"));
    }
    Ok(out)
}

pub fn parse_prefix(s: &str) -> Result<Prefix, String> {
    let (ip, len) = s.split_once('/').ok_or_else(|| format!("allowed IP {s:?} needs /len"))?;
    let len: u8 = len.parse().map_err(|_| format!("bad prefix length in {s:?}"))?;
    if len > 32 {
        return Err(format!("bad prefix length in {s:?}"));
    }
    let p = Prefix { addr: parse_ip(ip)?, len };
    if p.range().0 != u32::from_be_bytes(p.addr) {
        return Err(format!("allowed IP {s:?} has host bits set"));
    }
    Ok(p)
}

/// Validates a configuration; `max_peers` comes from the secrets format.
pub fn check(text: &str, max_peers: usize) -> Result<Checked, String> {
    let raw: RawConfig = toml::from_str(text).map_err(|e| format!("config: {e}"))?;
    let g = &raw.gateway;
    if raw.peers.is_empty() || raw.peers.len() > max_peers {
        return Err(format!("config: need 1..={max_peers} peers, got {}", raw.peers.len()));
    }
    let mut peers = Vec::new();
    for p in &raw.peers {
        let key = decode_key(&p.public_key)?;
        if peers.iter().any(|(k, _)| *k == key) {
            return Err(format!("config: duplicate peer {}", p.public_key));
        }
        if p.allowed_ips.is_empty() {
            return Err(format!("config: peer {} has no allowed IPs", p.public_key));
        }
        let prefixes = p.allowed_ips.iter().map(|s| parse_prefix(s)).collect::<Result<Vec<_>, _>>()?;
        peers.push((key, prefixes));
    }
    // Cryptokey routing needs an unambiguous owner for every address.
    let all: Vec<(usize, &Prefix)> = peers.iter().enumerate().flat_map(|(i, (_, ps))| ps.iter().map(move |p| (i, p))).collect();
    for (i, (pi, a)) in all.iter().enumerate() {
        for (pj, b) in &all[i + 1..] {
            let (a0, a1) = a.range();
            let (b0, b1) = b.range();
            if a0 <= b1 && b0 <= a1 {
                return Err(format!("config: allowed IPs of peers {pi} and {pj} overlap"));
            }
        }
    }
    let gateway_public = decode_key(&g.public_key)?;
    if peers.iter().any(|(k, _)| *k == gateway_public) {
        return Err("config: a peer uses the gateway's own key".into());
    }
    let mut neighbors = Vec::new();
    for n in &raw.neighbors {
        let ip = parse_ip(&n.ip)?;
        if neighbors.iter().any(|(i, _)| *i == ip) {
            return Err(format!("config: duplicate neighbor {}", n.ip));
        }
        neighbors.push((ip, parse_mac(&n.mac)?));
    }
    if g.listen_port == 0 {
        return Err("config: listen_port must be non-zero".into());
    }
    Ok(Checked {
        gateway_public,
        listen_port: g.listen_port,
        outside_ip: parse_ip(&g.outside_ip)?,
        outside_mac: parse_mac(&g.outside_mac)?,
        outside_router_mac: parse_mac(&g.outside_router_mac)?,
        inside_ip: parse_ip(&g.inside_ip)?,
        inside_mac: parse_mac(&g.inside_mac)?,
        neighbors,
        peers,
    })
}

pub fn render(c: &Checked) -> String {
    let mut s = String::new();
    s += &format!("pub const GATEWAY_PUBLIC: [u8; 32] = {:?};\n", c.gateway_public);
    s += &format!("pub const LISTEN_PORT: u16 = {};\n", c.listen_port);
    s += &format!("pub const OUTSIDE_IP: [u8; 4] = {:?};\n", c.outside_ip);
    s += &format!("pub const OUTSIDE_MAC: [u8; 6] = {:?};\n", c.outside_mac);
    s += &format!("pub const OUTSIDE_ROUTER_MAC: [u8; 6] = {:?};\n", c.outside_router_mac);
    s += &format!("pub const INSIDE_IP: [u8; 4] = {:?};\n", c.inside_ip);
    s += &format!("pub const INSIDE_MAC: [u8; 6] = {:?};\n", c.inside_mac);
    s += "pub const NEIGHBORS: &[Neighbor] = &[\n";
    for (ip, mac) in &c.neighbors {
        s += &format!("    Neighbor {{ ip: {ip:?}, mac: {mac:?} }},\n");
    }
    s += "];\npub const PEERS: &[Peer] = &[\n";
    for (key, ps) in &c.peers {
        s += &format!("    Peer {{ public: {key:?}, allowed: &[");
        for p in ps {
            s += &format!("Prefix {{ addr: {:?}, len: {} }}, ", p.addr, p.len);
        }
        s += "] },\n";
    }
    s += "];\n";
    s
}
