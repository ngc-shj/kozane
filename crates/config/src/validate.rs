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
    /// Rosenpass arrives on its own port (M3 plan F20).
    pub rp_port: u16,
    /// The gateway's McEliece public key file (`spkm`), relative to this
    /// file, and its BLAKE2s-256 in hex.
    pub rp_pub_path: String,
    pub rp_hash: String,
    pub outside_ip: String,
    pub outside_mac: String,
    pub outside_router_mac: String,
    pub inside_ip: String,
    /// The inside network (with prefix length): the gateway and every
    /// neighbor lie in it, and no peer's allowed IPs may overlap it.
    pub inside_prefix: String,
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
    /// WireGuard static public key.
    pub wg_pub: String,
    /// The peer's McEliece public key file (`spkt`), relative to this file,
    /// and its BLAKE2s-256 in hex: one record binds both keys (M3 plan S8).
    pub rp_pub_path: String,
    pub rp_hash: String,
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

    fn contains(&self, ip: [u8; 4]) -> bool {
        let (lo, hi) = self.range();
        (lo..=hi).contains(&u32::from_be_bytes(ip))
    }
}

/// A McEliece public key read from its file and checked against its hash.
#[derive(Debug)]
pub struct RpKey {
    pub hash: [u8; 32],
    pub public: Vec<u8>,
}

#[derive(Debug)]
pub struct CheckedPeer {
    pub public: [u8; 32],
    pub allowed: Vec<Prefix>,
    pub rp: RpKey,
}

#[derive(Debug)]
pub struct Checked {
    pub gateway_public: [u8; 32],
    pub listen_port: u16,
    pub rp_port: u16,
    pub gateway_rp: RpKey,
    pub outside_ip: [u8; 4],
    pub outside_mac: [u8; 6],
    pub outside_router_mac: [u8; 6],
    pub inside_ip: [u8; 4],
    pub inside_mac: [u8; 6],
    pub neighbors: Vec<([u8; 4], [u8; 6])>,
    pub peers: Vec<CheckedPeer>,
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

/// A 32-byte hash written as 64 hex digits.
pub fn decode_hash(s: &str) -> Result<[u8; 32], String> {
    let bad = || format!("hash {s:?}: expected 64 hex digits");
    if s.len() != 64 || !s.is_ascii() {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (o, i) in out.iter_mut().zip((0..64).step_by(2)) {
        *o = u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

pub fn encode_hash(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// Size of a Classic McEliece 460896 public key, rendered as `RP_PUBLIC_KEY_LEN`.
pub const RP_PUBLIC_KEY_LEN: usize = secret_blob::pq::PK_LEN;

/// Reads a McEliece public key through `load` and checks its size and hash.
fn load_rp(path: &str, hash: &str, load: &dyn Fn(&str) -> Result<Vec<u8>, String>) -> Result<RpKey, String> {
    let public = load(path)?;
    if public.len() != RP_PUBLIC_KEY_LEN {
        return Err(format!(
            "config: McEliece public key {path}: {} bytes, expected {RP_PUBLIC_KEY_LEN}",
            public.len()
        ));
    }
    let want = decode_hash(hash).map_err(|e| format!("config: rp_hash of {path}: {e}"))?;
    let hash = secret_blob::blake2s(&[&public]);
    if hash != want {
        return Err(format!("config: McEliece public key {path} does not match its rp_hash"));
    }
    Ok(RpKey { hash, public })
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
    let (ip, len) = s.split_once('/').ok_or_else(|| format!("prefix {s:?} needs /len"))?;
    let len: u8 = len.parse().map_err(|_| format!("bad prefix length in {s:?}"))?;
    if len > 32 {
        return Err(format!("bad prefix length in {s:?}"));
    }
    let p = Prefix { addr: parse_ip(ip)?, len };
    if p.range().0 != u32::from_be_bytes(p.addr) {
        return Err(format!("prefix {s:?} has host bits set"));
    }
    Ok(p)
}

/// Most peers an image can serve: `data` keeps three sessions per peer and
/// its replay windows dominate its memory (deviation log). Rendered into the
/// config crate as `MAX_PEERS`, so every PD sizes its tables from this one
/// value; build.rs asserts it fits the secrets region (secret_blob::MAX_PEERS).
pub const MAX_PEERS: usize = 8;
/// Most static inside neighbors (`inner`'s table), rendered as `MAX_NEIGHBORS`.
pub const MAX_NEIGHBORS: usize = 64;

/// Validates a configuration. `max_peers` is `MAX_PEERS` except in tests.
/// `load` reads a key file named in the configuration (build.rs resolves it
/// against the file's directory; tests and mksecrets serve it from memory).
pub fn check(text: &str, max_peers: usize, load: &dyn Fn(&str) -> Result<Vec<u8>, String>) -> Result<Checked, String> {
    let raw: RawConfig = toml::from_str(text).map_err(|e| format!("config: {e}"))?;
    let g = &raw.gateway;
    if raw.peers.is_empty() || raw.peers.len() > max_peers {
        return Err(format!("config: need 1..={max_peers} peers, got {}", raw.peers.len()));
    }
    let gateway_rp = load_rp(&g.rp_pub_path, &g.rp_hash, load)?;
    let mut peers: Vec<CheckedPeer> = Vec::new();
    for p in &raw.peers {
        let key = decode_key(&p.wg_pub)?;
        if peers.iter().any(|q| q.public == key) {
            return Err(format!("config: duplicate peer {}", p.wg_pub));
        }
        if p.allowed_ips.is_empty() {
            return Err(format!("config: peer {} has no allowed IPs", p.wg_pub));
        }
        let allowed = p
            .allowed_ips
            .iter()
            .map(|s| parse_prefix(s).map_err(|e| format!("config: allowed IP: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        let rp = load_rp(&p.rp_pub_path, &p.rp_hash, load)?;
        if rp.hash == gateway_rp.hash || peers.iter().any(|q| q.rp.hash == rp.hash) {
            return Err(format!("config: duplicate rp_pub {} (peer {})", p.rp_pub_path, p.wg_pub));
        }
        peers.push(CheckedPeer { public: key, allowed, rp });
    }
    // Cryptokey routing needs an unambiguous owner for every address.
    let all: Vec<(usize, &Prefix)> = peers.iter().enumerate().flat_map(|(i, q)| q.allowed.iter().map(move |p| (i, p))).collect();
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
    if peers.iter().any(|q| q.public == gateway_public) {
        return Err("config: a peer uses the gateway's own key".into());
    }
    let outside_ip = parse_ip(&g.outside_ip)?;
    let inside_ip = parse_ip(&g.inside_ip)?;
    let inside_prefix = parse_prefix(&g.inside_prefix).map_err(|e| format!("config: inside_prefix: {e}"))?;
    if !inside_prefix.contains(inside_ip) {
        return Err(format!("config: inside_ip {} is outside inside_prefix {}", g.inside_ip, g.inside_prefix));
    }
    if inside_prefix.contains(outside_ip) {
        return Err("config: outside_ip lies inside inside_prefix".into());
    }
    if raw.neighbors.len() > MAX_NEIGHBORS {
        return Err(format!("config: at most {MAX_NEIGHBORS} neighbors, got {}", raw.neighbors.len()));
    }
    let mut neighbors = Vec::new();
    for n in &raw.neighbors {
        let ip = parse_ip(&n.ip)?;
        if neighbors.iter().any(|(i, _)| *i == ip) {
            return Err(format!("config: duplicate neighbor {}", n.ip));
        }
        if ip == inside_ip || ip == outside_ip {
            return Err(format!("config: neighbor {} uses a gateway address", n.ip));
        }
        if !inside_prefix.contains(ip) {
            return Err(format!("config: neighbor {} is outside inside_prefix", n.ip));
        }
        neighbors.push((ip, parse_mac(&n.mac)?));
    }
    // A tunnel source inside a peer's allowed IPs passes `data`'s spoofing
    // check, so no allowed IP may stand for a gateway or inside-host address
    // (otherwise a peer could speak as that host on the inside LAN).
    for (i, q) in peers.iter().enumerate() {
        for p in &q.allowed {
            if p.contains(inside_ip) || p.contains(outside_ip) {
                return Err(format!("config: allowed IPs of peer {i} cover a gateway address"));
            }
            if let Some((ip, _)) = neighbors.iter().find(|(ip, _)| p.contains(*ip)) {
                return Err(format!("config: allowed IPs of peer {i} cover neighbor {}", std::net::Ipv4Addr::from(*ip)));
            }
            // Any overlap with the inside network would let the peer speak
            // as an inside host, listed as a neighbor or not.
            let ((a0, a1), (b0, b1)) = (p.range(), inside_prefix.range());
            if a0 <= b1 && b0 <= a1 {
                return Err(format!("config: allowed IPs of peer {i} overlap inside_prefix"));
            }
        }
    }
    if g.listen_port == 0 {
        return Err("config: listen_port must be non-zero".into());
    }
    if g.rp_port == 0 {
        return Err("config: rp_port must be non-zero".into());
    }
    if g.rp_port == g.listen_port {
        return Err("config: rp_port must differ from listen_port".into());
    }
    Ok(Checked {
        gateway_public,
        listen_port: g.listen_port,
        rp_port: g.rp_port,
        gateway_rp,
        outside_ip,
        outside_mac: parse_mac(&g.outside_mac)?,
        outside_router_mac: parse_mac(&g.outside_router_mac)?,
        inside_ip,
        inside_mac: parse_mac(&g.inside_mac)?,
        neighbors,
        peers,
    })
}

/// Renders the compiled configuration. `gateway_rp_file` and `peer_rp_files`
/// are the absolute paths of the McEliece public keys copied to OUT_DIR:
/// the generated macros embed them only in the crate that expands them
/// (`pq`, M3 plan F9/L6), never in `config` itself.
pub fn render(c: &Checked, gateway_rp_file: &str, peer_rp_files: &[String]) -> String {
    let mut s = String::new();
    s += &format!("pub const MAX_PEERS: usize = {MAX_PEERS};\n");
    s += &format!("pub const MAX_NEIGHBORS: usize = {MAX_NEIGHBORS};\n");
    s += &format!("pub const GATEWAY_PUBLIC: [u8; 32] = {:?};\n", c.gateway_public);
    s += &format!("pub const LISTEN_PORT: u16 = {};\n", c.listen_port);
    s += &format!("pub const RP_PORT: u16 = {};\n", c.rp_port);
    s += &format!("pub const RP_PUBLIC_KEY_LEN: usize = {RP_PUBLIC_KEY_LEN};\n");
    s += &format!("pub const GATEWAY_RP_HASH: [u8; 32] = {:?};\n", c.gateway_rp.hash);
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
    for q in &c.peers {
        s += &format!("    Peer {{ public: {:?}, rp_hash: {:?}, allowed: &[", q.public, q.rp.hash);
        for p in &q.allowed {
            s += &format!("Prefix {{ addr: {:?}, len: {} }}, ", p.addr, p.len);
        }
        s += "] },\n";
    }
    s += "];\n";
    s += "/// The gateway's McEliece public key (`spkm`) as `&'static [u8; RP_PUBLIC_KEY_LEN]`.\n";
    s += &format!("#[macro_export]\nmacro_rules! gateway_rp_public {{\n    () => {{ include_bytes!({gateway_rp_file:?}) }};\n}}\n");
    s += "/// Each peer's McEliece public key (`spkt`), in `PEERS` order.\n";
    s += "#[macro_export]\nmacro_rules! peer_rp_publics {\n    () => { [";
    for f in peer_rp_files {
        s += &format!("include_bytes!({f:?}), ");
    }
    s += "] };\n}\n";
    s
}
