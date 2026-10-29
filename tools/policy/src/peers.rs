//! The vendor-neutral `peers.toml` (M8 plan C2): peers with their
//! WireGuard and rp public keys, allowed IPs and group memberships; groups
//! with their rules; `min_release`; `fleet_id`. `render` turns this into
//! the canonical peer/group order `policy_wire::render` needs (M8 plan C1:
//! peers strictly ascending by raw `wg_pub`, rules within a group strictly
//! ascending by their encoded bytes) and then validates the result against
//! every node in the fleet file with `policy_wire::parse`, so a mistake
//! here is caught the same way the device would catch it, not by a second,
//! looser check.
//!
//! ```toml
//! fleet_id = "<32 lowercase hex>"
//! min_release = 0
//!
//! [[peers]]
//! wg_pub = "<44-char base64, as gateway.toml>"
//! rp_pub_path = "peer-a.pub"           # relative to this file
//! allowed_ips = ["10.1.0.0/24"]
//! groups = ["eng"]
//!
//! [[groups]]
//! name = "eng"
//! [[groups.rules]]
//! dst = "10.2.0.0/24"
//! proto = "tcp"                        # "tcp" | "udp" | "icmp"
//! port_lo = 443
//! port_hi = 443
//! ```

use std::path::Path;

use policy_wire::{PROTO_ICMP, PROTO_TCP, PROTO_UDP, Prefix, Rule};

use crate::validate;

#[derive(Debug, serde::Deserialize)]
struct RawPeersFile {
    fleet_id: String,
    min_release: u32,
    peers: Vec<RawPeer>,
    #[serde(default)]
    groups: Vec<RawGroup>,
}

#[derive(Debug, serde::Deserialize)]
struct RawPeer {
    wg_pub: String,
    rp_pub_path: String,
    allowed_ips: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct RawGroup {
    name: String,
    #[serde(default)]
    rules: Vec<RawRule>,
}

#[derive(Debug, serde::Deserialize)]
struct RawRule {
    dst: String,
    proto: String,
    port_lo: u16,
    port_hi: u16,
}

pub struct PeerOwned {
    pub wg_pub: [u8; 32],
    pub rp_pub: Vec<u8>,
    pub allowed: Vec<Prefix>,
    pub groups: u8,
}

pub struct GroupOwned {
    pub rules: Vec<Rule>,
}

pub struct Draft {
    pub fleet_id: [u8; 16],
    pub min_release: u32,
    /// Strictly ascending by raw `wg_pub` bytes (M8 plan C1).
    pub peers: Vec<PeerOwned>,
    /// In bit-index order (group 0 first); each group's rules strictly
    /// ascending by their encoded bytes.
    pub groups: Vec<GroupOwned>,
}

fn parse_proto(s: &str) -> Result<u8, String> {
    match s {
        "tcp" => Ok(PROTO_TCP),
        "udp" => Ok(PROTO_UDP),
        "icmp" => Ok(PROTO_ICMP),
        other => Err(format!("peers.toml: proto {other:?} must be tcp, udp or icmp")),
    }
}

/// The 10-byte rule encoding the wire format fixes (M8 plan C1), used here
/// only to order and de-duplicate rules the same way the device would see
/// them; `policy_wire::render` lays the bytes out again independently, and
/// `policy_wire::parse` re-checks the order afterwards.
fn encode_rule(r: &Rule) -> [u8; 10] {
    let mut out = [0u8; 10];
    out[0..4].copy_from_slice(&r.dst.addr);
    out[4] = r.dst.len;
    out[5] = r.proto;
    out[6..8].copy_from_slice(&r.port_lo.to_be_bytes());
    out[8..10].copy_from_slice(&r.port_hi.to_be_bytes());
    out
}

impl Draft {
    pub fn load(path: &Path) -> Result<Draft, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let raw: RawPeersFile = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let fleet_id = crate::util::hex_n::<16>(&raw.fleet_id, "peers.toml: fleet_id")?;
        let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));

        if raw.groups.len() > limits::MAX_GROUPS {
            return Err(format!("peers.toml: at most {} groups, got {}", limits::MAX_GROUPS, raw.groups.len()));
        }
        let mut group_names: Vec<&str> = raw.groups.iter().map(|g| g.name.as_str()).collect();
        group_names.sort_unstable();
        if group_names.windows(2).any(|w| w[0] == w[1]) {
            return Err("peers.toml: a group name appears twice".into());
        }
        // Canonical group order: ascending by name; a peer's membership
        // bitmask bit `i` refers to the group at sorted index `i`.
        let mut ordered_groups: Vec<&RawGroup> = raw.groups.iter().collect();
        ordered_groups.sort_by_key(|g| g.name.clone());
        let groups: Vec<GroupOwned> = ordered_groups
            .iter()
            .map(|g| {
                if g.rules.is_empty() || g.rules.len() > limits::MAX_RULES {
                    return Err(format!("peers.toml: group {} needs 1..={} rules, got {}", g.name, limits::MAX_RULES, g.rules.len()));
                }
                let mut rules: Vec<Rule> = g
                    .rules
                    .iter()
                    .map(|r| {
                        let dst = validate::parse_prefix(&r.dst).map_err(|e| format!("peers.toml: group {}: {e}", g.name))?;
                        let proto = parse_proto(&r.proto)?;
                        if r.port_lo > r.port_hi {
                            return Err(format!("peers.toml: group {}: port_lo > port_hi", g.name));
                        }
                        if proto == PROTO_ICMP && (r.port_lo != 0 || r.port_hi != 0) {
                            return Err(format!("peers.toml: group {}: an icmp rule's ports must both be 0 (echo only)", g.name));
                        }
                        Ok(Rule { dst, proto, port_lo: r.port_lo, port_hi: r.port_hi })
                    })
                    .collect::<Result<_, String>>()?;
                rules.sort_by_key(encode_rule);
                if rules.windows(2).any(|w| encode_rule(&w[0]) == encode_rule(&w[1])) {
                    return Err(format!("peers.toml: group {} has a duplicate rule", g.name));
                }
                Ok(GroupOwned { rules })
            })
            .collect::<Result<_, String>>()?;

        if raw.peers.is_empty() || raw.peers.len() > limits::MAX_PEERS {
            return Err(format!("peers.toml: needs 1..={} peers, got {}", limits::MAX_PEERS, raw.peers.len()));
        }
        let mut peers: Vec<PeerOwned> = raw
            .peers
            .iter()
            .map(|p| {
                let wg_pub = validate::decode_key(&p.wg_pub).map_err(|e| format!("peers.toml: {e}"))?;
                let rp_path = dir.join(&p.rp_pub_path);
                let rp_pub = std::fs::read(&rp_path).map_err(|e| format!("{}: {e}", rp_path.display()))?;
                if rp_pub.len() != limits::SPK_LEN {
                    return Err(format!("{}: {} bytes, expected {}", rp_path.display(), rp_pub.len(), limits::SPK_LEN));
                }
                if p.allowed_ips.is_empty() || p.allowed_ips.len() > limits::MAX_ALLOWED {
                    return Err(format!("peers.toml: peer {}: needs 1..={} allowed IPs, got {}", p.wg_pub, limits::MAX_ALLOWED, p.allowed_ips.len()));
                }
                let allowed: Vec<Prefix> = p.allowed_ips.iter().map(|s| validate::parse_prefix(s).map_err(|e| format!("peers.toml: allowed IP: {e}"))).collect::<Result<_, _>>()?;
                let mut groups = 0u8;
                for name in &p.groups {
                    let idx = group_names.iter().position(|n| n == name).ok_or_else(|| format!("peers.toml: peer {}: unknown group {name:?}", p.wg_pub))?;
                    groups |= 1 << idx;
                }
                Ok(PeerOwned { wg_pub, rp_pub, allowed, groups })
            })
            .collect::<Result<_, String>>()?;
        peers.sort_by_key(|a| a.wg_pub);
        if peers.windows(2).any(|w| w[0].wg_pub == w[1].wg_pub) {
            return Err("peers.toml: a peer's wg_pub appears twice".into());
        }
        if peers.windows(2).any(|w| w[0].rp_pub == w[1].rp_pub) {
            return Err("peers.toml: a peer's rp_pub appears twice".into());
        }

        Ok(Draft { fleet_id, min_release: raw.min_release, peers, groups })
    }
}
