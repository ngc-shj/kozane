//! The fleet file (M8 plan C2): each node's `policy_wire::NodeConfig`,
//! rendered from its `gateway.toml` through the exact `config::validate`
//! checks the image build runs (`crate::validate`, shared by `include!` as
//! `tools/mksecrets` shares it), plus a digest of that `NodeConfig` which
//! `tools/package` also records for the node so `verify --fleet` can catch
//! the two falling out of step.
//!
//! `gateway.toml` has no `fleet_id` field yet (M8 plan C7, which moves
//! `[[peers]]` out and adds a `[policy]` section, is a later slice; this
//! tool does not touch `crates/config`). `tools/policy fleet` therefore
//! takes `--fleet-id` once on the command line and stamps every node built
//! in that call with it — one fleet file is always one fleet.
//!
//! On-disk format (TOML; only the digest below is byte-canonical, not the
//! file):
//!
//! ```toml
//! fleet_id = "<32 lowercase hex>"
//!
//! [[node]]
//! name = "gw1"
//! inside_prefix = "10.0.0.0/24"
//! inside_ip = "10.0.0.1"
//! outside_ip = "203.0.113.5"
//! neighbors = ["10.0.0.2"]
//! gateway_wg_public = "<64 hex>"
//! gateway_rp_digest = "<64 hex>"
//! node_sha256 = "<64 hex>"
//! ```

use policy_wire::{NodeConfig, Prefix};

use crate::sig;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct RawNode {
    pub name: String,
    pub inside_prefix: String,
    pub inside_ip: String,
    pub outside_ip: String,
    #[serde(default)]
    pub neighbors: Vec<String>,
    pub gateway_wg_public: String,
    pub gateway_rp_digest: String,
    pub node_sha256: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct RawFleet {
    pub fleet_id: String,
    #[serde(rename = "node")]
    pub nodes: Vec<RawNode>,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub name: String,
    pub fleet_id: [u8; 16],
    pub inside_prefix: Prefix,
    pub inside_ip: [u8; 4],
    pub outside_ip: [u8; 4],
    pub neighbors: Vec<[u8; 4]>,
    pub gateway_wg_public: [u8; 32],
    pub gateway_rp_digest: [u8; 32],
}

fn fmt_ip(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn parse_ip(s: &str) -> Result<[u8; 4], String> {
    let a: std::net::Ipv4Addr = s.parse().map_err(|_| format!("fleet: bad IPv4 address {s:?}"))?;
    Ok(a.octets())
}

fn parse_prefix(s: &str) -> Result<Prefix, String> {
    let (ip, len) = s.split_once('/').ok_or_else(|| format!("fleet: prefix {s:?} needs /len"))?;
    let len: u8 = len.parse().map_err(|_| format!("fleet: bad prefix length in {s:?}"))?;
    let addr = parse_ip(ip)?;
    Prefix::checked(addr, len).ok_or_else(|| format!("fleet: prefix {s:?} has host bits set or len > 32"))
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    crate::util::hex_n::<32>(s, &format!("fleet: {what}"))
}

fn hex16(s: &str, what: &str) -> Result<[u8; 16], String> {
    crate::util::hex_n::<16>(s, &format!("fleet: {what}"))
}

/// `sha256(DOMAIN ‖ fleet_id[16] ‖ inside_prefix.addr[4] ‖
/// inside_prefix.len[1] ‖ inside_ip[4] ‖ outside_ip[4] ‖ neighbor_count(u8)
/// ‖ neighbors, ascending, each [4] ‖ gateway_wg_public[32] ‖
/// gateway_rp_digest[32])`. A canonical byte encoding, not the wire
/// format: it exists only to let two independently-built records
/// (`tools/policy fleet` here, `tools/package` for the node) agree that
/// they describe the same `NodeConfig`.
pub fn node_digest(n: &Node) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    const DOMAIN: &[u8] = b"kozane-policy-nodeconfig-v1\0";
    let mut neighbors = n.neighbors.clone();
    neighbors.sort_unstable();
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(n.fleet_id);
    h.update(n.inside_prefix.addr);
    h.update([n.inside_prefix.len]);
    h.update(n.inside_ip);
    h.update(n.outside_ip);
    #[allow(clippy::cast_possible_truncation)]
    h.update([neighbors.len() as u8]);
    for ip in &neighbors {
        h.update(ip);
    }
    h.update(n.gateway_wg_public);
    h.update(n.gateway_rp_digest);
    h.finalize().into()
}

impl Node {
    pub fn as_node_config(&self) -> NodeConfig<'_> {
        NodeConfig {
            fleet_id: self.fleet_id,
            inside_prefix: self.inside_prefix,
            inside_ip: self.inside_ip,
            outside_ip: self.outside_ip,
            neighbors: &self.neighbors,
            gateway_wg_public: self.gateway_wg_public,
            gateway_rp_digest: self.gateway_rp_digest,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Fleet {
    pub fleet_id: [u8; 16],
    /// Sorted ascending by `name` (canonical, and the order `render`
    /// validates peers against).
    pub nodes: Vec<Node>,
}

impl Fleet {
    pub fn parse(text: &str) -> Result<Fleet, String> {
        let raw: RawFleet = toml::from_str(text).map_err(|e| format!("fleet: {e}"))?;
        let fleet_id = hex16(&raw.fleet_id, "fleet_id")?;
        if raw.nodes.is_empty() {
            return Err("fleet: needs at least one node".into());
        }
        let mut nodes = Vec::new();
        for rn in &raw.nodes {
            if nodes.iter().any(|n: &Node| n.name == rn.name) {
                return Err(format!("fleet: node {} appears twice", rn.name));
            }
            let node = Node {
                name: rn.name.clone(),
                fleet_id,
                inside_prefix: parse_prefix(&rn.inside_prefix)?,
                inside_ip: parse_ip(&rn.inside_ip)?,
                outside_ip: parse_ip(&rn.outside_ip)?,
                neighbors: rn.neighbors.iter().map(|s| parse_ip(s)).collect::<Result<_, _>>()?,
                gateway_wg_public: hex32(&rn.gateway_wg_public, "gateway_wg_public")?,
                gateway_rp_digest: hex32(&rn.gateway_rp_digest, "gateway_rp_digest")?,
            };
            let want = hex32(&rn.node_sha256, "node_sha256")?;
            let got = node_digest(&node);
            if got != want {
                return Err(format!("fleet: node {} digest does not match its stored node_sha256 (fleet file tampered or stale)", rn.name));
            }
            nodes.push(node);
        }
        nodes.sort_by_key(|n| n.name.clone());
        Ok(Fleet { fleet_id, nodes })
    }

    pub fn render(&self) -> String {
        let raw = RawFleet {
            fleet_id: sig::hex(&self.fleet_id),
            nodes: self
                .nodes
                .iter()
                .map(|n| RawNode {
                    name: n.name.clone(),
                    inside_prefix: format!("{}/{}", fmt_ip(n.inside_prefix.addr), n.inside_prefix.len),
                    inside_ip: fmt_ip(n.inside_ip),
                    outside_ip: fmt_ip(n.outside_ip),
                    neighbors: n.neighbors.iter().map(|ip| fmt_ip(*ip)).collect(),
                    gateway_wg_public: sig::hex(&n.gateway_wg_public),
                    gateway_rp_digest: sig::hex(&n.gateway_rp_digest),
                    node_sha256: sig::hex(&node_digest(n)),
                })
                .collect(),
        };
        toml::to_string(&raw).unwrap_or_default()
    }
}
