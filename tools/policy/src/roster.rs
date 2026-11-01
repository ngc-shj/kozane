//! The approver roster (M8 plan C2, D11): approver IDs and Ed25519 keys,
//! distinct by ID *and* key. A roster's digest rides in every bundle body
//! (`roster_sha256`) and is the only thing `sign` ever takes from the
//! caller; the actual roster content comes only from the verified ledger
//! (the genesis roster, or whichever bundle last changed it), never from a
//! flag.
//!
//! On-disk roster file (TOML, human-edited, not itself canonical bytes —
//! only the digest below is):
//!
//! ```toml
//! [[approver]]
//! id = "alice"
//! ed25519_pub = "<64 lowercase hex>"
//! ```

use crate::sig;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct RawApprover {
    pub id: String,
    pub ed25519_pub: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct RawRoster {
    #[serde(rename = "approver")]
    pub approvers: Vec<RawApprover>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approver {
    pub id: String,
    pub ed25519_pub: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster {
    /// Sorted ascending by `id` (the canonical order the digest is over).
    pub approvers: Vec<Approver>,
}

/// Domain tag for the roster digest, so it can never collide with a digest
/// of anything else `tools/policy` hashes under sha256 alone.
const ROSTER_DOMAIN: &[u8] = b"kozane-policy-roster-v1\0";

impl Roster {
    pub fn parse(text: &str) -> Result<Roster, String> {
        let raw: RawRoster = toml::from_str(text).map_err(|e| format!("roster: {e}"))?;
        if raw.approvers.is_empty() {
            return Err("roster: needs at least one approver".into());
        }
        let mut approvers = Vec::new();
        for a in &raw.approvers {
            if a.id.is_empty() || a.id.len() > 255 || !a.id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                return Err(format!("roster: approver id {:?} must be [A-Za-z0-9_-]+, at most 255 bytes", a.id));
            }
            let key = sig::unhex(&a.ed25519_pub).filter(|k| k.len() == 32).ok_or_else(|| format!("roster: approver {}: ed25519_pub is not 64 lowercase hex digits", a.id))?;
            let mut ed25519_pub = [0u8; 32];
            ed25519_pub.copy_from_slice(&key);
            if approvers.iter().any(|p: &Approver| p.id == a.id) {
                return Err(format!("roster: approver id {} appears twice", a.id));
            }
            if approvers.iter().any(|p: &Approver| p.ed25519_pub == ed25519_pub) {
                return Err(format!("roster: approver {} reuses another approver's key", a.id));
            }
            approvers.push(Approver { id: a.id.clone(), ed25519_pub });
        }
        approvers.sort_by_key(|a| a.id.clone());
        Ok(Roster { approvers })
    }

    pub fn render(&self) -> String {
        let raw = RawRoster {
            approvers: self.approvers.iter().map(|a| RawApprover { id: a.id.clone(), ed25519_pub: sig::hex(&a.ed25519_pub) }).collect(),
        };
        toml::to_string(&raw).unwrap_or_default()
    }

    /// `sha256(ROSTER_DOMAIN ‖ count u32 ‖ (id_len u32 ‖ id ‖ ed25519_pub[32])*)`,
    /// lengths big-endian and never truncated, so no two rosters share an
    /// encoding,
    /// over the approvers in their canonical (sorted-by-id) order. Sorts a
    /// local copy rather than trusting `self.approvers` to already be
    /// sorted, so a `Roster` built directly (not through [`Roster::parse`])
    /// still digests the same way regardless of field order.
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut sorted: Vec<&Approver> = self.approvers.iter().collect();
        sorted.sort_by_key(|a| a.id.clone());
        let mut h = Sha256::new();
        h.update(ROSTER_DOMAIN);
        h.update(len32(sorted.len()));
        for a in sorted {
            h.update(len32(a.id.len()));
            h.update(a.id.as_bytes());
            h.update(a.ed25519_pub);
        }
        h.finalize().into()
    }

    pub fn find(&self, id: &str) -> Option<&Approver> {
        self.approvers.iter().find(|a| a.id == id)
    }
}

/// A length as four big-endian bytes; saturates rather than wraps, and no
/// roster or id comes near 2^32.
fn len32(n: usize) -> [u8; 4] {
    u32::try_from(n).unwrap_or(u32::MAX).to_be_bytes()
}
