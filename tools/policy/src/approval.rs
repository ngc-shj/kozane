//! Approval and restore-approval records (M8 plan C2, D11): canonical
//! `key=value` fields (`record.rs`) followed by one `sig_ed25519=<hex>`
//! line, the signature over exactly the fields block's bytes under the
//! record's own domain (`sig.rs`). `ts` rides in the signed fields so a
//! forged approval cannot be replayed with a different timestamp, but it
//! is informational only: nothing here compares it to anything.

use crate::roster::Roster;
use crate::{record, sig};

fn hex(b: &[u8]) -> String {
    sig::hex(b)
}

fn split_signed(bytes: &[u8]) -> Result<(&str, [u8; 64]), String> {
    let text = core::str::from_utf8(bytes).map_err(|_| "record is not UTF-8".to_string())?;
    let body = text.strip_suffix('\n').ok_or("record does not end with LF")?;
    let (fields_part, sig_line) = body.rsplit_once('\n').ok_or("record: missing signature line")?;
    let sig_hex = sig_line.strip_prefix("sig_ed25519=").ok_or("record: last line is not sig_ed25519=")?;
    let sig_bytes = sig::unhex(sig_hex).filter(|b| b.len() == 64).ok_or("record: sig_ed25519 is not 128 lowercase hex digits")?;
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);
    Ok((fields_part, sig))
}

// --- Approval records ----------------------------------------------------

pub const APPROVAL_KEYS: [&str; 8] = ["approver_id", "body_sha256", "diff_sha256", "fleet_id", "prev_sha256", "roster_sha256", "ts", "version"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalFields {
    pub approver_id: String,
    pub body_sha256: [u8; 32],
    pub diff_sha256: [u8; 32],
    pub fleet_id: [u8; 16],
    pub prev_sha256: [u8; 32],
    pub roster_sha256: [u8; 32],
    pub ts: u64,
    pub version: u32,
}

impl ApprovalFields {
    fn to_pairs(&self) -> Vec<(String, String)> {
        vec![
            ("approver_id".into(), self.approver_id.clone()),
            ("body_sha256".into(), hex(&self.body_sha256)),
            ("diff_sha256".into(), hex(&self.diff_sha256)),
            ("fleet_id".into(), hex(&self.fleet_id)),
            ("prev_sha256".into(), hex(&self.prev_sha256)),
            ("roster_sha256".into(), hex(&self.roster_sha256)),
            ("ts".into(), self.ts.to_string()),
            ("version".into(), self.version.to_string()),
        ]
    }

    fn render_fields(&self) -> Vec<u8> {
        let pairs = self.to_pairs();
        let refs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        record::render(&refs, &APPROVAL_KEYS)
    }

    fn from_pairs(fields: &[(String, String)]) -> Result<ApprovalFields, String> {
        let get = |k: &str| record::get(fields, k).ok_or_else(|| format!("approval: missing {k}")).map(str::to_string);
        let hex32 = |k: &str| -> Result<[u8; 32], String> { crate::util::hex_n::<32>(&get(k)?, &format!("approval: {k}")) };
        Ok(ApprovalFields {
            approver_id: get("approver_id")?,
            body_sha256: hex32("body_sha256")?,
            diff_sha256: hex32("diff_sha256")?,
            fleet_id: crate::util::hex_n::<16>(&get("fleet_id")?, "approval: fleet_id")?,
            prev_sha256: hex32("prev_sha256")?,
            roster_sha256: hex32("roster_sha256")?,
            ts: get("ts")?.parse().map_err(|_| "approval: ts is not a number".to_string())?,
            version: get("version")?.parse().map_err(|_| "approval: version is not a number".to_string())?,
        })
    }
}

pub fn sign(sk: &sig::ApproverSigningKey, fields: &ApprovalFields, random: &mut dyn FnMut(&mut [u8]) -> bool) -> Result<Vec<u8>, String> {
    let block = fields.render_fields();
    let signature = sig::approver_sign(sk, sig::APPROVAL_DOMAIN, &block, random).map_err(|e| e.to_string())?;
    let mut out = block;
    out.extend_from_slice(format!("sig_ed25519={}\n", hex(&signature)).as_bytes());
    Ok(out)
}

/// Parses `bytes` and verifies its signature against `roster`. Does not
/// compare the parsed fields against anything the caller expects: that is
/// `sign`'s/`verify`'s job, so each bound-field mismatch gets its own
/// refusal reason.
pub fn parse_and_verify(bytes: &[u8], roster: &Roster) -> Result<ApprovalFields, String> {
    let (fields_part, signature) = split_signed(bytes)?;
    let fields_bytes = format!("{fields_part}\n").into_bytes();
    let pairs = record::parse(&fields_bytes, &APPROVAL_KEYS).map_err(|e| e.to_string())?;
    let fields = ApprovalFields::from_pairs(&pairs)?;
    let approver = roster.find(&fields.approver_id).ok_or_else(|| format!("approval: approver {} is not in the roster", fields.approver_id))?;
    sig::approver_verify(&approver.ed25519_pub, sig::APPROVAL_DOMAIN, &fields_bytes, &signature).map_err(|_| "approval: the signature does not verify".to_string())?;
    Ok(fields)
}

// --- Restore-approval records (D11) --------------------------------------

pub const RESTORE_KEYS: [&str; 5] = ["approver_id", "fleet_id", "head_body_sha256", "head_version", "ts"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreFields {
    pub approver_id: String,
    pub fleet_id: [u8; 16],
    pub head_body_sha256: [u8; 32],
    pub head_version: u32,
    pub ts: u64,
}

impl RestoreFields {
    fn to_pairs(&self) -> Vec<(String, String)> {
        vec![
            ("approver_id".into(), self.approver_id.clone()),
            ("fleet_id".into(), hex(&self.fleet_id)),
            ("head_body_sha256".into(), hex(&self.head_body_sha256)),
            ("head_version".into(), self.head_version.to_string()),
            ("ts".into(), self.ts.to_string()),
        ]
    }

    fn render_fields(&self) -> Vec<u8> {
        let pairs = self.to_pairs();
        let refs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        record::render(&refs, &RESTORE_KEYS)
    }

    fn from_pairs(fields: &[(String, String)]) -> Result<RestoreFields, String> {
        let get = |k: &str| record::get(fields, k).ok_or_else(|| format!("restore approval: missing {k}")).map(str::to_string);
        Ok(RestoreFields {
            approver_id: get("approver_id")?,
            fleet_id: crate::util::hex_n::<16>(&get("fleet_id")?, "restore approval: fleet_id")?,
            head_body_sha256: crate::util::hex_n::<32>(&get("head_body_sha256")?, "restore approval: head_body_sha256")?,
            head_version: get("head_version")?.parse().map_err(|_| "restore approval: head_version is not a number".to_string())?,
            ts: get("ts")?.parse().map_err(|_| "restore approval: ts is not a number".to_string())?,
        })
    }
}

/// How long a restore approval stays usable (S6-1): long enough for one
/// recovery, short enough that one restore's approvals, kept with the
/// restored ledger, are no token for rolling it back later.
pub const RESTORE_APPROVAL_MAX_AGE_S: u64 = 24 * 3600;
/// Clock skew tolerated between an approver's device and the restore host.
pub const RESTORE_APPROVAL_SKEW_S: u64 = 300;

pub fn restore_approval_fresh(ts: u64, now: u64) -> Result<(), String> {
    if ts > now.saturating_add(RESTORE_APPROVAL_SKEW_S) {
        return Err(format!("restore approval: signed at {ts}, in the future of this host's clock ({now})"));
    }
    if now.saturating_sub(ts) > RESTORE_APPROVAL_MAX_AGE_S {
        return Err(format!(
            "restore approval: signed at {ts}, more than {RESTORE_APPROVAL_MAX_AGE_S} s ago: approvals are for one recovery, ask again"
        ));
    }
    Ok(())
}

pub fn sign_restore(sk: &sig::ApproverSigningKey, fields: &RestoreFields, random: &mut dyn FnMut(&mut [u8]) -> bool) -> Result<Vec<u8>, String> {
    let block = fields.render_fields();
    let signature = sig::approver_sign(sk, sig::RESTORE_DOMAIN, &block, random).map_err(|e| e.to_string())?;
    let mut out = block;
    out.extend_from_slice(format!("sig_ed25519={}\n", hex(&signature)).as_bytes());
    Ok(out)
}

pub fn parse_and_verify_restore(bytes: &[u8], roster: &Roster) -> Result<RestoreFields, String> {
    let (fields_part, signature) = split_signed(bytes)?;
    let fields_bytes = format!("{fields_part}\n").into_bytes();
    let pairs = record::parse(&fields_bytes, &RESTORE_KEYS).map_err(|e| e.to_string())?;
    let fields = RestoreFields::from_pairs(&pairs)?;
    let approver = roster.find(&fields.approver_id).ok_or_else(|| format!("restore approval: approver {} is not in the roster", fields.approver_id))?;
    sig::approver_verify(&approver.ed25519_pub, sig::RESTORE_DOMAIN, &fields_bytes, &signature).map_err(|_| "restore approval: the signature does not verify".to_string())?;
    Ok(fields)
}
