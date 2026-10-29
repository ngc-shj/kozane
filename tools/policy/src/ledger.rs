//! The ledger (M8 plan C2, D11): every signed bundle plus the approval
//! records that signed it, in order; `sign`, `approve` and `verify
//! --ledger` all re-verify the whole chain (signatures, `prev` links, each
//! step's approvals under the roster in force at that step) rather than
//! trusting anything cached. Every approver keeps a full replica
//! (directory copy); there is no central service.
//!
//! On-disk layout:
//!
//! ```text
//! <dir>/
//!   genesis-roster.sha256        the pinned genesis digest (hex, LF)
//!   roster/<sha256-hex>.toml     every roster ever in force, content-addressed
//!   entries/<version:010>.bin    the signed slot, exactly BUNDLE_MAX bytes
//!   approvals/<version:010>/<approver_id>.approval
//! ```

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::roster::Roster;
use crate::wire_header::{self, Header};
use crate::{approval, diff, sig};

pub struct Ledger {
    dir: PathBuf,
}

fn body_sha256(slot: &[u8]) -> Result<[u8; 32], String> {
    let u = policy_wire::split(slot).map_err(|e| format!("slot: {e:?}"))?;
    Ok(Sha256::digest(u.body()).into())
}

impl Ledger {
    pub fn open(dir: &Path) -> Ledger {
        Ledger { dir: dir.to_path_buf() }
    }

    fn entries_dir(&self) -> PathBuf {
        self.dir.join("entries")
    }

    fn roster_dir(&self) -> PathBuf {
        self.dir.join("roster")
    }

    fn approvals_dir(&self) -> PathBuf {
        self.dir.join("approvals")
    }

    fn pin_path(&self) -> PathBuf {
        self.dir.join("genesis-roster.sha256")
    }

    fn entry_path(&self, v: u32) -> PathBuf {
        self.entries_dir().join(format!("{v:010}.bin"))
    }

    fn approval_dir_for(&self, v: u32) -> PathBuf {
        self.approvals_dir().join(format!("{v:010}"))
    }

    fn roster_path(&self, digest: &[u8; 32]) -> PathBuf {
        self.roster_dir().join(format!("{}.toml", sig::hex(digest)))
    }

    /// Creates an empty ledger, pinning `genesis_roster` (which must hash
    /// to `pinned`, the fleet's compiled-in constant) as version 0's
    /// incoming roster.
    pub fn init(dir: &Path, genesis_roster: &Roster, pinned: [u8; 32]) -> Result<Ledger, String> {
        if dir.exists() {
            return Err(format!("{}: already exists", dir.display()));
        }
        if genesis_roster.digest() != pinned {
            return Err("ledger init: the genesis roster does not match the pinned digest".into());
        }
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let ledger = Ledger::open(dir);
        std::fs::create_dir_all(ledger.entries_dir()).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(ledger.roster_dir()).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(ledger.approvals_dir()).map_err(|e| e.to_string())?;
        std::fs::write(ledger.pin_path(), format!("{}\n", sig::hex(&pinned))).map_err(|e| e.to_string())?;
        ledger.store_roster(genesis_roster)?;
        Ok(ledger)
    }

    pub fn store_roster(&self, roster: &Roster) -> Result<(), String> {
        let path = self.roster_path(&roster.digest());
        if path.exists() {
            // Content-addressed: already present under this digest means
            // byte-identical content (the digest covers everything), so
            // writing again is a harmless no-op.
            return Ok(());
        }
        std::fs::write(&path, roster.render()).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn load_roster(&self, digest: &[u8; 32]) -> Result<Roster, String> {
        let path = self.roster_path(digest);
        let text = std::fs::read_to_string(&path).map_err(|_| format!("ledger: roster {} is not in the ledger's roster store", sig::hex(digest)))?;
        let roster = Roster::parse(&text)?;
        if &roster.digest() != digest {
            return Err(format!("ledger: roster file {} does not hash to its own name (tampered)", path.display()));
        }
        Ok(roster)
    }

    /// The highest version present, or `None` for an empty ledger.
    /// Requires every version `0..=height` to be present with no gap (a
    /// truncated or holey ledger is refused, never silently resumed from
    /// whatever is there).
    pub fn height(&self) -> Result<Option<u32>, String> {
        let dir = self.entries_dir();
        if !dir.is_dir() {
            return Ok(None);
        }
        let mut versions: Vec<u32> = Vec::new();
        for entry in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name();
            let name = name.to_str().ok_or("ledger: a non-UTF-8 entry file name")?;
            let digits = name.strip_suffix(".bin").ok_or_else(|| format!("ledger: unexpected file {name} in entries/"))?;
            if digits.len() != 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("ledger: unexpected file {name} in entries/"));
            }
            versions.push(digits.parse().map_err(|_| format!("ledger: unexpected file {name} in entries/"))?);
        }
        if versions.is_empty() {
            return Ok(None);
        }
        versions.sort_unstable();
        let max = *versions.last().ok_or("ledger: internal")?;
        if versions != (0..=max).collect::<Vec<u32>>() {
            return Err(format!("ledger: truncated or has a gap (has {} entries, highest version {max})", versions.len()));
        }
        Ok(Some(max))
    }

    pub fn read_entry(&self, v: u32) -> Result<Vec<u8>, String> {
        let path = self.entry_path(v);
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if bytes.len() != limits::BUNDLE_MAX {
            return Err(format!("{}: {} bytes, expected {}", path.display(), bytes.len(), limits::BUNDLE_MAX));
        }
        Ok(bytes)
    }

    fn check_not_signed(&self, v: u32) -> Result<(), String> {
        if self.entry_path(v).exists() {
            return Err(format!("ledger: version {v} already has a signed body (no second body for a signed version)"));
        }
        Ok(())
    }

    /// Writes the entry file. Callers check [`Ledger::check_not_signed`]
    /// first, so approvals are durably written before the entry that
    /// makes them "used": a failure partway through `append` never leaves
    /// a signed body with no recorded approvals.
    fn write_entry(&self, v: u32, bytes: &[u8]) -> Result<(), String> {
        std::fs::create_dir_all(self.entries_dir()).map_err(|e| e.to_string())?;
        let path = self.entry_path(v);
        std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn read_approvals(&self, v: u32) -> Result<Vec<Vec<u8>>, String> {
        let dir = self.approval_dir_for(v);
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
            let entry = entry.map_err(|e| e.to_string())?;
            out.push(std::fs::read(entry.path()).map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    fn write_approvals(&self, v: u32, files: &[Vec<u8>], roster: &Roster) -> Result<(), String> {
        let dir = self.approval_dir_for(v);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        for bytes in files {
            let fields = approval::parse_and_verify(bytes, roster)?;
            std::fs::write(dir.join(format!("{}.approval", fields.approver_id)), bytes).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// `verify_chain` without the bundle Ed25519/ML-DSA-65 signatures:
    /// `approve` has no policy verifying key (an approver only ever holds
    /// their own approval key) and still needs to re-verify the prev
    /// links, the roster and the approval chain before trusting the
    /// ledger's head (D11). `sign` and `verify --ledger`, which do hold
    /// the policy public keys, call [`Ledger::verify_chain`] instead so
    /// the bundle signatures are checked too.
    pub fn verify_chain_unsigned(&self, pinned: [u8; 32]) -> Result<ChainState, String> {
        self.verify_chain_inner(None, pinned)
    }

    /// Re-verifies the whole chain: every signature, every `prev` link and
    /// every step's approvals under the roster that was in force when it
    /// signed. Returns the state as of the (verified) head, and the roster
    /// in force for the *next* version's approvals.
    pub fn verify_chain(&self, keys_pub: &sig::BundleVerifyingKeys, pinned: [u8; 32]) -> Result<ChainState, String> {
        self.verify_chain_inner(Some(keys_pub), pinned)
    }

    fn verify_chain_inner(&self, keys_pub: Option<&sig::BundleVerifyingKeys>, pinned: [u8; 32]) -> Result<ChainState, String> {
        let height = self.height()?;
        let mut roster = self.load_roster(&pinned).map_err(|e| format!("ledger: genesis roster: {e}"))?;
        if roster.digest() != pinned {
            return Err("ledger: the genesis roster does not match the pinned digest".into());
        }
        let mut prev: Option<(Header, Vec<u8>)> = None;
        let Some(height) = height else {
            return Ok(ChainState { height: None, head_header: None, head_body: None, roster });
        };
        for v in 0..=height {
            let slot = self.read_entry(v)?;
            let header = wire_header::read(&slot)?;
            if header.version != v {
                return Err(format!("ledger: entries/{v:010}.bin carries version {}", header.version));
            }
            let split = policy_wire::split(&slot).map_err(|e| format!("ledger: version {v}: {e:?}"))?;
            if let Some(keys_pub) = keys_pub {
                sig::bundle_verify(keys_pub, policy_wire::DOMAIN, split.body(), split.sig_ed25519(), split.sig_mldsa65())
                    .map_err(|e| format!("ledger: version {v}: {e}"))?;
            }
            let body_digest: [u8; 32] = Sha256::digest(split.body()).into();

            match &prev {
                None => {
                    if header.prev_sha256 != [0u8; 32] {
                        return Err("ledger: version 0 must have prev_sha256 = 0".into());
                    }
                }
                Some((prev_header, _)) => {
                    let want = body_sha256(&self.read_entry(v - 1)?)?;
                    if header.prev_sha256 != want {
                        return Err(format!("ledger: version {v}: prev_sha256 does not match version {}'s body (broken chain link)", v - 1));
                    }
                    let _ = prev_header;
                }
            }

            let diff_text = diff::render(prev.as_ref().map(|(h, b)| (h, b.as_slice())), &header, split.body());
            let diff_digest = diff::sha256(&diff_text);

            let approvals = self.read_approvals(v).map_err(|e| format!("ledger: version {v}: {e}"))?;
            let mut approver_ids: Vec<String> = Vec::new();
            for bytes in &approvals {
                let fields = approval::parse_and_verify(bytes, &roster).map_err(|e| format!("ledger: version {v}: {e}"))?;
                if fields.version != v {
                    return Err(format!("ledger: version {v}: an approval is bound to version {}", fields.version));
                }
                if fields.fleet_id != header.fleet_id {
                    return Err(format!("ledger: version {v}: an approval is bound to another fleet_id"));
                }
                if fields.prev_sha256 != header.prev_sha256 {
                    return Err(format!("ledger: version {v}: an approval is bound to another prev_sha256"));
                }
                if fields.body_sha256 != body_digest {
                    return Err(format!("ledger: version {v}: an approval is bound to another body_sha256"));
                }
                if fields.roster_sha256 != header.roster_sha256 {
                    return Err(format!("ledger: version {v}: an approval is bound to another roster_sha256"));
                }
                if fields.diff_sha256 != diff_digest {
                    return Err(format!("ledger: version {v}: an approval is bound to another diff_sha256"));
                }
                if approver_ids.contains(&fields.approver_id) {
                    return Err(format!("ledger: version {v}: the same approver ({}) approved twice", fields.approver_id));
                }
                approver_ids.push(fields.approver_id);
            }
            if approver_ids.len() < 2 {
                return Err(format!("ledger: version {v}: fewer than two valid approvals"));
            }

            let roster_after =
                if header.roster_sha256 == roster.digest() { roster } else { self.load_roster(&header.roster_sha256).map_err(|e| format!("ledger: version {v}: new roster: {e}"))? };
            prev = Some((header, split.body().to_vec()));
            roster = roster_after;
        }
        let (head_header, head_body) = prev.ok_or("ledger: internal: height set but no entries walked")?;
        Ok(ChainState { height: Some(height), head_header: Some(head_header), head_body: Some(head_body), roster })
    }

    /// Appends a freshly signed bundle and the approvals that signed it.
    /// The caller (`sign`) has already verified everything; this only
    /// writes, and refuses a second body for a version that already has
    /// one (no new chain state is computed here — call `verify_chain`
    /// again if needed).
    pub fn append(&self, version: u32, slot: &[u8], approval_files: &[Vec<u8>], roster_before: &Roster, new_roster: Option<&Roster>) -> Result<(), String> {
        if slot.len() != limits::BUNDLE_MAX {
            return Err(format!("sign: slot is {} bytes, expected {}", slot.len(), limits::BUNDLE_MAX));
        }
        self.check_not_signed(version)?;
        if let Some(r) = new_roster {
            self.store_roster(r)?;
        }
        self.write_approvals(version, approval_files, roster_before)?;
        self.write_entry(version, slot)?;
        Ok(())
    }
}

pub struct ChainState {
    pub height: Option<u32>,
    pub head_header: Option<Header>,
    pub head_body: Option<Vec<u8>>,
    /// The roster the *next* version's approvals must verify under.
    pub roster: Roster,
}
