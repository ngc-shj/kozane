//! The peer-policy signing toolchain (M8 plan C2, D11): draft, approve,
//! sign and verify a peer-policy bundle, and keep the two-person-approved
//! ledger that is its signed history.
//!
//!   policy keygen --dir <new dir> [--forbid <path>]...
//!   policy approver-keygen --dir <new dir> [--forbid <path>]...
//!   policy fleet --out <file> --fleet-id <hex32> <gateway.toml>...
//!   policy node-digest --out <file> <gateway.toml>      (the node's NodeConfig digest, as tools/package records it)
//!   policy render --input peers.toml --fleet <file> --ledger <dir> --out draft.bin [--set-roster <file>]
//!   policy diff --ledger <dir> --draft draft.bin
//!   policy rp-digest <rp public key file>                (the digest `diff` prints per peer)
//!   policy approve --ledger <dir> --draft draft.bin --diff-sha256 <hex> --approver-key <file> --approver-id <id> --head <file> [--supersede <earlier approval>] --out A.approval
//!   policy sign --ledger <dir> --draft draft.bin --approvals A B ... --keys <dir> --out slot.bin [--new-roster <file>]
//!   policy verify --keys-pub <dir> --slot slot.bin [--fleet <file> [--package-node <file>]]
//!   policy verify --fleet <file> --package-node <file>
//!   policy verify --ledger <dir> --keys-pub <dir>
//!   policy ledger init --dir <dir> --genesis-roster <roster.toml>
//!   policy ledger approve-restore --from <copy> --keys-pub <dir> --approver-key <file> --approver-id <id> --head <file> [--supersede <earlier approval>] --out R.approval
//!   policy ledger restore --from <copy> --dir <dir> --approvals R1 R2 --keys-pub <dir> --head <file>...
//!   policy roster-digest <roster.toml>                    (prints the hex digest to pin, for operators and fixtures)
//!
//! Keys are dev keys (owner decision, residual RM8-1, as tools/release's
//! RM5-1): `keygen`/`approver-keygen` refuse a directory under any
//! `--forbid` root, create it 0700 and the private key files 0600.
//! The genesis-roster pin is compiled in; no flag bypasses an approval, the
//! roster lookup or the ledger chain (M8 plan C2).

mod approval;
mod diff;
mod fleet;
mod ledger;
mod peers;
mod record;
mod roster;
mod sig;
mod util;
mod wire_header;

// Shared with `config`'s build.rs and `tools/mksecrets`: the `fleet`
// command renders each node's `NodeConfig` through the exact checks the
// image build runs, never a second parser.
// validate.rs is shared with the image build and mksecrets; this tool uses
// only its loader and checks, so the rest is unused here by design.
#[allow(dead_code)]
mod validate {
    include!("../../../crates/config/src/validate.rs");
}

#[cfg(test)]
mod tests;

use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use roster::Roster;

fn arg(args: &[String], name: &str) -> Result<String, String> {
    let i = args.iter().position(|a| a == name).ok_or(format!("missing {name}"))?;
    args.get(i + 1).cloned().ok_or(format!("{name} needs a value"))
}

fn arg_opt(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1).cloned()
}

/// Every value that follows any occurrence of `name`, up to the next
/// `--flag` or the end: covers both `--approvals A B C` and a flag given
/// more than once (`--head f1 --head f2`).
fn arg_list(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            i += 1;
            while i < args.len() && !args[i].starts_with("--") {
                out.push(args[i].clone());
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Positional arguments: everything not consumed as one of `flags`' value.
fn positional(args: &[String], flags: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if flags.contains(&args[i].as_str()) {
            i += 2;
        } else {
            out.push(args[i].clone());
            i += 1;
        }
    }
    out
}

fn hex(b: &[u8]) -> String {
    sig::hex(b)
}

fn write_new(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(path).and_then(|mut f| {
        use std::io::Write;
        f.write_all(data)
    }).map_err(|e| format!("{}: {e}", path.display()))
}

/// A key directory must not resolve under any forbidden root (as
/// `tools/release`'s `keygen`).
fn check_location(dir: &Path, forbid: &[PathBuf]) -> Result<(), String> {
    let parent = dir.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let parent = parent.canonicalize().map_err(|e| format!("{}: {e}", parent.display()))?;
    for root in forbid {
        let root = root.canonicalize().map_err(|e| format!("{}: {e}", root.display()))?;
        if parent.starts_with(&root) {
            return Err(format!("{} is inside {}; keys must live elsewhere", dir.display(), root.display()));
        }
    }
    Ok(())
}

fn forbid_roots(args: &[String]) -> Vec<PathBuf> {
    args.windows(2).filter(|w| w[0] == "--forbid").map(|w| PathBuf::from(&w[1])).collect()
}

/// The decoded file. Both the text and the bytes are wiped on drop: the
/// signing keys pass through here (L12), as in tools/release.
fn read_hex_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let text = Zeroizing::new(fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?);
    sig::unhex(text.trim_end_matches('\n'))
        .map(Zeroizing::new)
        .ok_or(format!("{}: not lowercase hex", path.display()))
}

// --- keygen / approver-keygen -------------------------------------------

fn cmd_keygen(args: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(arg(args, "--dir")?);
    check_location(&dir, &forbid_roots(args))?;
    fs::DirBuilder::new().mode(0o700).create(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let (sk, pk) = sig::bundle_keygen(&mut sig::urandom).map_err(|e| e.to_string())?;
    // The hex text of a private key is wiped once written (L12).
    let ed_hex = Zeroizing::new(format!("{}\n", hex(&sk.ed25519)));
    write_new(&dir.join("ed25519.key"), ed_hex.as_bytes(), 0o600)?;
    let ml_hex = Zeroizing::new(format!("{}\n", hex(sk.ml_dsa.as_ref())));
    write_new(&dir.join("ml-dsa-65.key"), ml_hex.as_bytes(), 0o600)?;
    write_new(&dir.join("ed25519.pub"), format!("{}\n", hex(&pk.ed25519)).as_bytes(), 0o644)?;
    write_new(&dir.join("ml-dsa-65.pub"), format!("{}\n", hex(pk.ml_dsa.as_ref())).as_bytes(), 0o644)?;
    println!("policy: dev bundle-signing keys in {}", dir.display());
    Ok(())
}

fn cmd_approver_keygen(args: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(arg(args, "--dir")?);
    check_location(&dir, &forbid_roots(args))?;
    fs::DirBuilder::new().mode(0o700).create(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let (sk, pk) = sig::approver_keygen(&mut sig::urandom).map_err(|e| e.to_string())?;
    let sk_hex = Zeroizing::new(format!("{}\n", hex(&sk.0)));
    write_new(&dir.join("ed25519.key"), sk_hex.as_bytes(), 0o600)?;
    write_new(&dir.join("ed25519.pub"), format!("{}\n", hex(&pk)).as_bytes(), 0o644)?;
    println!("policy: dev approver key in {}", dir.display());
    Ok(())
}

fn load_bundle_signing(dir: &Path) -> Result<sig::BundleSigningKeys, String> {
    use libcrux_ml_dsa::ml_dsa_65::MLDSA65SigningKey;
    let mut keys = sig::BundleSigningKeys { ed25519: [0; 32], ml_dsa: MLDSA65SigningKey::zero() };
    let ed = read_hex_file(&dir.join("ed25519.key"))?;
    if ed.len() != 32 {
        return Err("ed25519.key: wrong length".into());
    }
    keys.ed25519.copy_from_slice(&ed);
    let ml = read_hex_file(&dir.join("ml-dsa-65.key"))?;
    if ml.len() != MLDSA65SigningKey::len() {
        return Err("ml-dsa-65.key: wrong length".into());
    }
    keys.ml_dsa.as_ref_mut().copy_from_slice(&ml);
    Ok(keys)
}

fn load_bundle_verifying(dir: &Path) -> Result<sig::BundleVerifyingKeys, String> {
    use libcrux_ml_dsa::ml_dsa_65::MLDSA65VerificationKey;
    let ed_bytes = read_hex_file(&dir.join("ed25519.pub"))?;
    if ed_bytes.len() != 32 {
        return Err("ed25519.pub: wrong length".into());
    }
    let mut ed = [0u8; 32];
    ed.copy_from_slice(&ed_bytes);
    let mut ml = MLDSA65VerificationKey::zero();
    let bytes = read_hex_file(&dir.join("ml-dsa-65.pub"))?;
    if bytes.len() != MLDSA65VerificationKey::len() {
        return Err("ml-dsa-65.pub: wrong length".into());
    }
    ml.as_ref_mut().copy_from_slice(&bytes);
    Ok(sig::BundleVerifyingKeys { ed25519: ed, ml_dsa: ml })
}

fn load_approver_signing(path: &Path) -> Result<sig::ApproverSigningKey, String> {
    let b = read_hex_file(path)?;
    if b.len() != 32 {
        return Err(format!("{}: wrong length", path.display()));
    }
    let mut sk = sig::ApproverSigningKey([0u8; 32]);
    sk.0.copy_from_slice(&b);
    Ok(sk)
}

// --- fleet ---------------------------------------------------------------

fn rp_digest(key: &[u8; limits::SPK_LEN]) -> [u8; 32] {
    secret_blob::blake2s(&[key.as_slice()])
}

/// A node's `NodeConfig` from its `gateway.toml`, through the checks the
/// image build runs, named by the file's stem. Its `fleet_id` is
/// `fleet_id` when given (`fleet`), else the file's own `[policy]` one, the
/// value the image compiles in (`node-digest`); the second value says
/// whether the file has a `[policy]` section.
fn load_node(path: &Path, fleet_id: Option<[u8; 16]>) -> Result<(fleet::Node, bool), String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")).to_path_buf();
    let load = |name: &str| -> Result<Vec<u8>, String> { fs::read(dir.join(name)).map_err(|e| format!("{}: {e}", dir.join(name).display())) };
    let raw: validate::RawConfig = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let inside_prefix = validate::parse_prefix(&raw.gateway.inside_prefix).map_err(|e| format!("{}: {e}", path.display()))?;
    let checked = validate::check(&text, &load).map_err(|e| format!("{}: {e}", path.display()))?;
    let node = fleet::Node {
        name: path.file_stem().and_then(|s| s.to_str()).unwrap_or("node").to_string(),
        fleet_id: fleet_id.unwrap_or(checked.fleet_id),
        inside_prefix,
        inside_ip: checked.inside_ip,
        outside_ip: checked.outside_ip,
        neighbors: checked.neighbors.iter().map(|(ip, _)| *ip).collect(),
        gateway_wg_public: checked.gateway_public,
        gateway_rp_digest: checked.gateway_rp.hash,
    };
    Ok((node, raw.policy.is_some()))
}

/// The node digest `tools/package` records next to a package (M8 plan C2):
/// `fleet::node_digest` of the `NodeConfig` the image compiles from this
/// `gateway.toml`, its `[policy]` `fleet_id` included. A file without
/// `[policy]` is refused: its image would refuse every bundle.
fn cmd_node_digest(args: &[String]) -> Result<(), String> {
    let out = PathBuf::from(arg(args, "--out")?);
    let paths = positional(args, &["--out"]);
    let [path] = paths.as_slice() else {
        return Err("node-digest: need exactly one gateway.toml".into());
    };
    let (node, has_policy) = load_node(Path::new(path), None)?;
    if !has_policy {
        return Err(format!("node-digest: {path} has no [policy] section, so its image accepts no bundle"));
    }
    write_new(&out, format!("{}\n", hex(&fleet::node_digest(&node))).as_bytes(), 0o644)?;
    println!("policy: node digest of {path} in {}", out.display());
    Ok(())
}

/// `verify --package-node`: the digest `tools/package` recorded must be one
/// node's of the fleet file, else the fleet file and the package describe
/// different nodes (a stale fleet file, or a package from another
/// `gateway.toml`) and the bundle checked against the fleet proves nothing
/// for that package.
fn check_package_node(fleet: &fleet::Fleet, path: &str) -> Result<(), String> {
    let digest = read_hex_file(Path::new(path))?;
    let digest: [u8; 32] = digest.as_slice().try_into().map_err(|_| format!("{path}: not a 32-byte digest"))?;
    let name = fleet::node_for_digest(fleet, &digest).ok_or_else(|| {
        format!("verify: the package's node digest {} is no node's in the fleet file (a stale fleet file, or a package built from another gateway.toml)", hex(&digest))
    })?;
    println!("policy: the package's node is {name} in the fleet file");
    Ok(())
}

fn cmd_fleet(args: &[String]) -> Result<(), String> {
    let out = PathBuf::from(arg(args, "--out")?);
    let fleet_id = util::hex_n::<16>(&arg(args, "--fleet-id")?, "--fleet-id")?;
    let gateway_paths = positional(args, &["--out", "--fleet-id"]);
    if gateway_paths.is_empty() {
        return Err("fleet: need at least one gateway.toml".into());
    }
    let mut nodes = Vec::new();
    for path in &gateway_paths {
        // A node already provisioned compiles its own `[policy]` fleet_id:
        // stamping another one here would describe an image that refuses
        // every bundle as WrongFleet. A node without `[policy]` (not yet
        // provisioned) takes `--fleet-id`.
        let (own, has_policy) = load_node(Path::new(path), None)?;
        if has_policy && own.fleet_id != fleet_id {
            return Err(format!("fleet: {path}'s [policy] fleet_id {} is not --fleet-id {}", hex(&own.fleet_id), hex(&fleet_id)));
        }
        let (node, _) = load_node(Path::new(path), Some(fleet_id))?;
        if nodes.iter().any(|n: &fleet::Node| n.name == node.name) {
            return Err(format!("fleet: two gateway.toml files both name the node {:?}", node.name));
        }
        nodes.push(node);
    }
    nodes.sort_by_key(|n| n.name.clone());
    let built = fleet::Fleet { fleet_id, nodes };
    write_new(&out, built.render().as_bytes(), 0o644)?;
    println!("policy: fleet of {} node(s) in {}", built.nodes.len(), out.display());
    Ok(())
}

// --- the compiled-in genesis-roster pin ----------------------------------

/// The fleet's genesis-roster digest, compiled in (D11): the tool's own
/// build is what fixes it, so whoever runs the tool cannot swap it.
/// `genesis-roster.sha256` ships as 64 zero hex digits, which no roster
/// hashes to, so every command fails closed until a fleet's genesis
/// ceremony (C12) commits its digest there. The integration and tool tests
/// build their own binary with `KOZANE_POLICY_GENESIS_PIN` set instead: a
/// build-time input, like the file, never a run-time flag.
const GENESIS_PIN_HEX: &str = match option_env!("KOZANE_POLICY_GENESIS_PIN") {
    Some(pin) => pin,
    None => include_str!("../genesis-roster.sha256"),
};

fn read_pin() -> Result<[u8; 32], String> {
    util::hex_n::<32>(GENESIS_PIN_HEX.trim_end_matches('\n'), "the compiled-in genesis-roster pin")
}

// --- render ---------------------------------------------------------------

fn head_body_sha256(slot: &[u8]) -> Result<[u8; 32], String> {
    let u = policy_wire::split(slot).map_err(|e| format!("{e:?}"))?;
    Ok(Sha256::digest(u.body()).into())
}

fn cmd_render(args: &[String]) -> Result<(), String> {
    let input = PathBuf::from(arg(args, "--input")?);
    let fleet_path = PathBuf::from(arg(args, "--fleet")?);
    let ledger_dir = PathBuf::from(arg(args, "--ledger")?);
    let out = PathBuf::from(arg(args, "--out")?);
    let set_roster = arg_opt(args, "--set-roster").map(PathBuf::from);

    let draft = peers::Draft::load(&input)?;
    let fleet = fleet::Fleet::parse(&fs::read_to_string(&fleet_path).map_err(|e| format!("{}: {e}", fleet_path.display()))?)?;
    if draft.fleet_id != fleet.fleet_id {
        return Err("render: peers.toml's fleet_id does not match the fleet file's".into());
    }

    let ledger = ledger::Ledger::open(&ledger_dir);
    let height = ledger.height()?;
    let (version, prev_sha256, current_roster) = match height {
        None => {
            let pinned = read_pin()?;
            (0u32, [0u8; 32], ledger.load_roster(&pinned).map_err(|e| format!("render: genesis roster: {e}"))?)
        }
        Some(h) => {
            let head = ledger.read_entry(h)?;
            let header = wire_header::read(&head)?;
            let roster = ledger.load_roster(&header.roster_sha256).map_err(|e| format!("render: current roster: {e}"))?;
            (h.checked_add(1).ok_or("render: version overflow")?, head_body_sha256(&head)?, roster)
        }
    };
    let roster_sha256 = match &set_roster {
        None => current_roster.digest(),
        Some(p) => {
            let text = fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            Roster::parse(&text)?.digest()
        }
    };

    let mut rp_bufs: Vec<[u8; limits::SPK_LEN]> = Vec::with_capacity(draft.peers.len());
    for p in &draft.peers {
        let mut buf = [0u8; limits::SPK_LEN];
        buf.copy_from_slice(&p.rp_pub);
        rp_bufs.push(buf);
    }
    let plain_peers: Vec<policy_wire::render::PlainPeer<'_>> = draft
        .peers
        .iter()
        .zip(&rp_bufs)
        .map(|(p, rp)| policy_wire::render::PlainPeer { wg_pub: p.wg_pub, rp_pub: rp, groups: p.groups, allowed: &p.allowed })
        .collect();
    let plain_groups: Vec<policy_wire::render::PlainGroup<'_>> = draft.groups.iter().map(|g| policy_wire::render::PlainGroup { rules: &g.rules }).collect();
    let plain = policy_wire::render::PlainBundle {
        fleet_id: draft.fleet_id,
        version,
        min_release: draft.min_release,
        prev_sha256,
        roster_sha256,
        peers: &plain_peers,
        groups: &plain_groups,
        sig_ed25519: [0; 64],
        sig_mldsa65: [0; 3309],
    };
    let slot = policy_wire::render::render(&plain);
    if slot.len() != limits::BUNDLE_MAX {
        return Err(format!("render: internal: rendered {} bytes, expected {}", slot.len(), limits::BUNDLE_MAX));
    }

    for node in &fleet.nodes {
        policy_wire::parse(&slot, &node.as_node_config(), &rp_digest).map_err(|e| format!("render: node {} rejects the draft: {e:?}", node.name))?;
    }

    write_new(&out, &slot, 0o644)?;
    if let Some(p) = &set_roster {
        let sidecar = out.with_extension("roster.toml");
        fs::copy(p, &sidecar).map_err(|e| format!("{}: {e}", sidecar.display()))?;
        println!("policy: new roster saved alongside the draft as {}", sidecar.display());
    }
    println!("policy: draft version {version} written to {}", out.display());
    Ok(())
}

// --- diff -------------------------------------------------------------

/// The ledger head as `diff` needs it: no signature re-verification (the
/// diff is read-only bookkeeping; `sign` is the actual gate).
fn head_for_diff(ledger: &ledger::Ledger) -> Result<Option<(wire_header::Header, Vec<u8>)>, String> {
    let Some(h) = ledger.height()? else { return Ok(None) };
    let slot = ledger.read_entry(h)?;
    let header = wire_header::read(&slot)?;
    let body = policy_wire::split(&slot).map_err(|e| format!("{e:?}"))?.body().to_vec();
    Ok(Some((header, body)))
}

fn compute_diff(ledger: &ledger::Ledger, draft: &[u8]) -> Result<(String, [u8; 32]), String> {
    let header = wire_header::read(draft)?;
    let body = policy_wire::split(draft).map_err(|e| format!("{e:?}"))?.body();
    let old = head_for_diff(ledger)?;
    let text = diff::render(old.as_ref().map(|(h, b)| (h, b.as_slice())), &header, body)?;
    let digest = diff::sha256(&text);
    Ok((text, digest))
}

fn cmd_diff(args: &[String]) -> Result<(), String> {
    let ledger = ledger::Ledger::open(Path::new(&arg(args, "--ledger")?));
    let draft = fs::read(arg(args, "--draft")?).map_err(|e| e.to_string())?;
    let (text, digest) = compute_diff(&ledger, &draft)?;
    print!("{text}");
    println!("diff_sha256={}", hex(&digest));
    Ok(())
}

// --- approve ------------------------------------------------------------

/// An approver's head file (D11): the newest ledger head they verified
/// (absent before the ledger has one), and the last version and body they
/// approved, which a truncated ledger can drop.
struct HeadFile {
    ledger: Option<(u32, [u8; 32])>,
    approved: Option<(u32, [u8; 32])>,
}

const HEAD_KEYS: [&str; 4] = ["approved_body_sha256", "approved_version", "body_sha256", "version"];

/// `-` for both fields is "none yet" (every key is always written).
fn head_pair(fields: &[(String, String)], version: &str, digest: &str) -> Result<Option<(u32, [u8; 32])>, String> {
    match (record::get(fields, version), record::get(fields, digest)) {
        (Some("-"), Some("-")) => Ok(None),
        (Some(v), Some(d)) if v != "-" && d != "-" => Ok(Some((
            v.parse().map_err(|_| format!("head file: bad {version}"))?,
            util::hex_n::<32>(d, &format!("head file: {digest}"))?,
        ))),
        _ => Err(format!("head file: {version} and {digest} must be both set or both -")),
    }
}

fn read_head_file(path: &Path) -> Result<Option<HeadFile>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let fields = record::parse(&bytes, &HEAD_KEYS).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Some(HeadFile {
        ledger: head_pair(&fields, "version", "body_sha256")?,
        approved: head_pair(&fields, "approved_version", "approved_body_sha256")?,
    }))
}

/// The approver's checks against `ledger` (D11), on their own device: the
/// ledger holds their recorded head unchanged, and holds the version they
/// last approved with the body they approved. A version the ledger lacks,
/// or holds with another body, was either cut off this ledger or abandoned
/// (or superseded by another draft); only the approver can say which, by
/// handing back their own approval of it (`--supersede`).
/// `Ok(true)` when the last approval was handed back (`--supersede`).
/// `draft` is the version and body being approved now (`approve`): the same
/// one approved again (a lost approval file) needs nothing handed back.
fn check_head(
    what: &str,
    ledger: &ledger::Ledger,
    state: &ledger::ChainState,
    head: Option<&HeadFile>,
    approver_id: &str,
    draft: Option<(u32, [u8; 32])>,
    supersede: Option<&str>,
) -> Result<bool, String> {
    let needed = check_head_needs(what, ledger, state, head, draft)?;
    match (needed, supersede) {
        (None, None) => Ok(false),
        (None, Some(path)) => Err(format!("{what}: --supersede {path} given, but nothing recorded needs superseding")),
        (Some(why), None) => Err(why),
        (Some(_), Some(path)) => {
            let Some((approved_version, approved_body)) = head.and_then(|h| h.approved) else {
                return Err(format!("{what}: internal: nothing to supersede"));
            };
            let bytes = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
            let earlier = approval::parse_and_verify(&bytes, &state.roster).map_err(|e| format!("{what}: --supersede {path}: {e}"))?;
            if earlier.approver_id != approver_id || earlier.version != approved_version || earlier.body_sha256 != approved_body {
                return Err(format!("{what}: --supersede {path} is not your approval of version {approved_version} recorded in the head file"));
            }
            println!("policy: superseding your approval of version {approved_version} ({})", hex(&approved_body));
            Ok(true)
        }
    }
}

/// `Ok(Some(why))` when the last approval must be handed back to go on.
fn check_head_needs(what: &str, ledger: &ledger::Ledger, state: &ledger::ChainState, head: Option<&HeadFile>, draft: Option<(u32, [u8; 32])>) -> Result<Option<String>, String> {
    let Some(head) = head else { return Ok(None) };
    if let Some((recorded_version, recorded_digest)) = head.ledger {
        match state.height {
            None => return Err(format!("{what}: the ledger is empty, behind this approver's recorded head (version {recorded_version})")),
            Some(h) if h < recorded_version => {
                return Err(format!("{what}: the ledger (height {h}) is behind this approver's recorded head (version {recorded_version})"));
            }
            _ => {}
        }
        if head_body_sha256(&ledger.read_entry(recorded_version)?)? != recorded_digest {
            return Err(format!(
                "{what}: the ledger's version {recorded_version} digest does not match this approver's recorded head (tampered or forked ledger)"
            ));
        }
    }
    let Some((approved_version, approved_body)) = head.approved else { return Ok(None) };
    let held = match state.height {
        Some(h) if h >= approved_version => Some(head_body_sha256(&ledger.read_entry(approved_version)?)?),
        _ => None,
    };
    if held == Some(approved_body) || (held.is_none() && draft == Some((approved_version, approved_body))) {
        return Ok(None);
    }
    let why = match held {
        None => "which this ledger does not hold: if it was signed, this ledger is truncated",
        Some(_) => "and this ledger holds another body at that version: if yours was signed, this ledger is forked",
    };
    Ok(Some(format!(
        "{what}: you approved version {approved_version} (body {}), {why}; if it was abandoned, pass that approval with --supersede <file>",
        hex(&approved_body)
    )))
}

/// `out` is created first (refused if it exists), then `before` moves the
/// approver's head, then the record lands in the file already reserved: a
/// head never records an approval whose file could not be created, and a
/// failed head write leaves no approval behind; a failed record write
/// removes the partial file.
fn write_reserved(out: &Path, record: &[u8], before: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
    use std::io::Write;
    let err = |e: std::io::Error| format!("{}: {e}", out.display());
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o644).open(out).map_err(err)?;
    if let Err(e) = before() {
        drop(f);
        let _ = fs::remove_file(out);
        return Err(e);
    }
    f.write_all(record).and_then(|()| f.sync_all()).map_err(|e| {
        drop(f);
        let _ = fs::remove_file(out);
        format!("{}: {e} (the head already records this approval: approve the same draft again to write it)", out.display())
    })
}

/// Written to a temporary file, synced and renamed into place, so a crash
/// leaves the old head or the new one, never a torn file.
fn write_head_file(path: &Path, head: &HeadFile) -> Result<(), String> {
    let pair = |p: Option<(u32, [u8; 32])>| p.map_or(("-".to_string(), "-".to_string()), |(v, d)| (v.to_string(), hex(&d)));
    let (version, body) = pair(head.ledger);
    let (approved_version, approved_body) = pair(head.approved);
    let pairs = [
        ("version", version),
        ("body_sha256", body),
        ("approved_version", approved_version),
        ("approved_body_sha256", approved_body),
    ];
    let refs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    use std::io::Write;
    let tmp = path.with_extension("head.tmp");
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    let mut f = fs::File::create(&tmp).map_err(err)?;
    f.write_all(&record::render(&refs, &HEAD_KEYS)).map_err(err)?;
    f.sync_all().map_err(err)?;
    fs::rename(&tmp, path).map_err(err)
}

fn cmd_approve(args: &[String]) -> Result<(), String> {
    let ledger = ledger::Ledger::open(Path::new(&arg(args, "--ledger")?));
    let draft = fs::read(arg(args, "--draft")?).map_err(|e| e.to_string())?;
    let approver_key_path = arg(args, "--approver-key")?;
    let approver_id = arg(args, "--approver-id")?;
    let out = PathBuf::from(arg(args, "--out")?);
    // Required (D11): an approver without a head file checks nothing
    // against truncation or forks. A missing *file* is a first approval or
    // a wiped device starting over (runbook).
    let head_path = PathBuf::from(arg(args, "--head")?);

    let pinned = read_pin()?;
    let state = ledger.verify_chain_unsigned(pinned)?;

    let recorded = read_head_file(&head_path)?;

    let header = wire_header::read(&draft)?;
    let body = policy_wire::split(&draft).map_err(|e| format!("{e:?}"))?.body();
    let body_sha256: [u8; 32] = Sha256::digest(body).into();
    check_head(
        "approve",
        &ledger,
        &state,
        recorded.as_ref(),
        &approver_id,
        Some((header.version, body_sha256)),
        arg_opt(args, "--supersede").as_deref(),
    )?;
    let old = head_for_diff(&ledger)?;
    let diff_text = diff::render(old.as_ref().map(|(h, b)| (h, b.as_slice())), &header, body)?;
    let diff_sha256 = diff::sha256(&diff_text);
    // The approver names the diff they reviewed (`policy diff`'s last
    // line), so what they read and the draft they approve are one (S8).
    print!("{diff_text}");
    let reviewed = util::hex_n::<32>(&arg(args, "--diff-sha256")?, "approve: --diff-sha256")?;
    if reviewed != diff_sha256 {
        return Err(format!(
            "approve: --diff-sha256 {} is not this draft's diff against this ledger ({}): review `policy diff` again",
            hex(&reviewed),
            hex(&diff_sha256)
        ));
    }

    let sk = load_approver_signing(Path::new(&approver_key_path))?;
    let fields = approval::ApprovalFields {
        approver_id: approver_id.clone(),
        body_sha256,
        diff_sha256,
        fleet_id: header.fleet_id,
        prev_sha256: header.prev_sha256,
        roster_sha256: header.roster_sha256,
        ts: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        version: header.version,
    };
    let record = approval::sign(&sk, &fields, &mut sig::urandom)?;
    // The head is the verified ledger's, never the draft's: a draft that is
    // never signed must not move it, or this approver is refused every
    // later ledger at the height it was drafted against. The approval is
    // recorded beside it before the approval exists, so no approval ever
    // goes out unrecorded.
    let ledger_head = state.height.zip(state.head_body.as_ref().map(|b| Sha256::digest(b).into()));
    write_reserved(&out, &record, || write_head_file(&head_path, &HeadFile { ledger: ledger_head, approved: Some((header.version, body_sha256)) }))?;
    println!("policy: {approver_id} approved version {} ({})", header.version, out.display());
    Ok(())
}

// --- sign -----------------------------------------------------------------

fn cmd_sign(args: &[String]) -> Result<(), String> {
    let ledger = ledger::Ledger::open(Path::new(&arg(args, "--ledger")?));
    let draft = fs::read(arg(args, "--draft")?).map_err(|e| e.to_string())?;
    if draft.len() != limits::BUNDLE_MAX {
        return Err(format!("sign: draft is {} bytes, expected {}", draft.len(), limits::BUNDLE_MAX));
    }
    let approval_paths = arg_list(args, "--approvals");
    if approval_paths.len() < 2 {
        return Err("sign: at least two --approvals are required".into());
    }
    let keys_dir = PathBuf::from(arg(args, "--keys")?);
    let out = PathBuf::from(arg(args, "--out")?);
    let new_roster_path = arg_opt(args, "--new-roster").map(PathBuf::from);

    let header = wire_header::read(&draft)?;
    let pinned = read_pin()?;
    let keys_pub = load_bundle_verifying(&keys_dir)?;
    let state = ledger.verify_chain(&keys_pub, pinned)?;

    let next_version = match state.height {
        None => 0u32,
        Some(h) => h.checked_add(1).ok_or("sign: version overflow")?,
    };
    if header.version != next_version {
        return Err(format!("sign: draft version {} does not match the ledger head+1 ({next_version})", header.version));
    }
    let expected_prev = match &state.head_body {
        None => [0u8; 32],
        Some(b) => Sha256::digest(b).into(),
    };
    if header.prev_sha256 != expected_prev {
        return Err("sign: the draft's prev_sha256 is not the ledger head's body".into());
    }

    let new_roster = if header.roster_sha256 == state.roster.digest() {
        if new_roster_path.is_some() {
            return Err("sign: --new-roster was given but the draft does not change roster_sha256".into());
        }
        None
    } else {
        let p = new_roster_path.ok_or("sign: the draft changes roster_sha256 but no --new-roster was given")?;
        let text = fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        let nr = Roster::parse(&text)?;
        if nr.digest() != header.roster_sha256 {
            return Err("sign: --new-roster does not hash to the draft's roster_sha256".into());
        }
        Some(nr)
    };

    let body = policy_wire::split(&draft).map_err(|e| format!("{e:?}"))?.body();
    let body_sha256: [u8; 32] = Sha256::digest(body).into();
    let old = state.head_header.as_ref().zip(state.head_body.as_ref());
    let diff_text = diff::render(old.map(|(h, b)| (h, b.as_slice())), &header, body)?;
    let diff_sha256 = diff::sha256(&diff_text);

    let mut approval_bytes = Vec::new();
    let mut approver_ids = Vec::new();
    for path in &approval_paths {
        let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path))?;
        let fields = approval::parse_and_verify(&bytes, &state.roster).map_err(|e| format!("sign: {path}: {e}"))?;
        if fields.version != header.version {
            return Err(format!("sign: {path}: approval is bound to version {}, draft is version {}", fields.version, header.version));
        }
        if fields.fleet_id != header.fleet_id {
            return Err(format!("sign: {path}: approval is bound to another fleet_id"));
        }
        if fields.prev_sha256 != header.prev_sha256 {
            return Err(format!("sign: {path}: approval is bound to another prev_sha256"));
        }
        if fields.roster_sha256 != header.roster_sha256 {
            return Err(format!("sign: {path}: approval is bound to another roster_sha256"));
        }
        if fields.body_sha256 != body_sha256 {
            return Err(format!("sign: {path}: approval is bound to another body (the draft changed after approval)"));
        }
        if fields.diff_sha256 != diff_sha256 {
            return Err(format!("sign: {path}: approval is bound to another diff"));
        }
        if approver_ids.contains(&fields.approver_id) {
            return Err(format!("sign: approver {} approved twice", fields.approver_id));
        }
        approver_ids.push(fields.approver_id);
        approval_bytes.push(bytes);
    }
    if approver_ids.len() < 2 {
        return Err("sign: at least two distinct roster entries must approve".into());
    }

    let signing = load_bundle_signing(&keys_dir)?;
    let sig_start = body.len();
    let (sig_ed, sig_ml) = sig::bundle_sign(&signing, policy_wire::DOMAIN, body, &mut sig::urandom).map_err(|e| e.to_string())?;
    let mut slot = draft.clone();
    slot.get_mut(sig_start..sig_start + 64).ok_or("sign: internal: slot too short for sig_ed25519")?.copy_from_slice(&sig_ed);
    slot.get_mut(sig_start + 64..sig_start + 64 + 3309).ok_or("sign: internal: slot too short for sig_mldsa65")?.copy_from_slice(&sig_ml);

    ledger.append(header.version, &slot, &approval_bytes, &state.roster, new_roster.as_ref())?;
    write_new(&out, &slot, 0o644)?;
    println!("policy: signed version {} ({})", header.version, out.display());
    Ok(())
}

// --- verify ---------------------------------------------------------------

fn cmd_verify(args: &[String]) -> Result<(), String> {
    if let Some(slot_path) = arg_opt(args, "--slot") {
        let keys_pub = load_bundle_verifying(Path::new(&arg(args, "--keys-pub")?))?;
        let slot = fs::read(&slot_path).map_err(|e| format!("{slot_path}: {e}"))?;
        if slot.len() != limits::BUNDLE_MAX {
            return Err(format!("verify: slot is {} bytes, expected {}", slot.len(), limits::BUNDLE_MAX));
        }
        let split = policy_wire::split(&slot).map_err(|e| format!("verify: {e:?}"))?;
        sig::bundle_verify(&keys_pub, policy_wire::DOMAIN, split.body(), split.sig_ed25519(), split.sig_mldsa65()).map_err(|e| format!("verify: {e}"))?;
        let header = wire_header::read(&slot)?;
        if let Some(fleet_path) = arg_opt(args, "--fleet") {
            let fleet = fleet::Fleet::parse(&fs::read_to_string(&fleet_path).map_err(|e| format!("{fleet_path}: {e}"))?)?;
            for node in &fleet.nodes {
                policy_wire::parse(&slot, &node.as_node_config(), &rp_digest).map_err(|e| format!("verify: node {} rejects the slot: {e:?}", node.name))?;
            }
            if let Some(path) = arg_opt(args, "--package-node") {
                check_package_node(&fleet, &path)?;
            }
        } else if arg_opt(args, "--package-node").is_some() {
            return Err("verify: --package-node needs --fleet".into());
        }
        println!("policy: both signatures verify; version={} min_release={} peer_count={}", header.version, header.min_release, header.peer_count);
        return Ok(());
    }
    if let Some(dir) = arg_opt(args, "--ledger") {
        let ledger = ledger::Ledger::open(Path::new(&dir));
        let keys_pub = load_bundle_verifying(Path::new(&arg(args, "--keys-pub")?))?;
        let pinned = read_pin()?;
        let state = ledger.verify_chain(&keys_pub, pinned)?;
        match state.height {
            None => println!("policy: ledger verifies (genesis, empty)"),
            Some(h) => println!("policy: ledger verifies up to version {h}"),
        }
        return Ok(());
    }
    if let (Some(fleet_path), Some(path)) = (arg_opt(args, "--fleet"), arg_opt(args, "--package-node")) {
        let fleet = fleet::Fleet::parse(&fs::read_to_string(&fleet_path).map_err(|e| format!("{fleet_path}: {e}"))?)?;
        return check_package_node(&fleet, &path);
    }
    Err("verify: need --slot, --ledger, or --fleet with --package-node".into())
}

// --- ledger init / restore -----------------------------------------------

fn cmd_ledger(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("init") => {
            let dir = PathBuf::from(arg(&args[1..], "--dir")?);
            let roster_path = arg(&args[1..], "--genesis-roster")?;
            let pinned = read_pin()?;
            let text = fs::read_to_string(&roster_path).map_err(|e| format!("{roster_path}: {e}"))?;
            let genesis_roster = Roster::parse(&text)?;
            ledger::Ledger::init(&dir, &genesis_roster, pinned)?;
            println!("policy: ledger initialised at {}", dir.display());
            Ok(())
        }
        // Not in the plan's literal command list, which only says restore
        // approvals exist (D11); something has to produce them for an
        // approver to hand to `ledger restore`, so this is that signer,
        // built the same way `approve` signs a bundle approval.
        Some("approve-restore") => {
            let args = &args[1..];
            let from = PathBuf::from(arg(args, "--from")?);
            let approver_key_path = arg(args, "--approver-key")?;
            let approver_id = arg(args, "--approver-id")?;
            let out = PathBuf::from(arg(args, "--out")?);
            let pinned = read_pin()?;

            // With the bundle signatures (S5-1): this moves the approver's
            // head, so the copy must be one `restore` itself would accept.
            let keys_pub = load_bundle_verifying(Path::new(&arg(args, "--keys-pub")?))?;
            let copy = ledger::Ledger::open(&from);
            let state = copy
                .verify_chain(&keys_pub, pinned)
                .map_err(|e| format!("ledger approve-restore: the copy's chain does not verify: {e}"))?;
            let Some(version) = state.height else {
                return Err("ledger approve-restore: the copy is empty; nothing to restore".into());
            };
            // The approver's own head, on their own device (D11): the copy
            // holds their head and their last approval, or they hand that
            // approval back. The restore operator holds no say in it. An
            // approver without a head file has nothing to check the copy
            // against, so cannot vouch for it.
            let head_path = PathBuf::from(arg(args, "--head")?);
            let head = read_head_file(&head_path)?
                .filter(|h| h.ledger.is_some() || h.approved.is_some())
                .ok_or_else(|| {
                    format!(
                        "ledger approve-restore: no head recorded at {}: an approver without one cannot vouch for a restore",
                        head_path.display()
                    )
                })?;
            let superseded =
                check_head("ledger approve-restore", &copy, &state, Some(&head), &approver_id, None, arg_opt(args, "--supersede").as_deref())?;
            let head_body_sha256: [u8; 32] = Sha256::digest(state.head_body.as_ref().ok_or("ledger approve-restore: internal")?).into();
            // The head moves only for a handed-back approval, and only that
            // half: the copy may never be restored, so its ledger head is not
            // recorded (the next `approve` on the restored ledger does that).
            let new_head = HeadFile { ledger: head.ledger, approved: if superseded { None } else { head.approved } };
            let fleet_id = state.head_header.as_ref().ok_or("ledger approve-restore: internal")?.fleet_id;

            let sk = load_approver_signing(Path::new(&approver_key_path))?;
            let fields = approval::RestoreFields {
                approver_id: approver_id.clone(),
                fleet_id,
                head_body_sha256,
                head_version: version,
                ts: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            };
            let record = approval::sign_restore(&sk, &fields, &mut sig::urandom)?;
            write_reserved(&out, &record, || write_head_file(&head_path, &new_head))?;
            println!("policy: {approver_id} approved restoring head version {version} ({})", out.display());
            Ok(())
        }
        Some("restore") => {
            let args = &args[1..];
            let from = PathBuf::from(arg(args, "--from")?);
            let dir = PathBuf::from(arg(args, "--dir")?);
            let approval_paths = arg_list(args, "--approvals");
            let head_paths = arg_list(args, "--head");
            let keys_pub = load_bundle_verifying(Path::new(&arg(args, "--keys-pub")?))?;
            let pinned = read_pin()?;

            let copy = ledger::Ledger::open(&from);
            let state = copy.verify_chain(&keys_pub, pinned).map_err(|e| format!("ledger restore: the copy's chain does not verify: {e}"))?;
            let Some(restored_version) = state.height else {
                return Err("ledger restore: the copy is empty; nothing to restore".into());
            };
            let restored_body_sha256: [u8; 32] = Sha256::digest(state.head_body.as_ref().ok_or("ledger restore: internal")?).into();
            let fleet_id = state.head_header.as_ref().ok_or("ledger restore: internal")?.fleet_id;

            // Every head it is given, ledger head and last approval both,
            // fail-closed (D11): an approver whose approval the copy lacks
            // either restores through `approve-restore --supersede` on their
            // own device (which rewrites their head) or is refused here.
            // Which heads are passed is the operator's choice (D-24 residual).
            for head_path in &head_paths {
                let head = read_head_file(Path::new(head_path))?.ok_or_else(|| format!("ledger restore: no head file at {head_path}"))?;
                if let Some((recorded_version, recorded_digest)) = head.ledger {
                    if restored_version < recorded_version {
                        return Err(format!("ledger restore: the copy (version {restored_version}) is behind the head in {head_path} (version {recorded_version})"));
                    }
                    if head_body_sha256(&copy.read_entry(recorded_version)?)? != recorded_digest {
                        return Err(format!("ledger restore: the copy's version {recorded_version} does not match the head in {head_path} (contains or extends, never diverges)"));
                    }
                }
                if let Some((approved_version, approved_body)) = head.approved {
                    if restored_version < approved_version {
                        return Err(format!(
                            "ledger restore: {head_path} records an approval of version {approved_version}, which the copy (version {restored_version}) does not hold: if it was signed, the copy is truncated"
                        ));
                    }
                    if head_body_sha256(&copy.read_entry(approved_version)?)? != approved_body {
                        return Err(format!(
                            "ledger restore: {head_path} records an approval of version {approved_version} with another body than the copy's: if it was signed, the copy is forked"
                        ));
                    }
                }
            }

            if approval_paths.len() < 2 {
                return Err("ledger restore: at least two --approvals are required".into());
            }
            let mut approver_ids = Vec::new();
            let mut approval_bytes = Vec::new();
            for path in &approval_paths {
                let bytes = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
                let fields = approval::parse_and_verify_restore(&bytes, &state.roster).map_err(|e| format!("ledger restore: {path}: {e}"))?;
                if fields.head_version != restored_version {
                    return Err(format!("ledger restore: {path}: bound to head version {}, not {restored_version}", fields.head_version));
                }
                // The fleet first: another fleet's head differs in its body
                // too, and this order keeps the fleet binding observable.
                if fields.fleet_id != fleet_id {
                    return Err(format!("ledger restore: {path}: bound to another fleet_id"));
                }
                if fields.head_body_sha256 != restored_body_sha256 {
                    return Err(format!("ledger restore: {path}: bound to another head digest"));
                }
                if approver_ids.contains(&fields.approver_id) {
                    return Err(format!("ledger restore: approver {} approved twice", fields.approver_id));
                }
                approver_ids.push(fields.approver_id);
                approval_bytes.push(bytes);
            }
            if approver_ids.len() < 2 {
                return Err("ledger restore: at least two distinct roster entries must approve the restore".into());
            }

            if dir.exists() {
                return Err(format!("ledger restore: {} already exists", dir.display()));
            }
            copy_ledger_tree(&from, &dir)?;
            let restore_dir = dir.join("restore-approvals");
            fs::create_dir_all(&restore_dir).map_err(|e| e.to_string())?;
            for (i, bytes) in approval_bytes.iter().enumerate() {
                fs::write(restore_dir.join(format!("{i}.approval")), bytes).map_err(|e| e.to_string())?;
            }
            println!("policy: ledger restored to {} (version {restored_version})", dir.display());
            Ok(())
        }
        _ => Err("usage: policy ledger init|restore ...".into()),
    }
}

/// Copies the known ledger layout (`entries/`, `roster/`, `approvals/`,
/// the pin file) from a verified copy into a fresh directory.
fn copy_ledger_tree(from: &Path, to: &Path) -> Result<(), String> {
    fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(to)?;
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            let dest = to.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_dir(&entry.path(), &dest)?;
            } else {
                std::fs::copy(entry.path(), &dest)?;
            }
        }
        Ok(())
    }
    std::fs::create_dir_all(to).map_err(|e| format!("{}: {e}", to.display()))?;
    for name in ["entries", "roster", "approvals"] {
        let src = from.join(name);
        if src.is_dir() {
            copy_dir(&src, &to.join(name)).map_err(|e| format!("{}: {e}", src.display()))?;
        }
    }
    let pin = from.join("genesis-roster.sha256");
    if pin.exists() {
        std::fs::copy(&pin, to.join("genesis-roster.sha256")).map_err(|e| format!("{}: {e}", pin.display()))?;
    }
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("keygen") => cmd_keygen(&args[1..]),
        Some("approver-keygen") => cmd_approver_keygen(&args[1..]),
        Some("fleet") => cmd_fleet(&args[1..]),
        Some("node-digest") => cmd_node_digest(&args[1..]),
        Some("render") => cmd_render(&args[1..]),
        Some("diff") => cmd_diff(&args[1..]),
        // The rp key digest `diff` prints per peer, for checking it against
        // the peer's own key file.
        Some("rp-digest") => {
            let path = args.get(1).ok_or("usage: policy rp-digest <rp public key file>")?;
            let bytes = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
            let key: &[u8; limits::SPK_LEN] =
                bytes.as_slice().try_into().map_err(|_| format!("{path}: not {} bytes", limits::SPK_LEN))?;
            println!("{}", hex(&rp_digest(key)));
            Ok(())
        }
        Some("approve") => cmd_approve(&args[1..]),
        Some("sign") => cmd_sign(&args[1..]),
        Some("verify") => cmd_verify(&args[1..]),
        Some("ledger") => cmd_ledger(&args[1..]),
        // Not a signing or verification step, just a convenience so a
        // caller (an operator, or the fixture harness) can learn a
        // roster's digest to pin without re-implementing the hash.
        Some("roster-digest") => {
            let path = args.get(1).ok_or("usage: policy roster-digest <roster.toml>")?;
            let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            println!("{}", hex(&Roster::parse(&text)?.digest()));
            Ok(())
        }
        _ => Err("usage: policy keygen|approver-keygen|fleet|node-digest|render|diff|rp-digest|approve|sign|verify|ledger|roster-digest ...".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("policy: {e}");
            ExitCode::FAILURE
        }
    }
}
