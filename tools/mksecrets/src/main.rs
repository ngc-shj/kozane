//! Generates a development deployment (plan C16, M3 plan C6, M6 plan C11):
//! fresh gateway and peer keys, a gateway config for the build
//! (SECUREOS_CONFIG) with the McEliece public key files it names, both
//! secrets regions for `make package` (`secrets.bin` for `key`,
//! `pqkey-secrets.bin` for `pqkey`), and per peer a client bundle: a wg(8)
//! config without a PresharedKey (the PSK comes from Rosenpass, L8), a
//! rosenpass(1) config and the peer's McEliece keypair, the secret key in
//! the liboqs layout upstream rosenpass reads.
//!
//! For HTTPS, in the plan's order: a fresh P-256 scalar goes into the key
//! blob (v3) and its public key into `tls.pub` (PEM); tools/mkcert issues
//! a dev CA (`devca.pem`, its key never written) and the leaf (`tls.der`);
//! the config names the leaf and `tls_public`, and is validated last.
//!
//! Usage: mksecrets --template config/gateway.toml --peers N --out DIR
//!                  [--endpoint HOST:PORT] [--rp-endpoint HOST:PORT]
//!                  [--tls-name NAME] [--test-negative] [--tls-mismatch-blob]
//!
//! The Rosenpass endpoint defaults to the WireGuard endpoint's host with the
//! template's `rp_port`. NAME, the HTTPS server's name, defaults to the
//! template's `outside_ip` (mkcert's IP mode). --test-negative also writes
//! mkcert's negative leaves; --tls-mismatch-blob also writes
//! `secrets-tls-mismatch.bin`, this deployment's blob with another TLS
//! scalar (the TLS-only key failure case, M6 plan D5).
//!
//! `mksecrets seal` seals one of those blobs offline into its envelope (M5
//! plan C11) for one TPM and one expected PCR 8:
//!
//!   mksecrets seal --kind key|pq --blob FILE --srk-public FILE --pcr8 HEX --out FILE
//!
//! The SRK public is the TPM2B_PUBLIC `tpm2_readpublic -o` writes for the
//! SRK (the storage template `tpm2::envelope` pins); PCR 8 is the hex value
//! `tools/package` writes to `pcr8`. Every envelope gets a fresh KEK,
//! obfuscation seed and ECDH scalar from /dev/urandom (S13). The envelope
//! is public; OUT must not exist yet.
//!
//! DIR must not exist yet and, after resolving symlinks, must lie outside
//! the repository and the toolchain caches, so secrets never land where a
//! commit, a build artefact or a cache volume could pick them up.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use secret_blob::pq;
use tpm2::Secret;
use tpm2::envelope::{Kind, SEAL_ENTROPY_LEN};

// Shared with the config build script; only the parsers and `check` are used here.
#[allow(dead_code)]
mod validate {
    include!("../../../crates/config/src/validate.rs");
}

#[cfg(test)]
mod tests;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn encode_key(k: &[u8; 32]) -> String {
    let mut s = String::with_capacity(44);
    for chunk in k.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                s.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
            } else {
                s.push('=');
            }
        }
    }
    s
}

struct KeyPair {
    private: [u8; 32],
    public: [u8; 32],
}

fn random32() -> Result<[u8; 32], String> {
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| format!("/dev/urandom: {e}"))?;
    Ok(b)
}

/// A P-256 scalar (big-endian) from /dev/urandom and its uncompressed
/// point. A draw that is zero or not below the order (≈ 2^-32) is redrawn.
fn p256_keypair() -> Result<(Secret<32>, [u8; validate::TLS_PUBLIC_LEN]), String> {
    for _ in 0..8 {
        let mut scalar = Secret::<32>::zero();
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(scalar.as_mut_bytes()))
            .map_err(|e| format!("/dev/urandom: {e}"))?;
        if let Some(xy) = tpm2::crypto::public_point(&scalar) {
            let mut public = [0x04; validate::TLS_PUBLIC_LEN];
            public[1..].copy_from_slice(&xy);
            return Ok((scalar, public));
        }
    }
    Err("/dev/urandom gave no valid P-256 scalar in 8 draws".into())
}

/// RFC 4648 base64 with padding.
fn base64(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                s.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// The point as a PEM SubjectPublicKeyInfo (`tls.pub`, mkcert's input).
fn public_key_pem(public: &[u8; validate::TLS_PUBLIC_LEN]) -> String {
    let mut der = validate::P256_SPKI_PREFIX.to_vec();
    der.extend_from_slice(public);
    let b64 = base64(&der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for line in b64.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(line));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

/// Issues the certificates for `tls.pub` (PEM) and NAME: the files mkcert
/// writes, by name. Tests stand in for mkcert.
type Issue<'a> = &'a dyn Fn(&str, &str, bool) -> Result<Vec<(String, Vec<u8>)>, String>;

/// tools/mkcert, run in a private scratch directory that is removed again:
/// it holds only public material (the CA key never leaves mkcert).
fn mkcert_issue(public_pem: &str, name: &str, negative: bool) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut token = [0u8; 8];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut token))
        .map_err(|e| format!("/dev/urandom: {e}"))?;
    let token: String = token.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("mksecrets-mkcert-{token}"));
    std::fs::DirBuilder::new().mode(0o700).create(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let issued = mkcert_in(&dir, public_pem, name, negative);
    let removed = std::fs::remove_dir_all(&dir).map_err(|e| format!("cannot remove {}: {e}", dir.display()));
    let files = issued?;
    removed?;
    Ok(files)
}

fn mkcert_in(dir: &Path, public_pem: &str, name: &str, negative: bool) -> Result<Vec<(String, Vec<u8>)>, String> {
    let tool = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tools/mkcert");
    let public = dir.join("tls.pub");
    std::fs::write(&public, public_pem).map_err(|e| format!("{}: {e}", public.display()))?;
    let out = dir.join("out");
    std::fs::create_dir(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let mut cmd = std::process::Command::new("python3");
    cmd.arg(&tool).arg("--public").arg(&public).arg("--name").arg(name).arg("--out").arg(&out);
    if negative {
        cmd.arg("--test-negative");
    }
    let r = cmd.output().map_err(|e| format!("cannot run {}: {e}", tool.display()))?;
    if !r.status.success() {
        return Err(format!("tools/mkcert failed: {}", String::from_utf8_lossy(&r.stderr).trim()));
    }
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&out).map_err(|e| format!("{}: {e}", out.display()))? {
        let entry = entry.map_err(|e| format!("{}: {e}", out.display()))?;
        let name = entry.file_name().into_string().map_err(|n| format!("mkcert wrote {n:?}"))?;
        if !MKCERT_FILES.contains(&name.as_str()) {
            return Err(format!("tools/mkcert wrote an unexpected file {name:?}"));
        }
        files.push((name, std::fs::read(entry.path()).map_err(|e| format!("{}: {e}", entry.path().display()))?));
    }
    files.sort();
    Ok(files)
}

/// The HTTPS server's certificate options (M6 plan C11).
struct TlsOptions<'a> {
    /// The server's name; None: the template's `outside_ip`.
    name: Option<&'a str>,
    /// Also issue mkcert's negative leaves.
    negative: bool,
    /// Also write this deployment's blob with another TLS scalar.
    mismatch_blob: bool,
    issue: Issue<'a>,
}

/// The certificate files the config and the integration harness name.
const TLS_CERT: &str = "tls.der";
const TLS_PUB: &str = "tls.pub";
/// Everything mkcert may write (tools/mkcert OUTPUTS and NEGATIVES).
const MKCERT_FILES: [&str; 4] = ["devca.pem", TLS_CERT, "negative-name.der", "negative-form.der"];

fn keypair() -> Result<KeyPair, String> {
    let mut private = random32()?;
    libcrux_curve25519::clamp(&mut private);
    let mut public = [0u8; 32];
    libcrux_curve25519::secret_to_public(&mut public, &private);
    Ok(KeyPair { private, public })
}

/// /dev/urandom as the McEliece keygen and encapsulation RNG. Unlike
/// `rand_core::RngCore::fill_bytes`, `mce460896`'s closures can report a
/// failed read, so a short read surfaces as an immediate `RngError`.
struct Urandom(std::fs::File);

impl Urandom {
    fn open() -> Result<Self, String> {
        std::fs::File::open("/dev/urandom").map(Urandom).map_err(|e| format!("/dev/urandom: {e}"))
    }

    fn fill(&mut self, out: &mut [u8]) -> Result<(), mce460896::RngError> {
        self.0.read_exact(out).map_err(|_| mce460896::RngError)
    }
}

/// A zeroed heap array, never built on the stack (McEliece keys are large).
fn zeroed<const N: usize>() -> Result<Box<[u8; N]>, String> {
    vec![0u8; N].into_boxed_slice().try_into().map_err(|_| "allocation size mismatch".to_string())
}

/// A Classic McEliece 460896 keypair; the secret key in round-3 spec layout.
struct McEliece {
    public: Box<[u8; pq::PK_LEN]>,
    secret: Box<[u8; pq::SK_LEN]>,
}

fn mceliece_keypair(rng: &mut Urandom) -> Result<McEliece, String> {
    let mut public = zeroed::<{ pq::PK_LEN }>()?;
    let mut secret = zeroed::<{ pq::SK_LEN }>()?;
    mce460896::keypair(&mut |out| rng.fill(out), &mut public, &mut secret)
        .map_err(|_| "/dev/urandom: read failed".to_string())?;
    Ok(McEliece { public, secret })
}

/// The boot KAT pair for `public`: a ciphertext and BLAKE2s(shared key).
fn mceliece_kat(public: &[u8; pq::PK_LEN], rng: &mut Urandom) -> Result<([u8; pq::CT_LEN], [u8; 32]), String> {
    let mut ct = [0u8; pq::CT_LEN];
    let mut shk = [0u8; pq::SHK_LEN];
    mce460896::encaps(public, &mut |out| rng.fill(out), &mut ct, &mut shk)
        .map_err(|_| "/dev/urandom: read failed".to_string())?;
    let hash = secret_blob::blake2s(&[&shk]);
    Ok((ct, hash))
}

/// Refuses an output directory inside any of `forbidden` (all canonical).
/// `out` need not exist; its parent must.
fn check_out_dir(out: &Path, forbidden: &[PathBuf]) -> Result<PathBuf, String> {
    let name = out.file_name().ok_or_else(|| format!("{}: no directory name", out.display()))?;
    let parent = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let parent = parent.canonicalize().map_err(|e| format!("{}: {e}", parent.display()))?;
    let resolved = parent.join(name);
    if let Some(f) = forbidden.iter().find(|f| resolved.starts_with(f)) {
        return Err(format!("{} is inside {}; secrets must live elsewhere", resolved.display(), f.display()));
    }
    Ok(resolved)
}

/// The repository (which contains `build/`) and the toolchain caches. The
/// repository must resolve: a binary run where its source tree is absent
/// would otherwise silently drop the most important root. Caches that do
/// not exist are skipped (nothing can be written under them).
fn forbidden_roots() -> Result<Vec<PathBuf>, String> {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut roots = vec![repo.canonicalize().map_err(|e| format!("cannot resolve the repository {}: {e}", repo.display()))?];
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let caches = [
        std::env::var_os("CARGO_HOME").map(PathBuf::from),
        std::env::var_os("RUSTUP_HOME").map(PathBuf::from),
        home.as_ref().map(|h| h.join(".cargo")),
        home.as_ref().map(|h| h.join(".rustup")),
    ];
    roots.extend(caches.into_iter().flatten().filter_map(|p| p.canonicalize().ok()));
    Ok(roots)
}

/// One client's bundle.
struct PeerBundle {
    wg_conf: String,
    rp_toml: String,
    rp_public: Box<[u8; pq::PK_LEN]>,
    /// liboqs layout, as upstream `rp genkey` writes `pqsk`.
    rp_secret: Box<[u8; pq::LIBOQS_SK_LEN]>,
}

struct Deployment {
    config: String,
    blob: Box<[u8; secret_blob::REGION_SIZE]>,
    /// `blob` with another valid TLS scalar, if asked for.
    tls_mismatch_blob: Option<Box<[u8; secret_blob::REGION_SIZE]>>,
    tls_pub_pem: String,
    /// mkcert's files: `tls.der`, `devca.pem` and any negative leaves.
    certs: Vec<(String, Vec<u8>)>,
    pq_blob: Box<[u8; pq::REGION_SIZE]>,
    gateway_rp_public: Box<[u8; pq::PK_LEN]>,
    peers: Vec<PeerBundle>,
}

const GATEWAY_RP_PUBLIC: &str = "gateway.rp.pk";

fn peer_ip(i: usize) -> String {
    format!("10.200.0.{}", i + 2)
}

fn peer_rp_public(i: usize) -> String {
    format!("peer-{i}.rp.pk")
}

/// The Rosenpass endpoint: `rp_endpoint` if given, else the WireGuard
/// endpoint's host with `rp_port`.
fn rosenpass_endpoint(endpoint: &str, rp_endpoint: Option<&str>, rp_port: u16) -> Result<String, String> {
    if let Some(e) = rp_endpoint {
        return Ok(e.to_string());
    }
    let (host, _) = endpoint.rsplit_once(':').ok_or_else(|| format!("--endpoint {endpoint:?}: expected HOST:PORT"))?;
    Ok(format!("{host}:{rp_port}"))
}

/// Builds every output in memory; nothing touches the disk here but
/// `tls.issue`'s mkcert run, which sees only the public key.
fn generate(
    template: &str,
    peers: usize,
    endpoint: &str,
    rp_endpoint: Option<&str>,
    tls: &TlsOptions<'_>,
) -> Result<Deployment, String> {
    if peers == 0 || peers > validate::MAX_PEERS {
        return Err(format!("--peers must be 1..={}", validate::MAX_PEERS));
    }
    let raw: validate::RawConfig = toml::from_str(template).map_err(|e| format!("template: {e}"))?;
    let g = &raw.gateway;
    let rp_endpoint = rosenpass_endpoint(endpoint, rp_endpoint, g.rp_port)?;
    let mut rng = Urandom::open()?;
    let gateway = keypair()?;
    let gateway_rp = mceliece_keypair(&mut rng)?;
    let peer_keys: Vec<(KeyPair, McEliece)> =
        (0..peers).map(|_| Ok((keypair()?, mceliece_keypair(&mut rng)?))).collect::<Result<_, String>>()?;
    // The plan's order (F13): the scalar and tls.pub first, then mkcert,
    // then the config naming the leaf, validated last.
    let (tls_private, tls_public) = p256_keypair()?;
    let tls_pub_pem = public_key_pem(&tls_public);
    let certs = (tls.issue)(&tls_pub_pem, tls.name.unwrap_or(&g.outside_ip), tls.negative)?;

    let mut config = format!(
        "# Generated by tools/mksecrets. Public values only.\n\n[gateway]\npublic_key = \"{}\"\n\
         listen_port = {}\nrp_port = {}\nhttps_port = {}\nrp_pub_path = \"{GATEWAY_RP_PUBLIC}\"\nrp_hash = \"{}\"\n\
         outside_ip = \"{}\"\noutside_mac = \"{}\"\noutside_router_mac = \"{}\"\n\
         inside_ip = \"{}\"\ninside_prefix = \"{}\"\ninside_mac = \"{}\"\n\
         tls_ports = {{ start = {}, count = {} }}\nbackend = {{ ip = \"{}\", port = {} }}\n\
         tls_cert = \"{TLS_CERT}\"\ntls_public = \"{}\"\n",
        encode_key(&gateway.public),
        g.listen_port,
        g.rp_port,
        g.https_port,
        validate::encode_hash(&secret_blob::blake2s(&[&gateway_rp.public[..]])),
        g.outside_ip,
        g.outside_mac,
        g.outside_router_mac,
        g.inside_ip,
        g.inside_prefix,
        g.inside_mac,
        g.tls_ports.start,
        g.tls_ports.count,
        g.backend.ip,
        g.backend.port,
        tls_public.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    for n in &raw.neighbors {
        config.push_str(&format!("\n[[neighbors]]\nip = \"{}\"\nmac = \"{}\"\n", n.ip, n.mac));
    }
    for (i, (kp, rp)) in peer_keys.iter().enumerate() {
        config.push_str(&format!(
            "\n[[peers]]\nwg_pub = \"{}\"\nrp_pub_path = \"{}\"\nrp_hash = \"{}\"\nallowed_ips = [\"{}/32\"]\n",
            encode_key(&kp.public),
            peer_rp_public(i),
            validate::encode_hash(&secret_blob::blake2s(&[&rp.public[..]])),
            peer_ip(i)
        ));
    }
    let load = |name: &str| -> Result<Vec<u8>, String> {
        if name == TLS_CERT {
            return certs.iter().find(|(n, _)| n == TLS_CERT).map(|(_, c)| c.clone()).ok_or("mkcert wrote no tls.der".into());
        }
        let key = if name == GATEWAY_RP_PUBLIC {
            Some(&gateway_rp)
        } else {
            (0..peers).find(|i| peer_rp_public(*i) == name).and_then(|i| peer_keys.get(i)).map(|(_, rp)| rp)
        };
        key.map(|k| k.public.to_vec()).ok_or_else(|| format!("{name}: not generated"))
    };
    validate::check(&config, validate::MAX_PEERS, &load).map_err(|e| format!("generated config invalid: {e}"))?;

    let mut blob = zeroed::<{ secret_blob::REGION_SIZE }>()?;
    let wg_publics: Vec<[u8; 32]> = peer_keys.iter().map(|(kp, _)| kp.public).collect();
    let boot_seed = random32()?;
    secret_blob::write(&mut blob, &gateway.private, &boot_seed, tls_private.as_bytes(), &wg_publics)
        .ok_or_else(|| "secrets do not fit the region".to_string())?;
    let tls_mismatch_blob = if tls.mismatch_blob {
        let (other, _) = p256_keypair()?;
        let mut b = zeroed::<{ secret_blob::REGION_SIZE }>()?;
        secret_blob::write(&mut b, &gateway.private, &boot_seed, other.as_bytes(), &wg_publics)
            .ok_or_else(|| "secrets do not fit the region".to_string())?;
        Some(b)
    } else {
        None
    };

    let (kat_ct, kat_shk_hash) = mceliece_kat(&gateway_rp.public, &mut rng)?;
    let mut pq_blob = zeroed::<{ pq::REGION_SIZE }>()?;
    let fields = pq::Fields {
        secret_key: &gateway_rp.secret,
        spkm_hash: &secret_blob::blake2s(&[&gateway_rp.public[..]]),
        kat_ct: &kat_ct,
        kat_shk_hash: &kat_shk_hash,
        blob_seed: &random32()?,
    };
    pq::write(&mut pq_blob, &fields).ok_or_else(|| "pqkey secrets do not fit the region".to_string())?;

    // Clients route the gateway's inside network through the tunnel.
    let inside = &g.inside_prefix;
    let mut bundles = Vec::with_capacity(peers);
    for (i, (kp, rp)) in peer_keys.into_iter().enumerate() {
        let wg_conf = format!(
            "# Address = {}/32\n# The PresharedKey is the Rosenpass output (peer-{i}.osk), applied with\n\
             # `wg set <interface> peer <gateway key> preshared-key peer-{i}.osk` on each rotation.\n\
             [Interface]\nPrivateKey = {}\n\n[Peer]\nPublicKey = {}\n\
             Endpoint = {endpoint}\nAllowedIPs = {inside}\nPersistentKeepalive = 25\n",
            peer_ip(i),
            encode_key(&kp.private),
            encode_key(&gateway.public),
        );
        let rp_toml = format!(
            "# rosenpass(1) client for peer {i} (upstream master, protocol V02).\n\
             # Paths are relative to this bundle; key_out receives each new WireGuard PSK.\n\
             public_key = \"{}\"\nsecret_key = \"peer-{i}.rp.sk\"\nlisten = []\nverbosity = \"Quiet\"\n\n\
             [[peers]]\npublic_key = \"{GATEWAY_RP_PUBLIC}\"\nendpoint = \"{rp_endpoint}\"\n\
             key_out = \"peer-{i}.osk\"\nprotocol_version = \"V02\"\n",
            peer_rp_public(i),
        );
        let mut rp_secret = zeroed::<{ pq::LIBOQS_SK_LEN }>()?;
        pq::liboqs_sk_from_cmr(&mut rp_secret, &rp.secret);
        bundles.push(PeerBundle { wg_conf, rp_toml, rp_public: rp.public, rp_secret });
    }
    Ok(Deployment {
        config,
        blob,
        tls_mismatch_blob,
        tls_pub_pem,
        certs,
        pq_blob,
        gateway_rp_public: gateway_rp.public,
        peers: bundles,
    })
}

/// Writes a deployment through `write` into a fresh 0700 staging directory
/// beside `dir`, then publishes it as `dir` in one rename that never
/// replaces anything. Stop signals are held from before the staging
/// directory exists until the outcome is settled, so a signal cannot leave
/// staged secrets behind: on success it is discarded (a signal during
/// staging does not cancel the run, and a run that published always
/// succeeds); on failure the staging directory is removed first and the
/// signal then ends the process with nothing published.
fn stage_and_publish(dir: &Path, write: impl FnOnce(&Path) -> Result<(), String>) -> Result<(), String> {
    let name = dir.file_name().ok_or_else(|| format!("{}: no directory name", dir.display()))?;
    let parent = dir.parent().ok_or_else(|| format!("{}: no parent", dir.display()))?;
    let mut token = [0u8; 8];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut token))
        .map_err(|e| format!("/dev/urandom: {e}"))?;
    let token: String = token.iter().map(|b| format!("{b:02x}")).collect();
    let staging = parent.join(format!(".{}.mksecrets-{token}", name.to_string_lossy()));
    stage_and_publish_at(dir, &staging, write)
}

/// `stage_and_publish` with the staging path given. Only a staging directory
/// this call created is ever removed: one that already exists makes the
/// creation fail, and is left as it was.
fn stage_and_publish_at(dir: &Path, staging: &Path, write: impl FnOnce(&Path) -> Result<(), String>) -> Result<(), String> {
    let held = StopSignals::hold()?;
    std::fs::DirBuilder::new().mode(0o700).create(staging).map_err(|e| format!("{}: {e}", staging.display()))?;
    let staged = write(staging)
        .and_then(|()| rename_noreplace(staging, dir).map_err(|e| format!("cannot publish {}: {e}", dir.display())));
    match staged {
        Ok(()) => {
            held.discard_pending();
            Ok(())
        }
        Err(e) => {
            let removed = match std::fs::remove_dir_all(staging) {
                Ok(()) => Ok(()),
                Err(r) => Err(format!("{e}; and could not remove staging directory {}: {r}", staging.display())),
            };
            drop(held);
            Err(removed.err().unwrap_or(e))
        }
    }
}

/// SIGTERM, SIGINT and SIGHUP blocked for the holder's lifetime; dropping it
/// restores the previous mask, which delivers anything that arrived.
struct StopSignals {
    previous: libc::sigset_t,
}

impl StopSignals {
    fn set() -> libc::sigset_t {
        // SAFETY: sigemptyset/sigaddset initialise and fill a local set.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for s in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
                libc::sigaddset(&mut set, s);
            }
            set
        }
    }

    fn hold() -> Result<Self, String> {
        let set = Self::set();
        // SAFETY: valid pointers to a filled set and to an output set.
        let mut previous: libc::sigset_t = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut previous) };
        if rc != 0 {
            return Err(format!("cannot block stop signals: error {rc}"));
        }
        Ok(Self { previous })
    }

    /// The commit point has passed: stop signals that arrived (or arrive)
    /// are ignored instead of ending a run that has already published.
    fn discard_pending(self) {
        for s in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            // SAFETY: SIG_IGN is a valid disposition for these signals;
            // ignoring a pending signal discards it.
            unsafe { libc::signal(s, libc::SIG_IGN) };
        }
    }
}

impl Drop for StopSignals {
    fn drop(&mut self) {
        // SAFETY: restores the mask saved by `hold`.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut()) };
    }
}

/// rename(2) that fails if `to` exists (RENAME_NOREPLACE), so an output
/// created after the checks is never replaced.
fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = |p: &Path| std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(std::io::Error::other);
    let (from, to) = (c(from)?, c(to)?);
    // SAFETY: two valid NUL-terminated paths relative to the cwd.
    let rc = unsafe { libc::renameat2(libc::AT_FDCWD, from.as_ptr(), libc::AT_FDCWD, to.as_ptr(), libc::RENAME_NOREPLACE) };
    if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn run(args: &[String]) -> Result<(), String> {
    let mut template = None;
    let mut peers = None;
    let mut out = None;
    let mut endpoint = "127.0.0.1:51820".to_string();
    let mut rp_endpoint = None;
    let mut tls_name = None;
    let mut negative = false;
    let mut mismatch_blob = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = || it.next().cloned().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--template" => template = Some(value()?),
            "--peers" => peers = Some(value()?.parse::<usize>().map_err(|_| "--peers: not a number")?),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--endpoint" => endpoint = value()?,
            "--rp-endpoint" => rp_endpoint = Some(value()?),
            "--tls-name" => tls_name = Some(value()?),
            "--test-negative" => negative = true,
            "--tls-mismatch-blob" => mismatch_blob = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let (Some(template), Some(peers), Some(out)) = (template, peers, out) else {
        return Err("usage: mksecrets --template FILE --peers N --out DIR [--endpoint HOST:PORT] [--rp-endpoint HOST:PORT] \
                    [--tls-name NAME] [--test-negative] [--tls-mismatch-blob]"
            .into());
    };
    let dir = check_out_dir(&out, &forbidden_roots()?)?;
    let text = std::fs::read_to_string(&template).map_err(|e| format!("{template}: {e}"))?;
    let tls = TlsOptions { name: tls_name.as_deref(), negative, mismatch_blob, issue: &mkcert_issue };
    let d = generate(&text, peers, &endpoint, rp_endpoint.as_deref(), &tls)?;

    stage_and_publish(&dir, |stage| {
        write_private(&stage.join("gateway.toml"), d.config.as_bytes())?;
        write_private(&stage.join(GATEWAY_RP_PUBLIC), &d.gateway_rp_public[..])?;
        write_private(&stage.join("secrets.bin"), &d.blob[..])?;
        if let Some(b) = &d.tls_mismatch_blob {
            write_private(&stage.join("secrets-tls-mismatch.bin"), &b[..])?;
        }
        write_private(&stage.join("pqkey-secrets.bin"), &d.pq_blob[..])?;
        write_private(&stage.join(TLS_PUB), d.tls_pub_pem.as_bytes())?;
        for (name, bytes) in &d.certs {
            write_private(&stage.join(name), bytes)?;
        }
        for (i, p) in d.peers.iter().enumerate() {
            write_private(&stage.join(format!("peer-{i}.conf")), p.wg_conf.as_bytes())?;
            write_private(&stage.join(format!("peer-{i}.rosenpass.toml")), p.rp_toml.as_bytes())?;
            write_private(&stage.join(peer_rp_public(i)), &p.rp_public[..])?;
            write_private(&stage.join(format!("peer-{i}.rp.sk")), &p.rp_secret[..])?;
        }
        Ok(())
    })?;
    println!("mksecrets: wrote {} ({} peers)", dir.display(), peers);
    Ok(())
}

/// The TPMT_PUBLIC inside a TPM2B_PUBLIC file.
fn srk_public(tpm2b: &[u8]) -> Result<&[u8], String> {
    let (size, public) = tpm2b.split_at_checked(2).ok_or("--srk-public: shorter than a TPM2B")?;
    if usize::from(u16::from_be_bytes([size[0], size[1]])) != public.len() {
        return Err("--srk-public: the TPM2B size does not match the file (expected tpm2_readpublic -o output)".into());
    }
    Ok(public)
}

fn pcr8(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    let mut out = [0u8; 32];
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("--pcr8: expected 64 hex digits".into());
    }
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| "--pcr8: not hex")?;
    }
    Ok(out)
}

/// Reads exactly the region from `path` into `region`, then checks it is a
/// blob of its kind (`key`'s peer count is the blob's own).
fn read_blob(path: &Path, kind: Kind, region: &mut [u8]) -> Result<(), String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let len = f.metadata().map_err(|e| format!("{}: {e}", path.display()))?.len();
    if usize::try_from(len).ok() != Some(region.len()) {
        return Err(format!("{}: {len} bytes, a {kind:?} blob is {}", path.display(), region.len()));
    }
    f.read_exact(region).map_err(|e| format!("{}: {e}", path.display()))?;
    let checked = match kind {
        Kind::Key => {
            let peers = region.get(12..16).map_or(0, |p| u32::from_le_bytes([p[0], p[1], p[2], p[3]]));
            secret_blob::Blob::parse(region, peers as usize).map(|_| ())
        }
        Kind::Pq => pq::Blob::parse(region).map(|_| ()),
    };
    checked.map_err(|e| format!("{}: {}", path.display(), e.message()))
}

/// Seals the blob at `blob` into its envelope.
fn seal_file(kind: Kind, blob: &Path, srk_public: &[u8], pcr8: &[u8; 32]) -> Result<Vec<u8>, String> {
    let mut region = Secret::<{ pq::REGION_SIZE }>::zero();
    let region = region.as_mut_bytes().get_mut(..kind.region_size()).ok_or("region size")?;
    read_blob(blob, kind, region)?;
    let mut entropy = Secret::<SEAL_ENTROPY_LEN>::zero();
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(entropy.as_mut_bytes()))
        .map_err(|e| format!("/dev/urandom: {e}"))?;
    let mut out = vec![0u8; kind.region_size()];
    tpm2::envelope::seal(&mut out, kind, region, srk_public, pcr8, &entropy).map_err(|e| format!("seal: {e:?}"))?;
    Ok(out)
}

fn run_seal(args: &[String]) -> Result<(), String> {
    let (mut kind, mut blob, mut srk, mut pcr, mut out) = (None, None, None, None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = || it.next().cloned().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--kind" => {
                kind = Some(match value()?.as_str() {
                    "key" => Kind::Key,
                    "pq" => Kind::Pq,
                    other => return Err(format!("--kind: {other} is not key or pq")),
                })
            }
            "--blob" => blob = Some(PathBuf::from(value()?)),
            "--srk-public" => srk = Some(PathBuf::from(value()?)),
            "--pcr8" => pcr = Some(pcr8(&value()?)?),
            "--out" => out = Some(PathBuf::from(value()?)),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let (Some(kind), Some(blob), Some(srk), Some(pcr), Some(out)) = (kind, blob, srk, pcr, out) else {
        return Err("usage: mksecrets seal --kind key|pq --blob FILE --srk-public FILE --pcr8 HEX --out FILE".into());
    };
    let srk_file = std::fs::read(&srk).map_err(|e| format!("{}: {e}", srk.display()))?;
    let envelope = seal_file(kind, &blob, srk_public(&srk_file)?, &pcr)?;
    write_private(&out, &envelope)?;
    println!("mksecrets: sealed {} to {}", blob.display(), out.display());
    Ok(())
}

/// M5 plan C12: the envelope's sealed object enforces this PCR 8. The
/// policy is the object public's authPolicy, the one the TPM enforces (S15);
/// `Envelope::parse` already refuses a header copy that disagrees with it,
/// attributes other than the sealed object's (userWithAuth clear) and a PCR
/// selection other than {8}/sha256.
fn envelope_sealed_to(bytes: &[u8], kind: Kind, pcr8: &[u8; 32]) -> Result<(), String> {
    let envelope = tpm2::envelope::Envelope::parse(bytes, kind).map_err(|e| format!("envelope: {e:?}"))?;
    if envelope.object_policy() != &tpm2::crypto::policy_digest(pcr8) {
        return Err("the envelope's sealed object enforces another PCR 8".into());
    }
    Ok(())
}

fn run_check_envelope(args: &[String]) -> Result<(), String> {
    let (mut kind, mut envelope, mut pcr) = (None, None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = || it.next().cloned().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--kind" => {
                kind = Some(match value()?.as_str() {
                    "key" => Kind::Key,
                    "pq" => Kind::Pq,
                    other => return Err(format!("--kind: {other} is not key or pq")),
                })
            }
            "--envelope" => envelope = Some(PathBuf::from(value()?)),
            "--pcr8" => pcr = Some(pcr8(&value()?)?),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let (Some(kind), Some(envelope), Some(pcr)) = (kind, envelope, pcr) else {
        return Err("usage: mksecrets check-envelope --kind key|pq --envelope FILE --pcr8 HEX".into());
    };
    let bytes = std::fs::read(&envelope).map_err(|e| format!("{}: {e}", envelope.display()))?;
    envelope_sealed_to(&bytes, kind, &pcr)?;
    let pcr_hex: String = pcr.iter().map(|b| format!("{b:02x}")).collect();
    println!("mksecrets: {} is sealed to PCR 8 {pcr_hex}", envelope.display());
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.split_first() {
        Some((mode, rest)) if mode == "seal" => run_seal(rest),
        Some((mode, rest)) if mode == "check-envelope" => run_check_envelope(rest),
        _ => run(&args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mksecrets: {e}");
            ExitCode::FAILURE
        }
    }
}
