//! Generates a development deployment (plan C16, M3 plan C6): fresh
//! gateway and peer keys, a gateway config for the build (SECUREOS_CONFIG)
//! with the McEliece public key files it names, both secrets regions for
//! `make package` (`secrets.bin` for `key`, `pqkey-secrets.bin` for
//! `pqkey`), and per peer a client bundle: a wg(8) config without a
//! PresharedKey (the PSK comes from Rosenpass, L8), a rosenpass(1) config
//! and the peer's McEliece keypair, the secret key in the liboqs layout
//! upstream rosenpass reads.
//!
//! Usage: mksecrets --template config/gateway.toml --peers N --out DIR
//!                  [--endpoint HOST:PORT] [--rp-endpoint HOST:PORT]
//!
//! The Rosenpass endpoint defaults to the WireGuard endpoint's host with the
//! template's `rp_port`.
//!
//! DIR must not exist yet and, after resolving symlinks, must lie outside
//! the repository and the toolchain caches, so secrets never land where a
//! commit, a build artefact or a cache volume could pick them up.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use classic_mceliece_rust as cmr;
use secret_blob::pq;

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

fn keypair() -> Result<KeyPair, String> {
    let mut private = random32()?;
    libcrux_curve25519::clamp(&mut private);
    let mut public = [0u8; 32];
    libcrux_curve25519::secret_to_public(&mut public, &private);
    Ok(KeyPair { private, public })
}

/// /dev/urandom as the McEliece keygen and encapsulation RNG. `fill_bytes`
/// cannot report failure, so a failed read is recorded (and the output
/// zeroed) and `check` turns it into an error once the operation is done.
struct Urandom {
    file: std::fs::File,
    failed: bool,
}

impl Urandom {
    fn open() -> Result<Self, String> {
        let file = std::fs::File::open("/dev/urandom").map_err(|e| format!("/dev/urandom: {e}"))?;
        Ok(Urandom { file, failed: false })
    }

    fn check(&self) -> Result<(), String> {
        if self.failed { Err("/dev/urandom: read failed".into()) } else { Ok(()) }
    }
}

impl rand_core::RngCore for Urandom {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.file.read_exact(dest).is_err() {
            self.failed = true;
            dest.fill(0);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for Urandom {}

/// A zeroed heap array, never built on the stack (McEliece keys are large).
fn zeroed<const N: usize>() -> Result<Box<[u8; N]>, String> {
    vec![0u8; N].into_boxed_slice().try_into().map_err(|_| "allocation size mismatch".to_string())
}

/// A Classic McEliece 460896 keypair; the secret key in cmr layout.
struct McEliece {
    public: Box<[u8; pq::PK_LEN]>,
    secret: Box<[u8; pq::SK_LEN]>,
}

fn mceliece_keypair(rng: &mut Urandom) -> Result<McEliece, String> {
    let mut public = zeroed::<{ pq::PK_LEN }>()?;
    let mut wrapped = zeroed::<{ pq::SK_LEN }>()?;
    let mut secret = zeroed::<{ pq::SK_LEN }>()?;
    {
        let (_, sk) = cmr::keypair(&mut public, &mut wrapped, rng);
        // cmr zeroizes the buffer it wraps when `sk` drops: copy it out first.
        secret.copy_from_slice(sk.as_array());
    }
    rng.check()?;
    Ok(McEliece { public, secret })
}

/// The boot KAT pair for `public`: a ciphertext and BLAKE2s(shared key).
fn mceliece_kat(public: &[u8; pq::PK_LEN], rng: &mut Urandom) -> Result<([u8; pq::CT_LEN], [u8; 32]), String> {
    let mut shk = [0u8; pq::SHK_LEN];
    let (ct, shared) = cmr::encapsulate(&cmr::PublicKey::from(public), &mut shk, rng);
    let hash = secret_blob::blake2s(&[shared.as_array()]);
    rng.check()?;
    Ok((*ct.as_array(), hash))
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

/// Builds every output in memory; nothing touches the disk here.
fn generate(template: &str, peers: usize, endpoint: &str, rp_endpoint: Option<&str>) -> Result<Deployment, String> {
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

    let mut config = format!(
        "# Generated by tools/mksecrets. Public values only.\n\n[gateway]\npublic_key = \"{}\"\n\
         listen_port = {}\nrp_port = {}\nrp_pub_path = \"{GATEWAY_RP_PUBLIC}\"\nrp_hash = \"{}\"\n\
         outside_ip = \"{}\"\noutside_mac = \"{}\"\noutside_router_mac = \"{}\"\n\
         inside_ip = \"{}\"\ninside_prefix = \"{}\"\ninside_mac = \"{}\"\n",
        encode_key(&gateway.public),
        g.listen_port,
        g.rp_port,
        validate::encode_hash(&secret_blob::blake2s(&[&gateway_rp.public[..]])),
        g.outside_ip,
        g.outside_mac,
        g.outside_router_mac,
        g.inside_ip,
        g.inside_prefix,
        g.inside_mac
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
    secret_blob::write(&mut blob, &gateway.private, &random32()?, &wg_publics)
        .ok_or_else(|| "secrets do not fit the region".to_string())?;

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
    Ok(Deployment { config, blob, pq_blob, gateway_rp_public: gateway_rp.public, peers: bundles })
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
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = || it.next().cloned().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--template" => template = Some(value()?),
            "--peers" => peers = Some(value()?.parse::<usize>().map_err(|_| "--peers: not a number")?),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--endpoint" => endpoint = value()?,
            "--rp-endpoint" => rp_endpoint = Some(value()?),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let (Some(template), Some(peers), Some(out)) = (template, peers, out) else {
        return Err(
            "usage: mksecrets --template FILE --peers N --out DIR [--endpoint HOST:PORT] [--rp-endpoint HOST:PORT]".into()
        );
    };
    let dir = check_out_dir(&out, &forbidden_roots()?)?;
    let text = std::fs::read_to_string(&template).map_err(|e| format!("{template}: {e}"))?;
    let d = generate(&text, peers, &endpoint, rp_endpoint.as_deref())?;

    std::fs::DirBuilder::new().mode(0o700).create(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    write_private(&dir.join("gateway.toml"), d.config.as_bytes())?;
    write_private(&dir.join(GATEWAY_RP_PUBLIC), &d.gateway_rp_public[..])?;
    write_private(&dir.join("secrets.bin"), &d.blob[..])?;
    write_private(&dir.join("pqkey-secrets.bin"), &d.pq_blob[..])?;
    for (i, p) in d.peers.iter().enumerate() {
        write_private(&dir.join(format!("peer-{i}.conf")), p.wg_conf.as_bytes())?;
        write_private(&dir.join(format!("peer-{i}.rosenpass.toml")), p.rp_toml.as_bytes())?;
        write_private(&dir.join(peer_rp_public(i)), &p.rp_public[..])?;
        write_private(&dir.join(format!("peer-{i}.rp.sk")), &p.rp_secret[..])?;
    }
    println!("mksecrets: wrote {} ({} peers)", dir.display(), peers);
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mksecrets: {e}");
            ExitCode::FAILURE
        }
    }
}
