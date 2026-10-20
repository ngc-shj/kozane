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
    filler: u64,
}

impl Urandom {
    fn open() -> Result<Self, String> {
        let file = std::fs::File::open("/dev/urandom").map_err(|e| format!("/dev/urandom: {e}"))?;
        Ok(Urandom { file, failed: false, filler: 0 })
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
            // Discarded output (`check` refuses it); varying bytes end cmr's
            // rejection sampling, which a zero fill would loop forever in.
            for b in dest.iter_mut() {
                self.filler = self.filler.wrapping_mul(0x5851_f42d_4c95_7f2d).wrapping_add(1);
                let [top, ..] = self.filler.to_be_bytes();
                *b = top;
            }
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

    stage_and_publish(&dir, |stage| {
        write_private(&stage.join("gateway.toml"), d.config.as_bytes())?;
        write_private(&stage.join(GATEWAY_RP_PUBLIC), &d.gateway_rp_public[..])?;
        write_private(&stage.join("secrets.bin"), &d.blob[..])?;
        write_private(&stage.join("pqkey-secrets.bin"), &d.pq_blob[..])?;
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
