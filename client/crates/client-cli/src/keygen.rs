//! `kzc keygen` (M9 plan C10, D7): run once as root at install.
//!
//! - Creates `/var/lib/kozane-psk` and `/var/lib/kozane-net` (`mkdirat`
//!   0700, opened `O_DIRECTORY|O_NOFOLLOW`, `fchown`ed to the unit's user).
//! - Writes `wg.sk`/`wg.pub` and `rp.sk`/`rp.pub` with
//!   `openat(O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC)`, `fchmod` 0600 (0644 for
//!   `.pub`), `fchown` and `fsync`. All four are created before any is
//!   written, so an existing key refuses the run and nothing is
//!   overwritten.
//! - Prints the M8 `peers.toml` entry: the Rosenpass digest
//!   (`secret_blob::blake2s` over `rp.pub`) and the base64 `wg_pub`.
//!
//! Formats: `rp.sk` is the liboqs-layout McEliece 460896 secret key,
//! `rp.pub` the raw `SPK_LEN` public key, `wg.sk`/`wg.pub` raw 32 bytes.

use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};

use kozane_client::{SPK_LEN, Secret, lock_memory};
use secret_blob::pq;
use wg_core::crypto::{Key32, clamp, public_key};

use crate::seams::Env;
use crate::{b64, sys};

pub const PSK_DIR: &str = "/var/lib/kozane-psk";
pub const NET_DIR: &str = "/var/lib/kozane-net";
pub const PSK_USER: &str = "kozane-psk";
pub const NET_USER: &str = "kozane-net";

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn zeroed<const N: usize>() -> Result<Box<[u8; N]>, String> {
    vec![0u8; N].into_boxed_slice().try_into().map_err(|_| "allocation".to_string())
}

struct RpPair {
    public: Box<[u8; SPK_LEN]>,
    secret_oqs: Box<[u8; pq::LIBOQS_SK_LEN]>,
}

impl Drop for RpPair {
    fn drop(&mut self) {
        secret::wipe(&mut self.secret_oqs[..]);
    }
}

fn rp_pair() -> Result<RpPair, String> {
    // Key generation needs about 1.1 MB of stack.
    std::thread::Builder::new()
        .stack_size(16 << 20)
        .spawn(|| -> Result<RpPair, String> {
            let mut secret = zeroed::<{ pq::SK_LEN }>()?;
            let mut pair = RpPair { public: zeroed()?, secret_oqs: zeroed()? };
            lock_memory(&*secret).map_err(|_| "cannot lock key memory")?;
            lock_memory(&*pair.secret_oqs).map_err(|_| "cannot lock key memory")?;
            let r = mce460896::keypair(
                &mut |out| getrandom::fill(out).map_err(|_| mce460896::RngError),
                &mut pair.public,
                &mut secret,
            );
            if r.is_ok() {
                pq::liboqs_sk_from_cmr(&mut pair.secret_oqs, &secret);
            }
            secret::wipe(&mut secret[..]);
            r.map_err(|_| "getrandom failed")?;
            Ok(pair)
        })
        .map_err(|e| format!("keygen thread: {e}"))?
        .join()
        .map_err(|_| "keygen thread panicked".to_string())?
}

/// A clamped X25519 private key and its public key.
fn wg_pair() -> Result<(Box<Secret<32>>, [u8; 32]), String> {
    let mut sk = Box::new(Secret::<32>::zero());
    lock_memory(&*sk).map_err(|_| "cannot lock key memory")?;
    getrandom::fill(sk.expose_mut()).map_err(|_| "getrandom failed")?;
    let mut k = Key32::copy_from(sk.expose());
    clamp(&mut k);
    sk.expose_mut().copy_from_slice(k.as_bytes());
    let public = public_key(&k);
    Ok((sk, public))
}

/// The key directory `name` under `parent`, created 0700 if missing, then
/// owned by `uid:gid` and set to 0700 through its own fd.
fn key_dir(parent: &OwnedFd, name: &str, uid: u32, gid: u32) -> Result<OwnedFd, String> {
    match sys::mkdirat(parent.as_fd(), OsStr::new(name), 0o700) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
        Err(e) => return Err(format!("{name}: mkdir: {e}")),
    }
    let fd = sys::openat(parent.as_fd(), OsStr::new(name), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW, 0)
        .map_err(|e| format!("{name}: {e} (a symlink is refused)"))?;
    sys::fchown(fd.as_fd(), uid, gid).map_err(|e| format!("{name}: fchown: {e}"))?;
    sys::fchmod(fd.as_fd(), 0o700).map_err(|e| format!("{name}: fchmod: {e}"))?;
    Ok(fd)
}

struct Out<'a> {
    dir: &'a OwnedFd,
    dir_name: &'a str,
    name: &'static str,
    mode: u32,
    uid: u32,
    gid: u32,
    bytes: &'a [u8],
}

fn create(o: &Out<'_>) -> Result<File, String> {
    let fd = sys::openat(
        o.dir.as_fd(),
        OsStr::new(o.name),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
        0o600,
    )
    .map_err(|e| format!("{}/{}: {e}; keys are never overwritten", o.dir_name, o.name))?;
    Ok(File::from(fd))
}

fn write(o: &Out<'_>, mut f: File) -> Result<(), String> {
    let at = format!("{}/{}", o.dir_name, o.name);
    f.write_all(o.bytes).map_err(|e| format!("{at}: {e}"))?;
    sys::fchmod(f.as_fd(), o.mode).map_err(|e| format!("{at}: fchmod: {e}"))?;
    sys::fchown(f.as_fd(), o.uid, o.gid).map_err(|e| format!("{at}: fchown: {e}"))?;
    sys::fsync(f.as_fd()).map_err(|e| format!("{at}: fsync: {e}"))
}

pub fn run(env: &Env) -> Result<(), String> {
    if sys::geteuid() != 0 {
        return Err("keygen runs as root".into());
    }
    let (psk_uid, psk_gid) = env.user(PSK_USER)?;
    let (net_uid, net_gid) = env.user(NET_USER)?;
    let (wg_sk, wg_pub) = wg_pair()?;
    let rp = rp_pair()?;

    // One source for the key directories: the paths kzc-psk and kzc read.
    let (parent_of, psk_name) = split_dir(PSK_DIR)?;
    let (net_parent, net_name) = split_dir(NET_DIR)?;
    if net_parent != parent_of {
        return Err(format!("keygen: {PSK_DIR} and {NET_DIR} must share a parent"));
    }
    let parent_path = env.path(parent_of);
    let parent = sys::open(&parent_path, libc::O_RDONLY | libc::O_DIRECTORY)
        .map_err(|e| format!("{}: {e}", parent_path.display()))?;
    let psk_dir = key_dir(&parent, psk_name, psk_uid, psk_gid)?;
    let net_dir = key_dir(&parent, net_name, net_uid, net_gid)?;
    let outs = [
        Out { dir: &psk_dir, dir_name: PSK_DIR, name: "wg.sk", mode: 0o600, uid: psk_uid, gid: psk_gid, bytes: wg_sk.expose() },
        Out { dir: &psk_dir, dir_name: PSK_DIR, name: "wg.pub", mode: 0o644, uid: psk_uid, gid: psk_gid, bytes: &wg_pub },
        Out {
            dir: &net_dir,
            dir_name: NET_DIR,
            name: "rp.sk",
            mode: 0o600,
            uid: net_uid,
            gid: net_gid,
            bytes: &rp.secret_oqs[..],
        },
        Out { dir: &net_dir, dir_name: NET_DIR, name: "rp.pub", mode: 0o644, uid: net_uid, gid: net_gid, bytes: &rp.public[..] },
    ];
    let mut files = Vec::with_capacity(outs.len());
    for o in &outs {
        match create(o) {
            Ok(f) => files.push(f),
            Err(e) => {
                // Only the empty files this run created go.
                for done in outs.iter().take(files.len()) {
                    let _ = sys::unlinkat(done.dir.as_fd(), OsStr::new(done.name));
                }
                return Err(e);
            }
        }
    }
    for (o, f) in outs.iter().zip(files) {
        write(o, f)?;
    }
    for d in [&psk_dir, &net_dir] {
        sys::fsync(d.as_fd()).map_err(|e| format!("key directory fsync: {e}"))?;
    }

    let digest = secret_blob::blake2s(&[&rp.public[..]]);
    println!("# kzc keygen: the start of this client's M8 peers.toml entry. Send it and");
    println!("# {NET_DIR}/rp.pub to the PDP, which copies rp.pub next to peers.toml,");
    println!("# sets rp_pub_path to that copy, and adds the peer's allowed_ips (and");
    println!("# groups). Check rp_digest there with `policy rp-digest`.");
    println!("# rp_digest = {}", hex(&digest));
    println!("[[peers]]");
    println!("wg_pub = \"{}\"", b64::encode(&wg_pub));
    println!("rp_pub_path = \"rp.pub\"");
    println!("# allowed_ips = [...]  (set by the PDP)");
    Ok(())
}

/// A key directory's parent and its own name.
fn split_dir(path: &'static str) -> Result<(&'static str, &'static str), String> {
    path.rsplit_once('/')
        .filter(|(parent, name)| !parent.is_empty() && !name.is_empty())
        .ok_or_else(|| format!("keygen: {path} is not an absolute directory"))
}

