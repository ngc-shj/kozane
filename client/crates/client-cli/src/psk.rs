//! `kzc-psk` (D6): runs as `kozane-psk` with `CAP_NET_ADMIN` only, holds
//! `wg.sk`, owns the WireGuard interface, and takes `Install` and `Scrub`
//! from `kozane-net` alone over the unit socket. When a connection closes
//! it scrubs, then accepts one new connection. On every exit it deletes
//! the interface; `kzc-psk cleanup` (the unit's `ExecStopPost=`) deletes a
//! marked one again.

use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use kozane_client::{Secret, lock_memory};
use wg_core::crypto::{Key32, public_key};

use crate::conf::{self, Conf};
use crate::device::{self, Device};
use crate::files::Checker;
use crate::ipc::{self, Request};
use crate::keygen::{NET_USER, PSK_DIR};
use crate::netlink::Socket;
use crate::seams::Env;
use crate::{b64, notify, sys};

pub fn load_conf(env: &Env, checker: &Checker) -> Result<Conf, String> {
    let path = env.path(conf::PATH);
    let text = checker.read_root_file(&path, conf::MAX_LEN)?;
    let text = std::str::from_utf8(&text).map_err(|_| format!("{}: not UTF-8", path.display()))?;
    Conf::parse(text).map_err(|e| format!("{}: {e}", path.display()))
}

fn sockets() -> Result<(Socket, Socket), String> {
    let route = Socket::open(libc::NETLINK_ROUTE).map_err(|e| format!("rtnetlink: {e}"))?;
    let genl = Socket::open(libc::NETLINK_GENERIC).map_err(|e| format!("generic netlink: {e}"))?;
    Ok((route, genl))
}

/// `kzc-psk cleanup`: deletes a marked interface of the configured name.
pub fn cleanup(env: &Env) -> Result<(), String> {
    let conf = load_conf(env, &Checker::system())?;
    let (mut route, _) = sockets()?;
    if device::reclaim(&mut route, &conf.interface)? {
        eprintln!("kzc-psk: deleted {}", conf.interface);
    }
    Ok(())
}

/// Binds the unit socket, mode 0660, replacing a stale socket (and only a
/// socket) at its path.
fn listen(path: &Path) -> Result<OwnedFd, String> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Ok(_) => return Err(format!("{}: exists and is not a socket", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    let fd = sys::seqpacket().map_err(|e| format!("socket: {e}"))?;
    let old = sys::umask(0o117);
    let bound = sys::bind_unix(fd.as_fd(), path);
    sys::umask(old);
    bound.map_err(|e| format!("{}: bind: {e}", path.display()))?;
    sys::listen(fd.as_fd(), 4).map_err(|e| format!("listen: {e}"))?;
    Ok(fd)
}

/// Locked, wiped-on-drop buffers for one record and its PSK.
struct Buffers {
    record: Box<Secret<{ ipc::RECORD_MAX }>>,
    psk: Box<Secret<32>>,
}

impl Buffers {
    fn new() -> Result<Self, String> {
        let b = Self { record: Box::new(Secret::zero()), psk: Box::new(Secret::zero()) };
        lock_memory(&*b.record).map_err(|_| "cannot lock PSK memory")?;
        lock_memory(&*b.psk).map_err(|_| "cannot lock PSK memory")?;
        Ok(b)
    }
}

/// Serves one admitted connection until it closes, a signal arrives, or a
/// record is not `Install` or `Scrub`. A device error is fatal.
fn serve<T: crate::netlink::Transport>(conn: &OwnedFd, dev: &mut Device<T>, b: &mut Buffers) -> Result<(), String> {
    loop {
        if sys::terminated() {
            return Ok(());
        }
        if sys::poll(&[(conn.as_fd(), libc::POLLIN)], -1).map_err(|e| format!("poll: {e}"))?.is_none() {
            continue;
        }
        let n = match sys::recv(conn.as_fd(), b.record.expose_mut()) {
            Ok(Some(n)) => n,
            Ok(None) => continue,
            Err(e) => {
                eprintln!("kzc-psk: connection: {e}");
                return Ok(());
            }
        };
        if n == 0 {
            return Ok(());
        }
        let req = ipc::decode(b.record.expose(), n, &mut b.psk);
        b.record.wipe();
        match req {
            Some(Request::Install) => {
                let r = dev.install(&b.psk);
                b.psk.wipe();
                r?;
            }
            Some(Request::Scrub) => dev.scrub()?,
            None => {
                eprintln!("kzc-psk: unexpected record ({n} bytes); closing the connection");
                return Ok(());
            }
        }
        if sys::send(conn.as_fd(), &[ipc::OK]).is_err() {
            return Ok(());
        }
    }
}

pub fn run(env: &Env) -> Result<(), String> {
    sys::no_dump().map_err(|e| format!("prctl: {e}"))?;
    sys::install_signal_handlers().map_err(|e| format!("signals: {e}"))?;
    let checker = Checker::system();
    let conf = load_conf(env, &checker)?;
    let (net_uid, _) = env.user(NET_USER)?;

    let mut private = Box::new(Secret::<32>::zero());
    lock_memory(&*private).map_err(|_| "cannot lock key memory")?;
    let dir_path = env.path(PSK_DIR);
    checker.open_key_dir(&dir_path)?.read_secret("wg.sk", private.expose_mut())?;
    let own_pub = public_key(&Key32::copy_from(private.expose()));
    eprintln!(
        "kzc-psk: interface {} wg_pub {} gateway wg_pub {}",
        conf.interface,
        b64::encode(&own_pub),
        b64::encode(&conf.gw_wg_pub)
    );

    let (route, genl) = sockets()?;
    let mut dev = Device::create(route, genl, &conf, &private, device::os_fill)?;
    private.wipe();
    drop(private);

    let sock_path = env.path(ipc::SOCKET);
    let listener = listen(&sock_path)?;
    notify::ready().map_err(|e| format!("sd_notify: {e}"))?;
    eprintln!("kzc-psk: ready");

    let mut bufs = Buffers::new()?;
    let result = (|| -> Result<(), String> {
        while !sys::terminated() {
            if sys::poll(&[(listener.as_fd(), libc::POLLIN)], -1).map_err(|e| format!("poll: {e}"))?.is_none() {
                continue;
            }
            let conn = match sys::accept(listener.as_fd()) {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("accept: {e}")),
            };
            let uid = match sys::peer_uid(conn.as_fd()) {
                Ok(uid) => uid,
                Err(e) => {
                    eprintln!("kzc-psk: SO_PEERCRED: {e}; connection refused");
                    continue;
                }
            };
            if !ipc::admit(uid, net_uid) {
                eprintln!("kzc-psk: refused a connection from uid {uid}");
                continue;
            }
            serve(&conn, &mut dev, &mut bufs)?;
            drop(conn);
            if sys::terminated() {
                break;
            }
            dev.scrub()?;
            eprintln!("kzc-psk: connection closed; peer scrubbed");
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(&sock_path);
    let deleted = dev.delete();
    result?;
    deleted?;
    eprintln!("kzc-psk: stopped; {} deleted", conf.interface);
    Ok(())
}
