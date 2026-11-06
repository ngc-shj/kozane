//! `kzc up` (D6): runs as `kozane-net` with no capabilities, holds `rp.sk`
//! and the pinned gateway key, parses Rosenpass from the network, and
//! drives `kozane-client` with `CLOCK_BOOTTIME`. Its PSKs and scrubs go to
//! `kzc-psk` over the unit socket, each acked before the next action.
//!
//! When `kzc-psk`'s connection closes, `kzc-psk` has scrubbed: `kzc`
//! reconnects (retrying until it can) and starts a fresh client, whose
//! first action is again `Scrub` (I8.1). On a signal, or any exit, the
//! socket closes and `kzc-psk` scrubs (I10.2).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use kozane_client::{Action, Actions, Client, Config, Error, Keys, RP_SK_LEN, SPK_LEN, Secret, lock_memory};

use crate::files::Checker;
use crate::ipc::{self, INSTALL_LEN};
use crate::keygen::{NET_DIR, hex};
use crate::psk::load_conf;
use crate::seams::Env;
use crate::sys;

/// How long `kzc-psk` may take to ack one request.
const ACK_TIMEOUT_MS: i32 = 10_000;
const RETRY_MS: i32 = 1_000;

/// The files `kzc` reads once; every session rebuilds its client from them.
struct Material {
    rp_endpoint: SocketAddr,
    gw_rp_pub: Vec<u8>,
    gw_wg_pub: [u8; 32],
    rp_pub: Vec<u8>,
    /// Locked, and wiped when dropped.
    rp_sk: Box<Secret<RP_SK_LEN>>,
}

fn load(env: &Env, checker: &Checker) -> Result<(Material, u16), String> {
    let conf = load_conf(env, checker)?;
    let gw_path = env.path(&conf.gw_rp_pub_path);
    let gw_rp_pub = checker.read_root_file(&gw_path, SPK_LEN as u64)?;
    if gw_rp_pub.len() != SPK_LEN {
        return Err(format!("{}: {} bytes, want {SPK_LEN}", gw_path.display(), gw_rp_pub.len()));
    }
    let dir_path = env.path(NET_DIR);
    let dir = checker.open_key_dir(&dir_path)?;
    let rp_pub = dir.read_public("rp.pub", SPK_LEN)?;
    // Zeroed when built, so the move to the heap copies no key.
    let mut rp_sk = Box::new(Secret::<RP_SK_LEN>::zero());
    lock_memory(&*rp_sk).map_err(|_| "cannot lock key memory")?;
    dir.read_secret("rp.sk", rp_sk.expose_mut())?;
    let m = Material { rp_endpoint: conf.rp_endpoint, gw_rp_pub, gw_wg_pub: conf.gw_wg_pub, rp_pub, rp_sk };
    Ok((m, conf.rp_listen_port))
}

enum End {
    /// `kzc-psk` closed the connection: reconnect.
    Closed,
    /// A signal: exit.
    Terminated,
}

/// One request to `kzc-psk` and its ack. Any failure means the connection
/// is gone.
fn request(conn: &OwnedFd, record: &[u8]) -> Result<(), ()> {
    sys::send(conn.as_fd(), record).map_err(drop)?;
    match sys::poll(&[(conn.as_fd(), libc::POLLIN)], ACK_TIMEOUT_MS) {
        Ok(Some(_)) => {}
        _ => return Err(()),
    }
    let mut reply = [0u8; 2];
    match sys::recv(conn.as_fd(), &mut reply) {
        Ok(Some(1)) if reply[0] == ipc::OK => Ok(()),
        _ => Err(()),
    }
}

/// Carries out one call's actions, in order. `Err(Closed)` when `kzc-psk`
/// did not ack.
fn perform(acts: Actions, udp: &UdpSocket, to: SocketAddr, conn: &OwnedFd, rec: &mut [u8; INSTALL_LEN]) -> Result<(), End> {
    for a in acts {
        match a {
            Action::Send(d) => {
                if let Err(e) = udp.send_to(d.as_bytes(), to) {
                    eprintln!("kzc: send to {to}: {e}");
                }
            }
            Action::InstallPsk(psk) => {
                ipc::encode_install(&psk, rec);
                drop(psk);
                let r = request(conn, rec);
                secret::wipe(rec);
                r.map_err(|()| End::Closed)?;
            }
            Action::Scrub => request(conn, &[ipc::TAG_SCRUB]).map_err(|()| End::Closed)?,
        }
    }
    Ok(())
}

/// One client call and its actions, in a frame of its own: kept out of
/// `session`, so the `Actions` the call returns (a PSK among them) and every
/// copy its moves leave lie below the caller's scrub.
#[inline(never)]
fn step(
    call: impl FnOnce() -> Result<Actions, Error>,
    udp: &UdpSocket,
    to: SocketAddr,
    conn: &OwnedFd,
    rec: &mut [u8; INSTALL_LEN],
) -> Result<Option<End>, String> {
    match call() {
        Ok(acts) => Ok(perform(acts, udp, to, conn, rec).err()),
        // A refused datagram changes nothing.
        Err(Error::Protocol(_)) => Ok(None),
        Err(e) => Err(fatal(e)),
    }
}

fn fatal(e: Error) -> String {
    format!("client: {e:?}")
}

fn session(m: &Material, udp: &UdpSocket, conn: &OwnedFd) -> Result<End, String> {
    let keys = Keys::new(&m.rp_pub, m.rp_sk.expose()).map_err(fatal)?;
    let config = Config::new(m.rp_endpoint, &m.gw_rp_pub, m.gw_wg_pub).map_err(fatal)?;
    let (client, first) = Client::new(config, keys).map_err(fatal)?;
    let mut client = Box::new(client);
    lock_memory(&*client).map_err(|_| "cannot lock client memory")?;
    let mut rec: Box<[u8; INSTALL_LEN]> = Box::new([0; INSTALL_LEN]);
    lock_memory(&*rec).map_err(|_| "cannot lock PSK memory")?;
    let to = m.rp_endpoint;
    let mut buf = vec![0u8; 2048];
    // After each step, from this frame: the OSK a step carries lives, with
    // its moved-from copies, in `step`'s frame and below, which the scrub
    // then reaches (code review S5, S7).
    let first = step(|| Ok(first), udp, to, conn, &mut rec);
    kozane_client::scrub_stack();
    if let Some(end) = first? {
        return Ok(end);
    }
    loop {
        if sys::terminated() {
            return Ok(End::Terminated);
        }
        let now = sys::boottime_ns().map_err(|e| format!("clock: {e}"))?;
        let timeout = match client.next_deadline() {
            Some(d) if d <= now => {
                let r = step(|| client.on_timer(now), udp, to, conn, &mut rec);
                kozane_client::scrub_stack();
                if let Some(end) = r? {
                    return Ok(end);
                }
                continue;
            }
            Some(d) => i32::try_from(d.saturating_sub(now).div_ceil(1_000_000)).unwrap_or(i32::MAX),
            None => -1,
        };
        let Some(rev) = sys::poll(&[(udp.as_fd(), libc::POLLIN), (conn.as_fd(), libc::POLLIN)], timeout)
            .map_err(|e| format!("poll: {e}"))?
        else {
            continue;
        };
        // kzc-psk never speaks unasked: anything on the connection is its
        // end.
        if rev.get(1).is_some_and(|r| *r != 0) {
            return Ok(End::Closed);
        }
        loop {
            match udp.recv_from(&mut buf) {
                Ok((n, from)) => {
                    if from != to {
                        continue;
                    }
                    let now = sys::boottime_ns().map_err(|e| format!("clock: {e}"))?;
                    let msg = buf.get(..n).unwrap_or(&[]);
                    let r = step(|| client.on_datagram(now, msg), udp, to, conn, &mut rec);
                    kozane_client::scrub_stack();
                    if let Some(end) = r? {
                        return Ok(end);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                // An ICMP error from an earlier send; retransmission covers it.
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => continue,
                Err(e) => return Err(format!("udp: {e}")),
            }
        }
    }
}

/// Connects to `kzc-psk`, retrying every second; `None` on a signal.
fn connect(path: &Path) -> Result<Option<OwnedFd>, String> {
    let mut said = false;
    loop {
        if sys::terminated() {
            return Ok(None);
        }
        let fd = sys::seqpacket().map_err(|e| format!("socket: {e}"))?;
        match sys::connect_unix(fd.as_fd(), path) {
            Ok(()) => return Ok(Some(fd)),
            Err(e) => {
                if !said {
                    eprintln!("kzc: {}: {e}; retrying", path.display());
                    said = true;
                }
                sys::sleep_ms(RETRY_MS);
            }
        }
    }
}

pub fn run(env: &Env) -> Result<(), String> {
    sys::no_dump().map_err(|e| format!("prctl: {e}"))?;
    sys::install_signal_handlers().map_err(|e| format!("signals: {e}"))?;
    let checker = Checker::system();
    let (m, port) = load(env, &checker)?;
    eprintln!(
        "kzc: gateway {} rp_digest {}; own rp_digest {}",
        m.rp_endpoint,
        hex(&secret_blob::blake2s(&[&m.gw_rp_pub])),
        hex(&secret_blob::blake2s(&[&m.rp_pub]))
    );
    let bind: SocketAddr = if m.rp_endpoint.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, port).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, port).into()
    };
    let udp = UdpSocket::bind(bind).map_err(|e| format!("udp {bind}: {e}"))?;
    udp.set_nonblocking(true).map_err(|e| format!("udp: {e}"))?;
    let path = env.path(ipc::SOCKET);
    while let Some(conn) = connect(&path)? {
        eprintln!("kzc: connected to kzc-psk");
        match session(&m, &udp, &conn)? {
            End::Terminated => break,
            End::Closed => eprintln!("kzc: kzc-psk closed the connection; reconnecting"),
        }
    }
    eprintln!("kzc: stopped");
    Ok(())
}
