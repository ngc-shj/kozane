//! `kzc` and `kzc-psk` against kernel WireGuard, inside `unshare -rn`
//! (VE25, P10): one uid (VE26), so the binaries run with `--root-prefix`
//! and `--user-map`, and the capability sets come from `setpriv` flags
//! parsed from the shipped unit files (I10.4).
//!
//! The gateway is the real `rosenpass-core` responder over UDP and a second
//! kernel WireGuard interface, `gw0`, driven with `wg` (tests only). The
//! outer test re-runs this binary under `unshare -rn`; the inner one runs
//! the cases in order, because they share the namespace and its interfaces.
//!
//! Failure messages naming a `kzc…:` needle are printed only when the
//! control they test is gone.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::fs;
use std::io::Read;
use std::net::UdpSocket;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use kozane_client_cli::{b64, ipc, sys};
use rosenpass_core::{Conf, Decaps, DecapsError, Kyber512, McEliece460896, Responder, Rng, RngError, SHK_LEN, SPK_LEN, Seams, Secret};
use rosenpass_wire::{MSG_INIT_CONF, MSG_INIT_HELLO, RESP_HELLO_LEN, SCT_LEN};
use secret_blob::pq;
use support::units::Unit;

const INNER: &str = "KZC_NETNS_INNER";
const KZC: &str = env!("CARGO_BIN_EXE_kzc");
const KZC_PSK: &str = env!("CARGO_BIN_EXE_kzc-psk");
const USERS: &str = "kozane-psk=0,kozane-net=0";
const WAIT: Duration = Duration::from_secs(20);

#[test]
fn kernel_wireguard_in_a_user_namespace() {
    if std::env::var_os(INNER).is_some() {
        return inner();
    }
    let out = Command::new("unshare")
        .args(["-rn", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "kernel_wireguard_in_a_user_namespace", "--nocapture", "--test-threads=1"])
        .env(INNER, "1")
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    print!("{text}");
    assert!(out.status.success(), "the namespace run failed");
    assert!(text.contains("netns: all cases passed"), "the namespace run did not reach the end");
}

// --- tools ------------------------------------------------------------------

fn run(prog: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(prog).args(args).output().unwrap_or_else(|e| panic!("{prog}: {e}"));
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

fn ok(prog: &str, args: &[&str]) -> String {
    let (ok, text) = run(prog, args);
    assert!(ok, "{prog} {args:?}: {text}");
    text
}

/// Polls `f` until it returns `Some`, or panics with `needle` at `WAIT`.
fn wait_for<T>(needle: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let end = Instant::now() + WAIT;
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < end, "{needle}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wg_psk(iface: &str) -> Option<String> {
    let (ok, text) = run("wg", &["show", iface, "preshared-keys"]);
    if !ok {
        return None;
    }
    let mut lines = text.lines();
    let line = lines.next()?;
    assert!(lines.next().is_none(), "{iface} has more than one peer: {text}");
    Some(line.split('\t').nth(1)?.to_string())
}

fn wg_field(iface: &str, what: &str) -> String {
    let text = ok("wg", &["show", iface, what]);
    text.lines().next().and_then(|l| l.split('\t').nth(1)).unwrap_or("").to_string()
}

fn link_exists(iface: &str) -> bool {
    run("ip", &["link", "show", iface]).0
}

fn zero_b64() -> String {
    b64::encode(&[0; 32])
}

fn caps(pid: u32) -> std::collections::BTreeMap<String, String> {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| k.starts_with("Cap") || *k == "NoNewPrivs")
        .map(|(k, v)| (k.to_string(), v.trim().to_string()))
        .collect()
}

// --- the gateway --------------------------------------------------------------

struct SysRng;

impl Rng for SysRng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        getrandom::fill(out).map_err(|_| RngError)
    }
}

struct GwDecaps(&'static [u8; pq::SK_LEN]);

impl Decaps for GwDecaps {
    fn decaps(&mut self, sct: &[u8; SCT_LEN]) -> Result<Secret<SHK_LEN>, DecapsError> {
        let mut shk = Secret::zero();
        mce460896::decaps(self.0, sct, shk.expose_mut());
        Ok(shk)
    }
}

fn mceliece_pair() -> (&'static [u8; SPK_LEN], &'static [u8; pq::SK_LEN]) {
    std::thread::Builder::new()
        .stack_size(16 << 20)
        .spawn(|| {
            let mut pk: Box<[u8; SPK_LEN]> = vec![0; SPK_LEN].into_boxed_slice().try_into().unwrap();
            let mut sk: Box<[u8; pq::SK_LEN]> = vec![0; pq::SK_LEN].into_boxed_slice().try_into().unwrap();
            mce460896::keypair(&mut |o| getrandom::fill(o).map_err(|_| mce460896::RngError), &mut pk, &mut sk).unwrap();
            (&*Box::leak(pk), &*Box::leak(sk))
        })
        .unwrap()
        .join()
        .unwrap()
}

struct Gateway {
    responder: Responder<'static>,
    sk: &'static [u8; pq::SK_LEN],
    udp: UdpSocket,
    start: Instant,
}

impl Gateway {
    fn now(&self) -> u64 {
        1_000_000_000 + u64::try_from(self.start.elapsed().as_nanos()).unwrap()
    }

    fn recv(&self, needle: &str) -> (Vec<u8>, std::net::SocketAddr) {
        let mut buf = vec![0u8; 4096];
        self.udp.set_read_timeout(Some(WAIT)).unwrap();
        let (n, from) = self.udp.recv_from(&mut buf).unwrap_or_else(|e| panic!("{needle}: {e}"));
        buf.truncate(n);
        (buf, from)
    }

    /// One full exchange with `kzc`: the OSK the gateway installs.
    fn exchange(&mut self) -> [u8; 32] {
        let (ih, from) = loop {
            let (m, from) = self.recv("kzc: no InitHello");
            if rosenpass_wire::peek_type(&m) == Ok(MSG_INIT_HELLO) {
                break (m, from);
            }
        };
        let now = self.now();
        self.responder.tick(now, &mut SysRng).unwrap();
        let mut out = [0u8; RESP_HELLO_LEN];
        let seams = &mut Seams {
            decaps: &mut GwDecaps(self.sk),
            kyber: &mut Kyber512,
            mceliece: &mut McEliece460896,
            rng: &mut SysRng,
        };
        self.responder.handle_init_hello(&ih, now, seams, &mut out).expect("gateway refused the InitHello");
        self.udp.send_to(&out, from).unwrap();
        // Retransmitted InitHellos may come first.
        let ic = loop {
            let (m, _) = self.recv("kzc: no InitConf");
            if rosenpass_wire::peek_type(&m) == Ok(MSG_INIT_CONF) {
                break m;
            }
        };
        let r = self.responder.handle_init_conf(&ic, self.now());
        let Ok(Conf::Fresh(p)) = r else {
            panic!("gateway refused the InitConf: {:?}", r.err());
        };
        let osk = *p.psk_install().osk.expose();
        let ed = self.responder.commit_conf(p, self.now()).unwrap();
        self.udp.send_to(&ed, from).unwrap();
        osk
    }
}

// --- the processes -------------------------------------------------------------

struct Env {
    root: PathBuf,
    spawned: std::cell::RefCell<Vec<u32>>,
    psk_flags: Vec<String>,
    net_flags: Vec<String>,
}

impl Env {
    fn path(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }

    fn seams(&self, users: &str) -> Vec<String> {
        vec!["--root-prefix".into(), self.root.display().to_string(), "--user-map".into(), users.into()]
    }

    fn spawn(&self, flags: &[String], bin: &str, users: &str, args: &[&str], log: &str) -> Child {
        let log = fs::File::create(self.root.join(log)).unwrap();
        let mut c = Command::new("setpriv");
        c.args(flags).arg("--").arg(bin).args(self.seams(users)).args(args);
        c.env("NOTIFY_SOCKET", self.root.join("notify")).stdout(Stdio::null()).stderr(log);
        let child = c.spawn().unwrap();
        self.spawned.borrow_mut().push(child.id());
        child
    }

    /// `kzc-psk`, started and READY.
    fn psk(&self, users: &str, notify: &UnixDatagram) -> Child {
        let child = self.spawn(&self.psk_flags, KZC_PSK, users, &[], "kzc-psk.log");
        notify.set_read_timeout(Some(WAIT)).unwrap();
        let mut buf = [0u8; 64];
        let n = notify.recv(&mut buf).unwrap_or_else(|e| panic!("kzc-psk: no READY=1 ({e}): {}", self.log("kzc-psk.log")));
        assert_eq!(&buf[..n], b"READY=1");
        child
    }

    fn kzc(&self) -> Child {
        self.spawn(&self.net_flags, KZC, USERS, &["up"], "kzc.log")
    }

    fn log(&self, name: &str) -> String {
        fs::read_to_string(self.root.join(name)).unwrap_or_default()
    }

    /// A connection to `kzc-psk`'s socket as the test's own uid.
    fn connect(&self) -> OwnedFd {
        let fd = sys::seqpacket().unwrap();
        sys::connect_unix(fd.as_fd(), &self.path(ipc::SOCKET)).unwrap();
        fd
    }
}

/// On every exit, a panic's included, the processes still running under
/// the scratch root are killed (the container allows no pid namespace)
/// and the root goes.
impl Drop for Env {
    fn drop(&mut self) {
        let root = self.root.display().to_string();
        for pid in self.spawned.borrow().iter() {
            let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            if String::from_utf8_lossy(&cmdline).contains(&root) {
                // SAFETY: kill takes integers only.
                unsafe { libc::kill(i32::try_from(*pid).unwrap_or(0), libc::SIGKILL) };
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn signal(child: &Child, sig: i32) {
    // SAFETY: kill takes integers only.
    assert_eq!(unsafe { libc::kill(i32::try_from(child.id()).unwrap(), sig) }, 0);
}

fn wait_exit(child: &mut Child) -> std::process::ExitStatus {
    let end = Instant::now() + WAIT;
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            return s;
        }
        assert!(Instant::now() < end, "process {} did not exit", child.id());
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn setup() -> (Env, UnixDatagram) {
    ok("ip", &["link", "set", "lo", "up"]);
    let root = std::env::temp_dir().join(format!("kzc-netns-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for d in ["etc/kozane", "var/lib", "run/kozane-psk"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    fs::set_permissions(root.join("run/kozane-psk"), fs::Permissions::from_mode(0o750)).unwrap();
    let notify = UnixDatagram::bind(root.join("notify")).unwrap();
    let env = Env {
        root,
        spawned: Default::default(),
        psk_flags: Unit::load("kozane-psk.service").setpriv(),
        net_flags: Unit::load("kozane-net.service").setpriv(),
    };
    (env, notify)
}

/// `kzc keygen`: modes, owners, the printed entry against independent
/// tools, and the refusal to overwrite. Returns the client's `wg_pub`.
fn keygen(env: &Env) -> String {
    let args: Vec<String> = env.seams(USERS).into_iter().chain(["keygen".to_string()]).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = ok(KZC, &args);
    let wg_pub = out
        .lines()
        .find_map(|l| l.strip_prefix("wg_pub = \""))
        .and_then(|l| l.strip_suffix('"'))
        .expect("keygen printed no wg_pub")
        .to_string();
    let digest = out.lines().find_map(|l| l.strip_prefix("# rp_digest = ")).expect("keygen printed no rp_digest").to_string();
    for (p, mode, len) in [
        ("var/lib/kozane-psk", 0o40700, None),
        ("var/lib/kozane-net", 0o40700, None),
        ("var/lib/kozane-psk/wg.sk", 0o100600, Some(32)),
        ("var/lib/kozane-psk/wg.pub", 0o100644, Some(32)),
        ("var/lib/kozane-net/rp.sk", 0o100600, Some(pq::LIBOQS_SK_LEN as u64)),
        ("var/lib/kozane-net/rp.pub", 0o100644, Some(SPK_LEN as u64)),
    ] {
        let m = fs::symlink_metadata(env.path(p)).unwrap();
        assert_eq!((m.mode(), m.uid()), (mode, 0), "{p}");
        if let Some(len) = len {
            assert_eq!(m.len(), len, "{p}");
        }
    }
    // The public key `wg pubkey` derives from wg.sk, and the digest Python
    // computes over rp.pub.
    let sk_b64 = b64::encode(&fs::read(env.path("var/lib/kozane-psk/wg.sk")).unwrap());
    let mut c = Command::new("wg").arg("pubkey").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    std::io::Write::write_all(c.stdin.as_mut().unwrap(), sk_b64.as_bytes()).unwrap();
    let derived = String::from_utf8(c.wait_with_output().unwrap().stdout).unwrap();
    assert_eq!(derived.trim(), wg_pub);
    assert_eq!(b64::encode(&fs::read(env.path("var/lib/kozane-psk/wg.pub")).unwrap()), wg_pub);
    let py = format!(
        "import hashlib;print(hashlib.blake2s(open('{}','rb').read()).hexdigest())",
        env.path("var/lib/kozane-net/rp.pub").display()
    );
    assert_eq!(ok("python3", &["-c", &py]).trim(), digest, "keygen digest differs from Python's blake2s");
    // A second run refuses and changes nothing.
    let before = fs::read(env.path("var/lib/kozane-psk/wg.sk")).unwrap();
    let (again, text) = run(KZC, &args);
    assert!(!again && text.contains("never overwritten"), "keygen overwrote: {text}");
    assert_eq!(fs::read(env.path("var/lib/kozane-psk/wg.sk")).unwrap(), before);
    eprintln!("netns: keygen ok");
    wg_pub
}

/// The gateway's keys, its responder, and its WireGuard interface `gw0`.
fn gateway(env: &Env, kz_wg_pub: &str) -> Gateway {
    let (gw_pub, gw_sk) = mceliece_pair();
    let gw_rp_path = env.path("etc/kozane/gw-rp.pub");
    fs::write(&gw_rp_path, &gw_pub[..]).unwrap();
    fs::set_permissions(&gw_rp_path, fs::Permissions::from_mode(0o644)).unwrap();
    let kz_rp: Vec<u8> = fs::read(env.path("var/lib/kozane-net/rp.pub")).unwrap();
    let kz_rp: &'static [u8; SPK_LEN] = Box::leak(kz_rp.into_boxed_slice().try_into().unwrap());
    let responder = Responder::new(gw_pub, &[kz_rp], &mut SysRng).unwrap();
    let udp = UdpSocket::bind("127.0.0.1:9999").unwrap();

    let gw_sk_path = env.path("gw-wg.sk");
    let mut wg_sk = [0u8; 32];
    getrandom::fill(&mut wg_sk).unwrap();
    fs::write(&gw_sk_path, b64::encode(&wg_sk)).unwrap();
    let mut c = Command::new("wg").arg("pubkey").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    std::io::Write::write_all(c.stdin.as_mut().unwrap(), b64::encode(&wg_sk).as_bytes()).unwrap();
    let gw_wg_pub = String::from_utf8(c.wait_with_output().unwrap().stdout).unwrap().trim().to_string();
    ok("ip", &["link", "add", "gw0", "type", "wireguard"]);
    let sk = gw_sk_path.display().to_string();
    ok("wg", &["set", "gw0", "private-key", &sk, "listen-port", "51820"]);
    ok("wg", &["set", "gw0", "peer", kz_wg_pub, "endpoint", "127.0.0.1:51821", "allowed-ips", "10.9.0.2/32"]);
    ok("ip", &["link", "set", "gw0", "up"]);

    let conf = format!(
        "interface = kz0\naddress = 10.9.0.2/24\nwg_listen_port = 51821\nwg_endpoint = 127.0.0.1:51820\n\
         rp_listen_port = 9998\nrp_endpoint = 127.0.0.1:9999\ngw_wg_pub = {gw_wg_pub}\n\
         gw_rp_pub_path = /etc/kozane/gw-rp.pub\nallowed_ips = 10.9.0.0/24, 10.9.1.0/24\n"
    );
    let conf_path = env.path("etc/kozane/client.conf");
    fs::write(&conf_path, conf).unwrap();
    fs::set_permissions(&conf_path, fs::Permissions::from_mode(0o644)).unwrap();
    Gateway { responder, sk: gw_sk, udp, start: Instant::now() }
}

/// Sets `gw0`'s PSK for the client and starts a handshake from `gw0`.
fn gateway_handshake(env: &Env, kz_wg_pub: &str, osk: &[u8; 32]) {
    let p = env.path("gw-psk");
    fs::write(&p, b64::encode(osk)).unwrap();
    let p = p.display().to_string();
    ok("wg", &["set", "gw0", "peer", kz_wg_pub, "preshared-key", &p, "persistent-keepalive", "1"]);
}

fn handshake_time(iface: &str) -> u64 {
    wg_field(iface, "latest-handshakes").parse().unwrap_or(0)
}

fn inner() {
    let (env, notify) = setup();
    let kz_wg_pub = keygen(&env);
    let mut gw = gateway(&env, &kz_wg_pub);

    // kozane-psk alone: a marked interface, routed, whose one peer has a
    // random PSK (neither zero nor an OSK).
    let mut psk = env.psk(USERS, &notify);
    let c = caps(psk.id());
    assert_eq!(c["NoNewPrivs"], "1");
    let bnd = u64::from_str_radix(&c["CapBnd"], 16).unwrap();
    assert_eq!(bnd & !(1u64 << 12), 0, // CAP_NET_ADMIN is capability 12
        "kzc-psk: CapBnd {bnd:x} beyond CAP_NET_ADMIN");
    assert!(ok("ip", &["-d", "link", "show", "kz0"]).contains("alias kozane-psk"));
    assert!(ok("ip", &["addr", "show", "kz0"]).contains("10.9.0.2/24"));
    assert!(ok("ip", &["route", "show", "dev", "kz0"]).contains("10.9.1.0/24"));
    let sock = fs::symlink_metadata(env.path(ipc::SOCKET)).unwrap();
    assert_eq!(sock.mode() & 0o777, 0o660);
    let psk0 = wg_psk("kz0").expect("kz0 missing");
    assert_eq!(wg_field("kz0", "endpoints"), "127.0.0.1:51820");
    assert!(psk0 != "(none)" && psk0 != zero_b64(), "kzc-psk: zero psk installed");
    eprintln!("netns: kzc-psk up");

    // kzc, with no capabilities, completes an exchange: kz0 holds the OSK
    // and a WireGuard session comes up on it.
    let mut kzc = env.kzc();
    let osk = gw.exchange();
    let c = caps(kzc.id());
    for k in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        assert_eq!(u64::from_str_radix(&c[k], 16).unwrap(), 0, "kzc: capabilities held ({k} {})", c[k]);
    }
    assert_eq!(c["NoNewPrivs"], "1", "kzc: capabilities held (no NoNewPrivs)");
    wait_for("kzc: OSK not installed", || (wg_psk("kz0")? == b64::encode(&osk)).then_some(()));
    gateway_handshake(&env, &kz_wg_pub, &osk);
    wait_for("netns: no WireGuard session on the OSK", || (handshake_time("kz0") != 0).then_some(()));
    eprintln!("netns: session on the OSK");

    // SIGTERM to kzc only: kzc-psk scrubs, so the session's keypairs go
    // with the removed peer and the new PSK is random.
    signal(&kzc, libc::SIGTERM);
    assert!(wait_exit(&mut kzc).success(), "kzc: {}", env.log("kzc.log"));
    let after = wait_for("kzc: psk survived exit", || wg_psk("kz0").filter(|p| *p != b64::encode(&osk)));
    assert_ne!(after, zero_b64(), "kzc-psk: zero psk installed");
    assert_eq!(handshake_time("kz0"), 0, "kzc: session survived scrub");
    assert_eq!(wg_field("kz0", "endpoints"), "127.0.0.1:51820");
    assert!(ok("wg", &["show", "kz0", "allowed-ips"]).contains("10.9.1.0/24"));
    eprintln!("netns: scrubbed on kzc exit");

    // kzc restarts: kzc-psk accepted the new connection.
    let mut kzc = env.kzc();
    let osk2 = gw.exchange();
    assert_ne!(osk2, osk);
    wait_for("kzc: OSK not installed after restart", || (wg_psk("kz0")? == b64::encode(&osk2)).then_some(()));
    signal(&kzc, libc::SIGINT);
    assert!(wait_exit(&mut kzc).success());
    wait_for("kzc: psk survived exit", || wg_psk("kz0").filter(|p| *p != b64::encode(&osk2)));
    eprintln!("netns: kzc restart ok");

    // SIGTERM to kzc-psk: no interface; a clean exit.
    signal(&psk, libc::SIGTERM);
    assert!(wait_exit(&mut psk).success(), "{}", env.log("kzc-psk.log"));
    assert!(!link_exists("kz0"), "kzc-psk: interface left after exit");
    assert!(!env.path(ipc::SOCKET).exists());

    // kzc-psk restarts under a running kzc: kzc reconnects, and its fresh
    // client scrubs and re-keys the new interface.
    let mut psk = env.psk(USERS, &notify);
    let mut kzc = env.kzc();
    let osk3 = gw.exchange();
    wait_for("kzc: OSK not installed", || (wg_psk("kz0")? == b64::encode(&osk3)).then_some(()));
    signal(&psk, libc::SIGTERM);
    assert!(wait_exit(&mut psk).success());
    let mut psk = env.psk(USERS, &notify);
    let fresh = wg_psk("kz0").unwrap();
    assert!(fresh != b64::encode(&osk3) && fresh != zero_b64(), "kzc-psk: restart kept the old PSK");
    let osk4 = gw.exchange();
    wait_for("kzc: no re-key after kzc-psk restarted", || (wg_psk("kz0")? == b64::encode(&osk4)).then_some(()));
    assert!(env.log("kzc.log").contains("reconnecting"), "{}", env.log("kzc.log"));
    eprintln!("netns: kzc reconnects after a kzc-psk restart");

    // SIGTERM to both: no interface.
    signal(&kzc, libc::SIGTERM);
    signal(&psk, libc::SIGTERM);
    wait_exit(&mut kzc);
    wait_exit(&mut psk);
    assert!(!link_exists("kz0"), "kzc-psk: interface left after exit");
    eprintln!("netns: exits delete the interface");

    // SIGKILL of kzc-psk leaves the marked interface; the next start
    // deletes and recreates it, with a fresh PSK.
    let mut psk = env.psk(USERS, &notify);
    let old = wg_psk("kz0").unwrap();
    signal(&psk, libc::SIGKILL);
    wait_exit(&mut psk);
    assert!(link_exists("kz0"));
    let mut psk = env.psk(USERS, &notify);
    let new = wg_psk("kz0").expect("kzc-psk: restart refused");
    assert_ne!(new, old, "kzc-psk: restart kept the old PSK");
    // And `kzc-psk cleanup` (ExecStopPost=) deletes a marked leftover.
    signal(&psk, libc::SIGKILL);
    wait_exit(&mut psk);
    let args: Vec<String> = env.seams(USERS).into_iter().chain(["cleanup".to_string()]).collect();
    ok(KZC_PSK, &args.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(!link_exists("kz0"), "kzc-psk: cleanup left the interface");
    eprintln!("netns: SIGKILL recovery ok");

    // A connection from a uid other than kozane-net's is refused: the
    // record gets no reply and changes nothing.
    let mut psk = env.psk("kozane-psk=0,kozane-net=4242", &notify);
    let before = wg_psk("kz0").unwrap();
    let conn = env.connect();
    let _ = sys::send(conn.as_fd(), &[ipc::TAG_SCRUB]);
    let mut reply = [0u8; 4];
    let n = sys::recv(conn.as_fd(), &mut reply).unwrap_or(Some(0));
    assert_eq!(n, Some(0), "kzc-psk: foreign peer accepted");
    assert_eq!(wg_psk("kz0").unwrap(), before, "kzc-psk: foreign peer accepted");
    signal(&psk, libc::SIGTERM);
    wait_exit(&mut psk);

    // A record that is neither Install(32) nor Scrub ends the connection,
    // and kzc-psk scrubs.
    let mut psk = env.psk(USERS, &notify);
    let before = wg_psk("kz0").unwrap();
    let conn = env.connect();
    sys::send(conn.as_fd(), &[ipc::TAG_INSTALL, 1, 2, 3]).unwrap();
    assert_eq!(sys::recv(conn.as_fd(), &mut reply).unwrap(), Some(0));
    wait_for("kzc-psk: bad record did not scrub", || wg_psk("kz0").filter(|p| *p != before));
    drop(conn);

    // A scrub against a vanished interface is fatal (the ack is checked).
    ok("ip", &["link", "del", "kz0"]);
    let conn = env.connect();
    sys::send(conn.as_fd(), &[ipc::TAG_SCRUB]).unwrap();
    let status = wait_exit(&mut psk);
    assert!(!status.success(), "kzc-psk: scrub unconfirmed");
    assert!(env.log("kzc-psk.log").contains("scrub"), "{}", env.log("kzc-psk.log"));
    drop(conn);
    eprintln!("netns: peer and record checks ok");

    // A foreign interface of the configured name is refused, untouched.
    ok("ip", &["link", "add", "kz0", "type", "wireguard"]);
    let mut psk = env.spawn(&env.psk_flags, KZC_PSK, USERS, &[], "kzc-psk.log");
    assert!(!wait_exit(&mut psk).success());
    let mut log = String::new();
    fs::File::open(env.root.join("kzc-psk.log")).unwrap().read_to_string(&mut log).unwrap();
    assert!(log.contains("not created by kzc-psk"), "{log}");
    assert!(link_exists("kz0"), "kzc-psk deleted a foreign interface");
    ok("ip", &["link", "del", "kz0"]);

    eprintln!("netns: all cases passed");
}
