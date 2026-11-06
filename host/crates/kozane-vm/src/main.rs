//! `kozane-vm`, the host launcher (M9 plan C4).
//!
//!   kozane-vm                         boot the node (as root, from a systemd unit)
//!   kozane-vm pin-firmware <release>  verify a release and pin its u-boot.bin
//!   kozane-vm --build-info            SEAMS=0|1, and the embedded argv's digest
//!
//! The boot starts as root. It opens every input itself and checks it: the
//! firmware pin, the swtpm key, the node's firmware and boot media. It
//! copies u-boot.bin into a sealed memfd and refuses to start unless its
//! digest is the pinned one (I4.2). It creates every cross-uid resource
//! itself: the TPM's socketpair and the two taps on their bridges. It then
//! starts swtpm as `kozane-swtpm`, QEMU as `kozane-qemu`, and a serial
//! reader as `kozane-qemu`, each with no capability and `no_new_privs`,
//! passing each its fds at the numbers `tools/vm.py` rendered. The argv is
//! `vm.py`'s, embedded at build time (`build/host/vm-args.json`); the
//! launcher adds nothing to it. It has no QMP and never parses guest output;
//! when any child exits it stops the others and exits, and systemd restarts
//! it (C3 row 1).

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod files;
mod kv;
mod net;
mod pin;
mod privs;
mod resolve;
mod serial;
mod spawn;
mod vmargs;

use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Child, ExitCode, Stdio};
use std::time::Duration;

use files::Mode;
use kv::{Pin, VmConf};
use resolve::{Resolver, Service};
use vmargs::VmArgs;

/// `tools/vm.py`'s `render_launcher_args()` output.
const VM_ARGS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../build/host/vm-args.json"));

pub const ETC: &str = "/etc/kozane";
const CONF: &str = "/etc/kozane/vm.conf";
pub const PIN: &str = "/etc/kozane/firmware.pin";
const SWTPM_KEY: &str = "/etc/kozane/swtpm.key";
pub const RELEASE_KEYS: &str = "/etc/kozane/release-keys";
/// u-boot.bin and the boot media (the release's image and descriptor, the
/// provisioned envelopes, the policy slots).
const NODE: &str = "/var/lib/kozane/node";
const LOG_DIR: &str = "/var/log/kozane";
const LOG: &str = "/var/log/kozane/console.log";
/// The serial reader child's name.
const READER: &str = "serial reader";

const OUTSIDE_TAP: &str = "kozane-out";
const INSIDE_TAP: &str = "kozane-in";

pub const FIRMWARE_MAX: u64 = 64 << 20;
/// tools/measure.py's MAX_IMAGE: U-Boot refuses a larger image.
const MEDIUM_MAX: u64 = 0x1000_0000;

/// How long a child gets to exit on its own, then after SIGTERM.
const GRACE: Duration = Duration::from_secs(5);

fn build_info() -> String {
    format!("SEAMS={}\nVM_ARGS_SHA256={}\n", u8::from(resolve::SEAMS), files::sha256_hex(VM_ARGS.as_bytes()))
}

fn read_text(path: &Path, owner: u32, mode: Mode) -> Result<String, String> {
    let mut f = files::open_checked(path, owner, mode)?;
    let bytes = files::read_bounded(&mut f, 4096, path)?;
    String::from_utf8(bytes).map_err(|_| format!("{}: not UTF-8", path.display()))
}

/// A child the launcher watches.
struct Running {
    name: &'static str,
    child: Child,
    pidfd: OwnedFd,
}

impl Running {
    fn start(name: &'static str, child: Child) -> Result<Self, String> {
        let pidfd = spawn::pidfd(child.id())?;
        Ok(Self { name, child, pidfd })
    }

    fn signal(&self, sig: libc::c_int) {
        // SAFETY: pidfd_send_signal on our own child's pidfd; a child that
        // has exited but is not reaped yet is still that child.
        unsafe { libc::syscall(libc::SYS_pidfd_send_signal, self.pidfd.as_raw_fd(), sig, std::ptr::null::<libc::siginfo_t>(), 0) };
    }

    /// Waits up to `limit` for the child to exit.
    fn exited_within(&mut self, limit: Duration) -> bool {
        let mut p = libc::pollfd { fd: self.pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let ms = libc::c_int::try_from(limit.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: one valid pollfd.
        unsafe { libc::poll(&mut p, 1, ms) > 0 }
    }

    /// Stops the child: its own exit, then SIGTERM, then SIGKILL.
    fn stop(mut self) {
        if !self.exited_within(GRACE) {
            self.signal(libc::SIGTERM);
            if !self.exited_within(GRACE) {
                self.signal(libc::SIGKILL);
            }
        }
        match self.child.wait() {
            Ok(status) => eprintln!("kozane-vm: {} stopped ({status})", self.name),
            Err(e) => eprintln!("kozane-vm: {}: {e}", self.name),
        }
    }
}

fn stop_all(children: Vec<Running>) {
    for c in children {
        c.stop();
    }
}

/// SIGTERM, SIGINT and SIGHUP, blocked and read through a signalfd; the
/// children start with an empty mask (spawn).
fn signal_fd() -> Result<OwnedFd, String> {
    // SAFETY: sigset manipulation on a local set, then sigprocmask and
    // signalfd with valid pointers.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::sigaddset(&mut set, s);
        }
        if libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) == -1 {
            return Err(format!("sigprocmask: {}", std::io::Error::last_os_error()));
        }
        let fd = libc::signalfd(-1, &set, libc::SFD_CLOEXEC);
        if fd == -1 {
            return Err(format!("signalfd: {}", std::io::Error::last_os_error()));
        }
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// Everything the boot needs, opened and checked before any child starts.
struct Opened {
    conf: VmConf,
    firmware: File,
    media: Vec<File>,
    key: File,
    log: File,
}

fn open_inputs(res: &Resolver, args: &VmArgs) -> Result<Opened, String> {
    let (owner, _) = res.owner();
    files::check_dir(&res.path(ETC), owner)?;
    let conf_path = res.path(CONF);
    let conf = VmConf::parse(&read_text(&conf_path, owner, Mode::NotShared)?).map_err(|e| format!("{}: {e}", conf_path.display()))?;
    // The two programs run with the TPM socket, the taps, the firmware and
    // the swtpm key: checked like the inputs they are given.
    for program in [&conf.qemu, &conf.swtpm] {
        files::check_program(Path::new(program), &res.dir_owners())?;
    }
    let pin_path = res.path(PIN);
    let pin = Pin::parse(&read_text(&pin_path, owner, Mode::Exact(0o600))?).map_err(|e| format!("{}: {e}", pin_path.display()))?;

    let node = res.path(NODE);
    files::check_dir(&node, owner)?;
    let fw_path = node.join("u-boot.bin");
    let firmware = files::sealed_copy("u-boot.bin", &mut files::open_checked(&fw_path, owner, Mode::NotShared)?, FIRMWARE_MAX, &fw_path)?;
    // The digest of what QEMU will read: the sealed copy, not the file.
    let found = files::sha256_hex(&files::read_all_at(&firmware, FIRMWARE_MAX)?);
    if found != pin.firmware_sha256 {
        return Err(format!(
            "{}: firmware {found} is not the pinned {} (release_seq {}); refusing to start",
            fw_path.display(),
            pin.firmware_sha256,
            pin.release_seq
        ));
    }
    let media = args
        .media
        .iter()
        .map(|m| {
            let p = node.join(&m.name);
            files::sealed_copy(&m.name, &mut files::open_checked(&p, owner, Mode::NotShared)?, MEDIUM_MAX, &p)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let key = files::open_checked(&res.path(SWTPM_KEY), owner, Mode::Exact(0o600))?;

    let log_dir = res.path(LOG_DIR);
    files::check_dir(&log_dir, owner)?;
    let log_path = res.path(LOG);
    let log = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&log_path)
        .map_err(|e| format!("{}: {e}", log_path.display()))?;
    let meta = log.metadata().map_err(|e| format!("{}: {e}", log_path.display()))?;
    files::check_meta(&log_path, &meta, owner, Mode::Exact(0o600), false)?;
    Ok(Opened { conf, firmware, media, key, log })
}

fn boot(res: &Resolver) -> Result<bool, String> {
    let args = VmArgs::parse(VM_ARGS).map_err(|e| format!("embedded vm-args.json: {e}"))?;
    // Every fd from here on lands above the numbers the children get.
    let first_free = args.max_fd().max(serial::HEARTBEAT_FD) + 1;
    let _reserved = spawn::reserve_low_fds(first_free)?;
    let opened = open_inputs(res, &args)?;
    let (tpm_qemu, tpm_swtpm) = spawn::socketpair()?;
    let outside = net::open_tap(OUTSIDE_TAP, &opened.conf.outside_bridge)?;
    let inside = net::open_tap(INSIDE_TAP, &opened.conf.inside_bridge)?;
    let swtpm_creds = res.creds(Service::Swtpm)?;
    let qemu_creds = res.creds(Service::Qemu)?;
    let reader_creds = res.creds(Service::Reader)?;
    let signals = signal_fd()?;

    let state = format!("dir={}", res.path(&args.swtpm_state).display());
    let swtpm_args: Vec<String> = args.swtpm.iter().map(|a| if *a == args.state_arg() { state.clone() } else { a.clone() }).collect();

    let mut children = Vec::new();
    let started = (|| -> Result<OwnedFd, String> {
        let s = &args.swtpm_fds;
        let swtpm = spawn::spawn(spawn::Spec {
            program: &opened.conf.swtpm,
            args: &swtpm_args,
            fds: vec![(tpm_swtpm.as_raw_fd(), s.ctrl), (opened.key.as_raw_fd(), s.key)],
            stdin: Stdio::null(),
            stdout: Stdio::inherit(),
            creds: &swtpm_creds,
            memlock: false,
            first_free,
        })?;
        children.push(Running::start("swtpm", swtpm)?);

        let (serial_r, serial_w) = spawn::pipe()?;
        let (beat_r, beat_w) = spawn::pipe()?;
        let reader = spawn::spawn(spawn::Spec {
            program: "/proc/self/exe",
            args: &["serial-reader".to_string()],
            fds: vec![(opened.log.as_raw_fd(), serial::LOG_FD), (beat_w.as_raw_fd(), serial::HEARTBEAT_FD)],
            stdin: Stdio::from(serial_r),
            stdout: Stdio::null(),
            creds: &reader_creds,
            memlock: false,
            first_free,
        })?;
        children.push(Running::start(READER, reader)?);

        let q = &args.qemu_fds;
        let mut fds = vec![
            (opened.firmware.as_raw_fd(), q.firmware),
            (tpm_qemu.as_raw_fd(), q.tpm),
            (outside.as_raw_fd(), q.outside),
            (inside.as_raw_fd(), q.inside),
        ];
        fds.extend(opened.media.iter().zip(&args.media).map(|(f, m)| (f.as_raw_fd(), m.fd)));
        let qemu = spawn::spawn(spawn::Spec {
            program: &opened.conf.qemu,
            args: &args.qemu,
            fds,
            stdin: Stdio::null(),
            stdout: Stdio::from(serial_w),
            creds: &qemu_creds,
            memlock: true,
            first_free,
        })?;
        children.push(Running::start("qemu", qemu)?);
        // The launcher keeps only the heartbeat's read end.
        Ok(beat_r)
    })();
    // Every resource now lives in the children only: the launcher's copies
    // close, so QEMU's exit is swtpm's and the reader's end of input.
    drop((opened, tpm_qemu, tpm_swtpm, outside, inside));
    match started {
        Ok(beat) => Ok(supervise(children, File::from(beat), &signals)),
        Err(e) => {
            stop_all(children);
            Err(e)
        }
    }
}

/// Watches the children until one exits, then stops the rest. True when
/// QEMU ended the run cleanly or a stop signal did.
fn supervise(mut children: Vec<Running>, mut beat: File, signals: &OwnedFd) -> bool {
    let mut beats: u64 = 0;
    let mut beat_open = true;
    let mut stopping = false;
    let first = loop {
        let mut polls = vec![
            libc::pollfd { fd: signals.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: if beat_open { beat.as_raw_fd() } else { -1 }, events: libc::POLLIN, revents: 0 },
        ];
        polls.extend(children.iter().map(|c| libc::pollfd { fd: c.pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 }));
        // SAFETY: `polls` is a valid array of its length.
        if unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, -1) } == -1 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("kozane-vm: poll: {}", std::io::Error::last_os_error());
            break None;
        }
        let ready = |i: usize| polls.get(i).is_some_and(|p| p.revents != 0);
        if ready(0) {
            let mut info = [0u8; std::mem::size_of::<libc::signalfd_siginfo>()];
            // SAFETY: reads one siginfo into a buffer of its size.
            unsafe { libc::read(signals.as_raw_fd(), info.as_mut_ptr().cast(), info.len()) };
            if !stopping {
                eprintln!("kozane-vm: stop requested; stopping QEMU");
                stopping = true;
                if let Some(q) = children.iter().find(|c| c.name == "qemu") {
                    q.signal(libc::SIGTERM);
                }
            }
        }
        if ready(1) {
            let mut buf = [0u8; 64];
            match beat.read(&mut buf) {
                Ok(0) | Err(_) => beat_open = false,
                Ok(n) => {
                    if beats == 0 {
                        eprintln!("kozane-vm: guest heartbeat");
                    }
                    beats = beats.saturating_add(n as u64);
                }
            }
        }
        if let Some(i) = (0..children.len()).find(|&i| ready(i + 2)) {
            break Some(children.remove(i));
        }
    };
    let clean = match first {
        Some(mut c) => {
            let success = reap(&mut c);
            if c.name == READER && success && !stopping {
                // The reader ends at EOF, and QEMU closing the console on
                // its way out is what causes that, so the reader can be
                // seen first: QEMU's own exit decides, if it follows.
                qemu_after_reader(&mut children)
            } else {
                clean_exit(c.name, stopping, success)
            }
        }
        None => false,
    };
    stop_all(children);
    eprintln!("kozane-vm: {beats} heartbeats");
    clean
}

/// How long QEMU may take to exit after its console closed.
const QEMU_AFTER_READER_MS: libc::c_int = 5000;

/// Waits for an exited child; whether it succeeded.
fn reap(c: &mut Running) -> bool {
    let status = c.child.wait();
    eprintln!("kozane-vm: {} exited ({})", c.name, status.as_ref().map(|s| s.to_string()).unwrap_or_else(|e| e.to_string()));
    status.is_ok_and(|s| s.success())
}

/// After the reader's clean EOF: whether QEMU exits, successfully, within
/// `QEMU_AFTER_READER_MS`. A QEMU still running is stopped by `stop_all`.
fn qemu_after_reader(children: &mut Vec<Running>) -> bool {
    let Some(i) = children.iter().position(|c| c.name == "qemu") else {
        return false;
    };
    let Some(q) = children.get(i) else {
        return false;
    };
    let mut poll = libc::pollfd { fd: q.pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    // SAFETY: one valid pollfd.
    if unsafe { libc::poll(&mut poll, 1, QEMU_AFTER_READER_MS) } != 1 {
        eprintln!("kozane-vm: the console closed and QEMU did not exit");
        return false;
    }
    let mut q = children.remove(i);
    clean_exit(q.name, false, reap(&mut q))
}

/// Whether the first child to exit ends the boot cleanly. After a requested
/// stop any order is clean: QEMU closes the TPM socket on its way out, so
/// swtpm may exit first. Otherwise only QEMU's own success is: swtpm or the
/// serial reader exiting on its own means the VM lost a part it needs.
fn clean_exit(first: &str, stopping: bool, success: bool) -> bool {
    stopping || (first == "qemu" && success)
}

fn run(mut args: Vec<String>) -> Result<ExitCode, String> {
    let res = Resolver::from_args(&mut args)?;
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        [] => {
            let clean = boot(&res)?;
            Ok(if clean { ExitCode::SUCCESS } else { ExitCode::FAILURE })
        }
        ["--build-info"] => {
            print!("{}", build_info());
            Ok(ExitCode::SUCCESS)
        }
        ["pin-firmware", release] => {
            let pin = pin::pin_firmware(&mut privs::RealSys, &res, Path::new(release)).map_err(|e| format!("pin-firmware: refused: {e}"))?;
            println!("kozane-vm: pinned firmware {} from release_seq {}", pin.firmware_sha256, pin.release_seq);
            Ok(ExitCode::SUCCESS)
        }
        ["serial-reader"] => {
            serial::reader_main()?;
            Ok(ExitCode::SUCCESS)
        }
        _ => Err("usage: kozane-vm [pin-firmware <release-dir> | --build-info]".into()),
    }
}

fn main() -> ExitCode {
    // Nothing the launcher creates is meant for anyone else.
    // SAFETY: umask cannot fail.
    unsafe { libc::umask(0o077) };
    match run(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("kozane-vm: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
