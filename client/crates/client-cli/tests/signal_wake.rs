//! A stop signal handled on another thread still ends a poll already in
//! progress: only the self-pipe can wake it, since the polling thread has
//! SIGTERM blocked and so is never interrupted (M9 deviation D-26, code
//! review T5). A check of the flag before polling would sleep the full
//! timeout here. Its own test binary, since the handlers are process-wide.

#![allow(clippy::unwrap_used, unsafe_code)]

use std::os::fd::AsFd;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use kozane_client_cli::sys;

/// ppoll's number on AArch64 (poll(2) is ppoll there).
const SYS_PPOLL: &str = "73";

#[test]
fn a_signal_handled_elsewhere_wakes_a_blocked_poll() {
    sys::install_signal_handlers().unwrap();
    let (tid_tx, tid_rx) = mpsc::channel();
    let poller = std::thread::spawn(move || {
        // SAFETY: a local sigset, then this thread's own mask.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGTERM);
            assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()), 0);
        }
        // SAFETY: gettid cannot fail.
        tid_tx.send(unsafe { libc::gettid() }).unwrap();
        let (r, _w) = std::io::pipe().unwrap();
        let start = Instant::now();
        let got = sys::poll(&[(r.as_fd(), libc::POLLIN)], 5_000).unwrap();
        (got, start.elapsed())
    });
    let tid = tid_rx.recv().unwrap();
    // Until the poller is inside ppoll: the signal must land during the poll.
    let syscall = format!("/proc/self/task/{tid}/syscall");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::fs::read_to_string(&syscall).is_ok_and(|s| s.split(' ').next() == Some(SYS_PPOLL)) {
        assert!(Instant::now() < deadline, "signal-wake: the poller never entered ppoll");
        std::thread::yield_now();
    }
    // SAFETY: raise only signals this (main) thread, which has SIGTERM
    // unblocked and runs the handler.
    assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
    let (got, slept) = poller.join().unwrap();
    assert!(got.is_none(), "poll: the self-pipe did not wake it");
    assert!(slept < Duration::from_secs(1), "poll: slept {slept:?}; the signal was handled elsewhere and nothing woke it");
}
