//! A stop signal that lands before `poll` still ends it: the loops check
//! `terminated()` and then poll, and a signal in between must not leave
//! them asleep to the timeout (M9 deviation D-26). Its own test binary,
//! since the handlers and the flag are process-wide.

#![allow(clippy::unwrap_used, unsafe_code)]

use std::os::fd::AsFd;
use std::time::{Duration, Instant};

use kozane_client_cli::sys;

#[test]
fn a_signal_before_poll_ends_the_poll_at_once() {
    sys::install_signal_handlers().unwrap();
    // SAFETY: raise only sends this process a signal, which the handler
    // just installed catches.
    assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
    assert!(sys::terminated());
    let start = Instant::now();
    let (r, _w) = std::io::pipe().unwrap();
    let got = sys::poll(&[(r.as_fd(), libc::POLLIN)], 5_000).unwrap();
    assert!(got.is_none(), "poll: the signal was lost");
    assert!(start.elapsed() < Duration::from_secs(1), "poll: slept {:?} after the signal", start.elapsed());
}
