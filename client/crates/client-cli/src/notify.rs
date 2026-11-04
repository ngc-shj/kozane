//! sd_notify(3), in-tree: `READY=1` to `$NOTIFY_SOCKET`, for
//! `Type=notify` (D6). Without the variable it does nothing.

use std::io;

use crate::sys;

pub fn ready() -> io::Result<()> {
    match std::env::var_os("NOTIFY_SOCKET") {
        Some(s) => sys::notify_datagram(&s, b"READY=1"),
        None => Ok(()),
    }
}
