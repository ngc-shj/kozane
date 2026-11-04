//! The unit socket between `kzc` and `kzc-psk` (D6): SOCK_SEQPACKET, one
//! record per request, and a one-byte `OK` reply after each one is done.
//!
//! - `Install`: tag 1, then the 32-byte PSK;
//! - `Scrub`: tag 2 alone.
//!
//! Anything else, a record of another length included, ends the
//! connection. `kzc-psk` accepts a connection only from `kozane-net`'s uid
//! (`SO_PEERCRED`).

use kozane_client::Secret;

pub const SOCKET: &str = "/run/kozane-psk/kzc.sock";
pub const TAG_INSTALL: u8 = 1;
pub const TAG_SCRUB: u8 = 2;
pub const OK: u8 = 0;
pub const INSTALL_LEN: usize = 33;
/// The receive buffer: larger than any valid record, so an oversized one
/// is seen as such.
pub const RECORD_MAX: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// The PSK was copied into the caller's buffer.
    Install,
    Scrub,
}

/// Decodes one record of real length `len` from `buf`. An `Install`'s PSK
/// goes to `psk`.
pub fn decode(buf: &[u8], len: usize, psk: &mut Secret<32>) -> Option<Request> {
    let rec = buf.get(..len)?;
    match rec {
        [TAG_SCRUB] => Some(Request::Scrub),
        [TAG_INSTALL, key @ ..] if key.len() == 32 => {
            psk.expose_mut().copy_from_slice(key);
            Some(Request::Install)
        }
        _ => None,
    }
}

/// `Install(psk)` into `out`.
pub fn encode_install(psk: &Secret<32>, out: &mut [u8; INSTALL_LEN]) {
    let (tag, key) = out.split_at_mut(1);
    tag.copy_from_slice(&[TAG_INSTALL]);
    key.copy_from_slice(psk.expose());
}

/// Only `kozane-net` may connect (I10.3).
pub fn admit(peer_uid: u32, kozane_net_uid: u32) -> bool {
    peer_uid == kozane_net_uid
}
