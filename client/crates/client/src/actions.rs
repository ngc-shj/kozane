//! What the client asks of its shell (M9 plan C8): fixed capacity, and a
//! push past it is an error, never a drop.

use core::fmt;

use rosenpass_wire::{INIT_CONF_LEN, INIT_HELLO_LEN};

use crate::{Error, Secret};

/// The longest datagram the client sends: an InitHello.
pub const MAX_DATAGRAM: usize = INIT_HELLO_LEN;
/// The most actions one call returns: an authenticated RespHello's
/// `InstallPsk` and InitConf.
pub const MAX_ACTIONS: usize = 2;
/// A WireGuard PSK: Rosenpass's OSK.
pub const PSK_LEN: usize = 32;

const _: () = assert!(INIT_CONF_LEN <= MAX_DATAGRAM);
const _: () = assert!(PSK_LEN == rosenpass_core::KEY_LEN);

/// One UDP payload for `Config.rp_endpoint`.
pub struct Datagram {
    buf: [u8; MAX_DATAGRAM],
    len: usize,
}

impl Datagram {
    pub(crate) fn new(bytes: &[u8]) -> Result<Self, Error> {
        let mut buf = [0u8; MAX_DATAGRAM];
        buf.get_mut(..bytes.len()).ok_or(Error::Full)?.copy_from_slice(bytes);
        Ok(Self { buf, len: bytes.len() })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }
}

// `Send` inline, not boxed: `Actions` is a fixed array, and no action
// allocates.
#[allow(clippy::large_enum_variant)]
pub enum Action {
    /// Send these bytes to `Config.rp_endpoint`.
    Send(Datagram),
    /// Set the gateway peer's WireGuard PSK.
    InstallPsk(Secret<PSK_LEN>),
    /// Remove the gateway peer and re-add it with a random PSK (D6), which
    /// drops every WireGuard keypair.
    Scrub,
}

/// Never shows the PSK.
impl fmt::Debug for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Send(d) => write!(f, "Send({} bytes)", d.len),
            Action::InstallPsk(_) => f.write_str("InstallPsk(..)"),
            Action::Scrub => f.write_str("Scrub"),
        }
    }
}

/// The actions of one call, in the order the shell carries them out.
#[derive(Debug)]
pub struct Actions {
    slots: [Option<Action>; MAX_ACTIONS],
    len: usize,
}

impl Actions {
    pub(crate) fn new() -> Self {
        Self { slots: [const { None }; MAX_ACTIONS], len: 0 }
    }

    pub(crate) fn push(&mut self, action: Action) -> Result<(), Error> {
        let slot = self.slots.get_mut(self.len).ok_or(Error::Full)?;
        *slot = Some(action);
        self.len = self.len.checked_add(1).ok_or(Error::Full)?;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = &Action> {
        self.slots.iter().flatten()
    }
}

impl IntoIterator for Actions {
    type Item = Action;
    type IntoIter = core::iter::Flatten<core::array::IntoIter<Option<Action>, MAX_ACTIONS>>;

    fn into_iter(self) -> Self::IntoIter {
        self.slots.into_iter().flatten()
    }
}
