//! The C ABI over `kozane-client` (M9 plan C9). `include/kozane_client.h`
//! is cbindgen's output for this file.
//!
//! Every export catches panics and returns `KZ_ERR_INTERNAL`; a handle that
//! panicked answers `KZ_ERR_INTERNAL` from then on, `kz_client_free` aside.
//! There are no foreign callbacks. The handle (the client, its handshake
//! secrets and the queued PSKs) is locked in memory and kept out of core
//! dumps, as are the keys `kz_client_new` copies.

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
#![allow(non_camel_case_types)]

use core::ffi::c_int;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};

use kozane_client::{Action, Actions, Client, Config, Error, Keys, Secret};

/// Success.
pub const KZ_OK: c_int = 0;
/// Nothing to report: no queued action, or no deadline.
pub const KZ_NONE: c_int = 1;
/// A null pointer, a wrong length or an unknown address family.
pub const KZ_ERR_INVALID: c_int = -1;
/// `cap` is too small for the next action, which stays queued; `*kind` and
/// `*len` say what it needs.
pub const KZ_ERR_BUFFER: c_int = -2;
/// Actions are still queued: take them all before the next `on_*` call.
/// Nothing was processed.
pub const KZ_ERR_BUSY: c_int = -3;
/// A panic inside the library; the handle is unusable except for
/// `kz_client_free`.
pub const KZ_ERR_INTERNAL: c_int = -4;
/// The OS RNG failed. Nothing was sent; stop the client.
pub const KZ_ERR_RNG: c_int = -5;
/// The datagram was refused; drop it. The client is unchanged.
pub const KZ_ERR_REJECTED: c_int = -6;
/// `now` went backwards.
pub const KZ_ERR_CLOCK: c_int = -7;
/// Key memory could not be locked (mlock) or kept out of core dumps.
pub const KZ_ERR_MEMORY: c_int = -8;

/// Send the `len` bytes in `buf` to the configured `rp_endpoint`.
pub const KZ_ACTION_SEND: c_int = 1;
/// Install the `KZ_PSK_LEN` bytes in `buf` as the gateway peer's
/// WireGuard PSK, then wipe `buf`.
pub const KZ_ACTION_INSTALL_PSK: c_int = 2;
/// Remove the gateway peer and re-add it with a random PSK. No payload.
pub const KZ_ACTION_SCRUB: c_int = 3;

/// The largest `KZ_ACTION_SEND` payload.
pub const KZ_MAX_DATAGRAM: usize = 1092;
/// The most actions one `on_*` call queues, and the queue's size.
pub const KZ_MAX_ACTIONS: usize = 2;
/// A `KZ_ACTION_INSTALL_PSK` payload.
pub const KZ_PSK_LEN: usize = 32;
/// A Classic McEliece 460896 public key: `rp.pub` and the gateway's key.
pub const KZ_RP_PUB_LEN: usize = 524160;
/// `rp.sk`, in the liboqs layout.
pub const KZ_RP_SK_LEN: usize = 13568;

/// `kz_sockaddr.family` for IPv4: the address is `addr[0..4]`, and the
/// other twelve bytes are zero.
pub const KZ_FAMILY_IPV4: u16 = 4;
/// `kz_sockaddr.family` for IPv6: the address is all of `addr`.
pub const KZ_FAMILY_IPV6: u16 = 6;

const _: () = assert!(KZ_MAX_DATAGRAM == kozane_client::MAX_DATAGRAM);
const _: () = assert!(KZ_MAX_ACTIONS == kozane_client::MAX_ACTIONS);
const _: () = assert!(KZ_PSK_LEN == kozane_client::PSK_LEN);
const _: () = assert!(KZ_RP_PUB_LEN == kozane_client::SPK_LEN);
const _: () = assert!(KZ_RP_SK_LEN == kozane_client::RP_SK_LEN);

/// An IP address and port, both in host byte order.
#[repr(C)]
pub struct kz_sockaddr {
    pub family: u16,
    pub addr: [u8; 16],
    pub port: u16,
}

#[repr(C)]
pub struct kz_config {
    /// The gateway's Rosenpass address.
    pub rp_endpoint: kz_sockaddr,
    /// The gateway's WireGuard public key.
    pub gw_wg_pub: [u8; 32],
    /// The gateway's pinned Rosenpass public key, `KZ_RP_PUB_LEN` bytes.
    pub gw_rp_pub: *const u8,
    pub gw_rp_pub_len: usize,
}

/// The client's Rosenpass key pair. `kz_client_new` copies both; the
/// caller wipes the `rp_sk` buffer it passed in.
#[repr(C)]
pub struct kz_keys {
    /// `rp.pub`, `KZ_RP_PUB_LEN` bytes.
    pub rp_pub: *const u8,
    pub rp_pub_len: usize,
    /// `rp.sk`, `KZ_RP_SK_LEN` bytes.
    pub rp_sk: *const u8,
    pub rp_sk_len: usize,
}

/// One queued action. A PSK sits in `psk` until it is taken.
struct Slot {
    kind: c_int,
    len: usize,
    datagram: [u8; KZ_MAX_DATAGRAM],
    psk: Secret<KZ_PSK_LEN>,
}

/// The client and its queue. Opaque to C.
pub struct kz_client {
    client: Client,
    slots: [Slot; KZ_MAX_ACTIONS],
    head: usize,
    queued: usize,
    poisoned: bool,
}

impl kz_client {
    fn queue(&mut self, actions: Actions) -> Result<(), c_int> {
        for (i, action) in actions.into_iter().enumerate() {
            let slot = self.slots.get_mut(i).ok_or(KZ_ERR_INTERNAL)?;
            match action {
                Action::Send(d) => {
                    let bytes = d.as_bytes();
                    slot.datagram.get_mut(..bytes.len()).ok_or(KZ_ERR_INTERNAL)?.copy_from_slice(bytes);
                    (slot.kind, slot.len) = (KZ_ACTION_SEND, bytes.len());
                }
                // `psk` drops (and is wiped) at the end of this arm.
                Action::InstallPsk(psk) => {
                    slot.psk.expose_mut().copy_from_slice(psk.expose());
                    (slot.kind, slot.len) = (KZ_ACTION_INSTALL_PSK, KZ_PSK_LEN);
                }
                Action::Scrub => (slot.kind, slot.len) = (KZ_ACTION_SCRUB, 0),
            }
            self.queued = i.checked_add(1).ok_or(KZ_ERR_INTERNAL)?;
        }
        self.head = 0;
        Ok(())
    }

    /// `on_*` runs only with an empty queue, which holds one call's worth.
    fn process(&mut self, f: impl FnOnce(&mut Client) -> Result<Actions, Error>) -> c_int {
        if self.queued != 0 {
            return KZ_ERR_BUSY;
        }
        match f(&mut self.client) {
            Ok(actions) => match self.queue(actions) {
                Ok(()) => KZ_OK,
                Err(code) => code,
            },
            Err(e) => status(e),
        }
    }
}

fn status(e: Error) -> c_int {
    match e {
        Error::Rng => KZ_ERR_RNG,
        Error::Protocol(_) => KZ_ERR_REJECTED,
        Error::Clock => KZ_ERR_CLOCK,
        Error::InvalidKey => KZ_ERR_INVALID,
        Error::Memory => KZ_ERR_MEMORY,
        Error::Full => KZ_ERR_INTERNAL,
    }
}

/// Runs `f` on the handle; a panic poisons it.
///
/// # Safety
///
/// `h` is null or a live handle from `kz_client_new`, not used elsewhere
/// for the duration of the call.
unsafe fn with_handle(h: *mut kz_client, f: impl FnOnce(&mut kz_client) -> c_int) -> c_int {
    // SAFETY: the caller's contract.
    let Some(handle) = (unsafe { h.as_mut() }) else {
        return KZ_ERR_INVALID;
    };
    if handle.poisoned {
        return KZ_ERR_INTERNAL;
    }
    match catch_unwind(AssertUnwindSafe(|| f(handle))) {
        Ok(code) => code,
        Err(_) => {
            // SAFETY: as above; the closure's borrow ended with the unwind.
            if let Some(handle) = unsafe { h.as_mut() } {
                handle.poisoned = true;
            }
            KZ_ERR_INTERNAL
        }
    }
}

/// `len` bytes at `ptr`, or None for a null pointer.
///
/// # Safety
///
/// A non-null `ptr` is valid for reads of `len` bytes.
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    // SAFETY: the caller's contract.
    (!ptr.is_null()).then(|| unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// Whether `alen` bytes at `a` and `blen` bytes at `b` share a byte. The
/// C contract does not keep the caller's pointers apart, and Rust's does:
/// an overlap is refused instead of becoming two aliasing writes.
fn overlaps(a: *const u8, alen: usize, b: *const u8, blen: usize) -> bool {
    let (a, b) = (a.addr(), b.addr());
    alen != 0 && blen != 0 && a < b.saturating_add(blen) && b < a.saturating_add(alen)
}

/// Whether `len` bytes at `p` reach into the handle's own memory.
fn in_handle(h: *const kz_client, p: *const u8, len: usize) -> bool {
    overlaps(h.cast(), size_of::<kz_client>(), p, len)
}

fn socket_addr(a: &kz_sockaddr) -> Option<SocketAddr> {
    let ip = match a.family {
        KZ_FAMILY_IPV4 => {
            let (v4, rest) = a.addr.split_first_chunk::<4>()?;
            if rest.iter().any(|&b| b != 0) {
                return None;
            }
            Ipv4Addr::from(*v4).into()
        }
        KZ_FAMILY_IPV6 => Ipv6Addr::from(a.addr).into(),
        _ => return None,
    };
    Some(SocketAddr::new(ip, a.port))
}

/// Creates a client and queues its first action, `KZ_ACTION_SCRUB`.
///
/// Every call on a handle needs about 160 KiB of free stack: the client
/// zeroes 128 KiB below its frame after each handshake step, so no secret
/// is left there (M9 deviation D-16). Call it from a thread whose stack has
/// that room; a small pthread stack would overflow.
///
/// # Safety
///
/// `config` and `keys` point to valid structures whose buffers are valid
/// for their lengths; `out` is valid for a write. On `KZ_OK`, `*out` holds
/// a handle for `kz_client_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_client_new(config: *const kz_config, keys: *const kz_keys, out: *mut *mut kz_client) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the caller's contract.
        let (Some(config), Some(keys)) = (unsafe { config.as_ref() }, unsafe { keys.as_ref() }) else {
            return KZ_ERR_INVALID;
        };
        if out.is_null() {
            return KZ_ERR_INVALID;
        }
        // SAFETY: the caller's contract.
        let (Some(gw_rp_pub), Some(rp_pub), Some(rp_sk)) = (unsafe {
            (
                bytes(config.gw_rp_pub, config.gw_rp_pub_len),
                bytes(keys.rp_pub, keys.rp_pub_len),
                bytes(keys.rp_sk, keys.rp_sk_len),
            )
        }) else {
            return KZ_ERR_INVALID;
        };
        let Some(rp_endpoint) = socket_addr(&config.rp_endpoint) else {
            return KZ_ERR_INVALID;
        };
        match new(rp_endpoint, gw_rp_pub, config.gw_wg_pub, rp_pub, rp_sk) {
            Ok(handle) => {
                // SAFETY: `out` is valid for a write (the caller's
                // contract); the input borrows are no longer used.
                unsafe { out.write(Box::into_raw(handle)) };
                KZ_OK
            }
            Err(code) => code,
        }
    }))
    .unwrap_or(KZ_ERR_INTERNAL)
}

fn new(
    rp_endpoint: SocketAddr,
    gw_rp_pub: &[u8],
    gw_wg_pub: [u8; 32],
    rp_pub: &[u8],
    rp_sk: &[u8],
) -> Result<Box<kz_client>, c_int> {
    let config = Config::new(rp_endpoint, gw_rp_pub, gw_wg_pub).map_err(status)?;
    let keys = Keys::new(rp_pub, rp_sk).map_err(status)?;
    let (client, first) = Client::new(config, keys).map_err(status)?;
    let empty = || Slot { kind: 0, len: 0, datagram: [0; KZ_MAX_DATAGRAM], psk: Secret::zero() };
    let mut handle = Box::new(kz_client { client, slots: [empty(), empty()], head: 0, queued: 0, poisoned: false });
    // Before any handshake secret or PSK enters the handle.
    kozane_client::lock_memory(&*handle).map_err(status)?;
    handle.queue(first)?;
    Ok(handle)
}

/// Passes a datagram received from `rp_endpoint`. `KZ_ERR_REJECTED`: the
/// datagram was refused and dropped, and nothing changed.
///
/// # Safety
///
/// `h` is a live handle; a non-null `buf` is valid for reads of `len`
/// bytes and does not point into the handle (`KZ_ERR_INVALID` if it does).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_client_on_datagram(h: *mut kz_client, now: u64, buf: *const u8, len: usize) -> c_int {
    if in_handle(h, buf, len) {
        return KZ_ERR_INVALID;
    }
    // SAFETY: the caller's contract.
    let Some(msg) = (unsafe { bytes(buf, len) }) else {
        return KZ_ERR_INVALID;
    };
    // SAFETY: the caller's contract.
    unsafe { with_handle(h, |c| c.process(|client| client.on_datagram(now, msg))) }
}

/// Runs the client's timers at `now` (ns on a clock that counts suspend,
/// `CLOCK_BOOTTIME` on Linux). Call it at `kz_client_next_deadline`.
///
/// # Safety
///
/// `h` is a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_client_on_timer(h: *mut kz_client, now: u64) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        with_handle(h, |c| {
            #[cfg(feature = "test-panic")]
            #[allow(clippy::panic)]
            if now == u64::MAX {
                panic!("kz_client_on_timer: test-panic seam");
            }
            c.process(|client| client.on_timer(now))
        })
    }
}

/// Writes the next deadline to `*out`, or returns `KZ_NONE` when there is
/// none.
///
/// # Safety
///
/// `h` is a live handle and `out` is valid for a write and outside the
/// handle (`KZ_ERR_INVALID` if not).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_client_next_deadline(h: *mut kz_client, out: *mut u64) -> c_int {
    if out.is_null() || in_handle(h, out.cast(), size_of::<u64>()) {
        return KZ_ERR_INVALID;
    }
    // SAFETY: the caller's contract; `out` is outside the handle.
    unsafe {
        with_handle(h, |c| match c.client.next_deadline() {
            Some(t) => {
                out.write(t);
                KZ_OK
            }
            None => KZ_NONE,
        })
    }
}

/// Takes the oldest queued action: its kind into `*kind`, its payload
/// (`KZ_MAX_DATAGRAM` bytes at most for a send, `KZ_PSK_LEN` for a PSK,
/// none for a scrub) into `buf`, and the payload's length into `*len`.
/// `KZ_NONE` with `*kind` 0 when the queue is empty. A queued PSK is wiped
/// as it is taken.
///
/// # Safety
///
/// `h` is a live handle, `kind` and `len` are valid for writes, and a
/// non-null `buf` is valid for writes of `cap` bytes (`buf` may be null
/// only with `cap` 0). `kind`, `len`, the `cap` bytes at `buf` and the
/// handle do not overlap (`KZ_ERR_INVALID` if any two do).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_client_take_action(
    h: *mut kz_client,
    buf: *mut u8,
    cap: usize,
    kind: *mut c_int,
    len: *mut usize,
) -> c_int {
    if kind.is_null() || len.is_null() || (buf.is_null() && cap != 0) {
        return KZ_ERR_INVALID;
    }
    let ranges = [
        (kind.cast_const().cast::<u8>(), size_of::<c_int>()),
        (len.cast_const().cast::<u8>(), size_of::<usize>()),
        (buf.cast_const(), cap),
        (h.cast_const().cast::<u8>(), size_of::<kz_client>()),
    ];
    for (i, &(a, alen)) in ranges.iter().enumerate() {
        if ranges.iter().skip(i.saturating_add(1)).any(|&(b, blen)| overlaps(a, alen, b, blen)) {
            return KZ_ERR_INVALID;
        }
    }
    // SAFETY: the caller's contract; `kind` and `len` are outside the
    // handle and each other, so their writes alias nothing.
    unsafe {
        with_handle(h, |c| {
            let (code, k, l) = take(c, buf, cap);
            kind.write(k);
            len.write(l);
            code
        })
    }
}

/// The oldest action into `buf`: (status, kind, payload length).
fn take(c: &mut kz_client, buf: *mut u8, cap: usize) -> (c_int, c_int, usize) {
    if c.queued == 0 {
        return (KZ_NONE, 0, 0);
    }
    let Some(slot) = c.slots.get_mut(c.head) else {
        return (KZ_ERR_INTERNAL, 0, 0);
    };
    let (kind, len) = (slot.kind, slot.len);
    if cap < len {
        return (KZ_ERR_BUFFER, kind, len);
    }
    let payload: &[u8] = match slot.kind {
        KZ_ACTION_SEND => slot.datagram.get(..slot.len).unwrap_or(&[]),
        KZ_ACTION_INSTALL_PSK => slot.psk.expose(),
        _ => &[],
    };
    if !payload.is_empty() {
        // SAFETY: `buf` is valid for `cap >= payload.len()` bytes (the
        // caller's contract), and the slot is inside the handle, which
        // `kz_client_take_action` checked `buf` is not.
        unsafe { core::ptr::copy_nonoverlapping(payload.as_ptr(), buf, payload.len()) };
    }
    slot.psk.wipe();
    (slot.kind, slot.len) = (0, 0);
    c.head = c.head.saturating_add(1);
    c.queued = c.queued.saturating_sub(1);
    (KZ_OK, kind, len)
}

/// Frees the handle, wiping the client's keys, its handshake secrets and
/// any queued PSK. A null `h` is ignored.
///
/// # Safety
///
/// `h` is null or a live handle, not used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_client_free(h: *mut kz_client) {
    if h.is_null() {
        return;
    }
    // SAFETY: the caller's contract: `h` came from `Box::into_raw` in
    // `kz_client_new` and is freed once. Dropping cannot unwind past here.
    let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { Box::from_raw(h) })));
}

#[cfg(test)]
mod tests;
