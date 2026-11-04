//! The client's keys, locked in memory.

use rosenpass_core::SPK_LEN;
use secret_blob::pq;

use crate::{Error, Secret};

/// `rp.sk` as the client reads it: the liboqs layout (M9 plan C10).
pub const RP_SK_LEN: usize = pq::LIBOQS_SK_LEN;

const _: () = assert!(pq::SK_LEN == mce460896::SK_LEN && pq::PK_LEN == SPK_LEN);

/// The client's Rosenpass key pair. The secret key is held once, in the
/// round-3 layout decapsulation reads, in locked memory kept out of core
/// dumps; it is wiped when `Keys` drops.
pub struct Keys {
    rp_pub: Box<[u8; SPK_LEN]>,
    rp_sk: Box<Secret<{ pq::SK_LEN }>>,
}

impl Keys {
    /// `rp_pub` is the raw `SPK_LEN` public key and `rp_sk` the liboqs
    /// layout secret key (`RP_SK_LEN` bytes). The secret is copied once,
    /// into memory locked before the copy; the caller wipes its buffer.
    pub fn new(rp_pub: &[u8], rp_sk: &[u8]) -> Result<Box<Self>, Error> {
        let oqs: &[u8; RP_SK_LEN] = rp_sk.try_into().map_err(|_| Error::InvalidKey)?;
        let rp_pub = boxed_public(rp_pub)?;
        let mut sk = Box::new(Secret::zero());
        lock_memory(&*sk)?;
        pq::cmr_sk_from_liboqs(sk.expose_mut(), oqs);
        Ok(Box::new(Self { rp_pub, rp_sk: sk }))
    }

    pub fn public(&self) -> &[u8; SPK_LEN] {
        &self.rp_pub
    }

    pub(crate) fn secret(&self) -> &Secret<{ pq::SK_LEN }> {
        &self.rp_sk
    }
}

/// A McEliece public key on the heap, never built on the stack.
pub(crate) fn boxed_public(bytes: &[u8]) -> Result<Box<[u8; SPK_LEN]>, Error> {
    if bytes.len() != SPK_LEN {
        return Err(Error::InvalidKey);
    }
    bytes.to_vec().into_boxed_slice().try_into().map_err(|_| Error::InvalidKey)
}

/// Locks the pages under `value` into memory (mlock) and keeps them out of
/// core dumps (MADV_DONTDUMP). The pages stay locked after `value` drops:
/// they may hold other locked data, and mlock does not nest.
#[allow(unsafe_code)]
pub fn lock_memory<T>(value: &T) -> Result<(), Error> {
    let len = size_of_val(value);
    if len == 0 {
        return Ok(());
    }
    // SAFETY: sysconf has no preconditions.
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).map_err(|_| Error::Memory)?;
    let addr = core::ptr::from_ref(value).addr();
    let start = addr.checked_div(page).and_then(|n| n.checked_mul(page)).ok_or(Error::Memory)?;
    let end = addr
        .checked_add(len)
        .and_then(|e| e.checked_next_multiple_of(page))
        .ok_or(Error::Memory)?;
    let span = end.checked_sub(start).ok_or(Error::Memory)?;
    let base = core::ptr::without_provenance_mut::<libc::c_void>(start);
    // SAFETY: mlock and madvise take any page-aligned range of the address
    // space; this one covers `value`, which is mapped. Neither touches the
    // bytes, and MADV_DONTDUMP changes only what a core dump includes.
    if unsafe { libc::mlock(base, span) } != 0 {
        return Err(Error::Memory);
    }
    #[cfg(target_os = "linux")]
    // SAFETY: as above.
    if unsafe { libc::madvise(base, span, libc::MADV_DONTDUMP) } != 0 {
        return Err(Error::Memory);
    }
    Ok(())
}

#[cfg(not(unix))]
compile_error!("kozane-client locks its key memory with mlock; port lock_memory first");
