//! A barrier PD's side of `policy` (M8 plan C6): `Await` over its PPC
//! channel, then `open` on the slot `policy` verified. This crate and the
//! `policy` PD are the only code that names the slot MR symbols
//! (check-pins P27); every barrier PD maps `policy_a` at
//! `layout::policy`'s slot windows read-only, as `policy` does.
//!
//! A barrier PD calls [`await_verified`] once in `init` and, on a
//! [`Verified`], builds its view with [`open`]; any `Err` is
//! `layout::policy::HALT_UNAVAILABLE`, a boot stop. Nothing it receives
//! before that is processed: frames wait in the driver rings.

#![no_std]
#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::arithmetic_side_effects)]

use layout::policy as ch;
use layout::tpm as words;
use policy_wire::{Bundle, NodeConfig, Reject, Slot, VERIFIED_REPLY_LEN, Verified};

/// Words `policy`'s `Verified` reply carries.
pub const VERIFIED_WORDS: usize = words::words(VERIFIED_REPLY_LEN);

/// Decodes `policy`'s `Await` reply: its label, word count and message
/// words. `VERIFIED` with exactly `VERIFIED_WORDS` words that
/// `Verified::from_reply` accepts is the token; `UNAVAILABLE` with one word
/// carries `policy`'s reason; anything else (a `BAD_REQUEST`, a short or
/// long reply, an unknown reason) is `Malformed`, which the caller treats
/// as unavailable all the same.
pub fn decode(label: u64, count: usize, mrs: &[u64]) -> Result<Verified, Reject> {
    match label {
        ch::VERIFIED if count == VERIFIED_WORDS => {
            let mut reply = [0u8; VERIFIED_REPLY_LEN];
            mrs.get(..count)
                .and_then(|w| words::unpack(w, VERIFIED_REPLY_LEN, &mut reply))
                .and_then(|()| Verified::from_reply(&reply))
                .ok_or(Reject::Malformed)
        }
        ch::UNAVAILABLE if count == 1 => {
            let code = mrs.first().and_then(|c| usize::try_from(*c).ok());
            Err(code.and_then(|c| Reject::ALL.get(c).copied()).unwrap_or(Reject::Malformed))
        }
        _ => Err(Reject::Malformed),
    }
}

/// The slot `token` names, of the two.
pub fn pick<'s>(token: &Verified, a: &'s [u8], b: &'s [u8]) -> &'s [u8] {
    match token.slot() {
        Slot::A => a,
        Slot::B => b,
    }
}

/// `policy_wire::open` on the slot `token` names, of `a` and `b`.
pub fn open_in<'s>(
    token: &Verified,
    a: &'s [u8],
    b: &'s [u8],
    node: &NodeConfig<'_>,
) -> Result<Bundle<'s>, Reject> {
    policy_wire::open(token, pick(token, a, b), node)
}

#[cfg(target_os = "none")]
mod pd {
    use core::ptr::NonNull;

    use limits::BUNDLE_MAX;
    use policy_wire::{Bundle, NodeConfig, Reject, Verified};
    use sel4_microkit::{Channel, MessageInfo, memory_region_symbol, with_msg_regs, with_msg_regs_mut};

    use super::{VERIFIED_WORDS, ch, decode, open_in};

    /// `Await` on `channel` (no words in): `policy`'s token, or why there is
    /// none. Blocks until `policy`'s init has decided. The registers it
    /// read are zeroed afterwards.
    pub fn await_verified(channel: Channel) -> Result<Verified, Reject> {
        let info = channel.pp_call(MessageInfo::new(ch::AWAIT, 0));
        let r = with_msg_regs(|mrs| decode(info.label(), info.count(), mrs));
        with_msg_regs_mut(|mrs| mrs.iter_mut().take(VERIFIED_WORDS).for_each(|w| *w = 0));
        r
    }

    fn slot_a() -> &'static [u8] {
        let p: NonNull<[u8]> = memory_region_symbol!(policy_a: *mut [u8], n = BUNDLE_MAX);
        // SAFETY: the slot is mapped read-only into this PD for the life of
        // the system, and no PD maps it writable (laws: bundle_slot, C11).
        unsafe { p.as_ref() }
    }

    fn slot_b() -> &'static [u8] {
        let p: NonNull<[u8]> = memory_region_symbol!(policy_b: *mut [u8], n = BUNDLE_MAX);
        // SAFETY: as for `slot_a`.
        unsafe { p.as_ref() }
    }

    /// The bundle in the slot `token` names, validated against `node`
    /// (`policy_wire::open`: no signature check, no re-hash; C1).
    pub fn open(token: &Verified, node: &NodeConfig<'_>) -> Result<Bundle<'static>, Reject> {
        open_in(token, slot_a(), slot_b(), node)
    }
}

#[cfg(target_os = "none")]
pub use pd::{await_verified, open};

#[cfg(test)]
mod tests;
