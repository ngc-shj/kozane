//! `tls`'s `Halted` reasons (the record's `a`), stable per M5 plan C6, and
//! when an answer of `tlskey` halts `tls`.

/// CNTFRQ is 0: no clock, so no TCP or connection timer would fire.
pub const NO_CLOCK: u32 = 1;
/// A draw failed at init: no seed for smoltcp's initial sequence numbers.
pub const RNG: u32 = 2;
/// The interface or a listener could not be set up, or `tlskey` refused
/// the boot seed for a reason other than Unavailable.
pub const INIT_FAILED: u32 = 3;
/// `tlskey` answered Unavailable (after `KeyUnavailable`): at init, to the
/// boot seed, before any listener exists (M6 plan C12), or to a `TlsSign`.
pub const KEY_UNAVAILABLE: u32 = 4;
/// `rng` gave no seed in `RNG_INIT_TRIES` tries (M7 plan C7).
pub const RNG_UNAVAILABLE: u32 = 5;

/// What a pass ends with when one of its `TlsSign` calls was answered
/// Unavailable with `code` (from the reply label): the code `tls` audits as
/// `KeyUnavailable`, then the reason it halts with. `tlskey` holds no key
/// any more, so no later handshake could complete either (M6 plan C12,
/// R2-T N8). None when every sign was answered, or failed otherwise (which
/// fails only its own handshake).
pub const fn after_sign(unavailable: Option<u32>) -> Option<(u32, u32)> {
    match unavailable {
        Some(code) => Some((code, KEY_UNAVAILABLE)),
        None => None,
    }
}
