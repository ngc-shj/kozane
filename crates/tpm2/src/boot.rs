//! One unseal as the key PDs run it in `init` (M5 plan C9, C11):
//! the [`client`](crate::client) flow over PPC to `tpm`, then the explicit
//! Done or Failed `tpm` caps PCR 8 after. The PD supplies the transport,
//! the clock and the random source ([`Transport`]); everything else is
//! here, so it is tested on the host.
//!
//! - The envelope is read where it lies (the read-only secrets region);
//!   the plaintext is written only to `out`, the PD's private buffer, and
//!   on any failure `out` is all zero (I11.1).
//! - The KEK and the session secrets live in the client and are wiped on
//!   every path out of it (I10.3).
//! - `tpm` answers Busy while another client's flow is under way (swtpm
//!   and small TPMs hold too few objects for two at once). A Busy client
//!   waits `BUSY_PAUSE_NS` and asks again, for at most `BUSY_TIMEOUT_NS`.
//! - Done (or Failed) is sent whatever happened, so `tpm` can cap PCR 8
//!   once every client (`key`, `pqkey`, `tlskey`) has finished. A Done
//!   `tpm` does not acknowledge leaves the PD without its secrets.
//! - The cap barrier (post-M6 plan P3): after its Done, the client asks
//!   `tpm` for the cap status until the cap is confirmed, and keeps its
//!   secrets only then. A failed cap is `CapFailed`, so every key domain
//!   fails closed, not only the last to finish; so does a client that
//!   never finishes, once the barrier times out.

use layout::tpm as ipc;

use crate::Secret;
use crate::client::{CLIENT_ENTROPY_LEN, Cause, Client, Failure, Step};
use crate::envelope::Kind;

/// Between two calls of a client `tpm` answered Busy.
pub const BUSY_PAUSE_NS: u64 = 10_000_000;
/// The longest one flow holds `tpm`: its TPM commands plus its P-256 work
/// under TCG at the smallest key PD init budget (`pqkey`'s 0.1; `key`'s and
/// `tlskey`'s are 0.2), with a wide margin (M5's bound for one flow).
const FLOW_MAX_NS: u64 = 120_000_000_000;
/// How long a client waits for the others' flows before giving up: every
/// other client may be served first (M6 plan C12: two flows of the three).
pub const BUSY_TIMEOUT_NS: u64 = FLOW_MAX_NS * (tpm2_wire::gate::CLIENTS as u64 - 1);
const _: () = assert!(BUSY_TIMEOUT_NS == 240_000_000_000);
/// How long a Done client waits for the cap: the other clients' flows (as
/// `BUSY_TIMEOUT_NS`), then every attempt of the cap within its deadline
/// (round 3 R3-3), so a slow TCG boot does not halt every domain.
pub const CAP_BARRIER_TIMEOUT_NS: u64 =
    BUSY_TIMEOUT_NS + tpm2_wire::gate::CAP_ATTEMPTS as u64 * tpm2_wire::gate::CAP_ATTEMPT_DEADLINE_NS;
const _: () = assert!(
    CAP_BARRIER_TIMEOUT_NS
        >= BUSY_TIMEOUT_NS + tpm2_wire::gate::CAP_ATTEMPTS as u64 * tpm2_wire::gate::CAP_ATTEMPT_DEADLINE_NS
);
/// Fresh draws of the client entropy when the ECDH scalar is unusable
/// (zero or not below the group order: about 2^-32 per draw).
const ENTROPY_DRAWS: usize = 4;

const _: () = assert!(ipc::MSG_BYTES == tpm2_wire::IPC_MSG_BYTES);

/// What the PD provides.
pub trait Transport {
    /// One PPC to `tpm` with `label` and the bytes `req` (at most
    /// `ipc::MSG_BYTES`). Returns the reply label and how many bytes the
    /// reply's message words carried into `rsp`.
    fn call(&mut self, label: u64, req: &[u8], rsp: &mut [u8; ipc::MSG_BYTES]) -> (u64, usize);
    /// The monotonic clock, in ns.
    fn now_ns(&mut self) -> u64;
    /// Fills `out` from the hardware random source; false if it failed.
    fn random(&mut self, out: &mut [u8]) -> bool;
}

/// Why the unseal failed; the PDs report each as a `BootError` code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsealError {
    /// The random source failed (or kept giving unusable scalars).
    Rng,
    /// The secrets region is not an envelope of this PD's kind (a
    /// plaintext `SOSSECR1` blob included).
    EnvelopeInvalid,
    /// `tpm` refused, timed out or stayed busy, the device failed, or a
    /// TPM command other than Unseal was refused.
    TpmUnavailable,
    /// The TPM's SRK is not the one the envelope pins (I10.2): another TPM.
    SrkMismatch,
    /// The TPM refused the Unseal: PCR 8 is not the value sealed to
    /// (another image or descriptor).
    UnsealRefused,
    /// A response failed the client's checks (its format, Unseal's HMAC,
    /// attributes or outData, Load's Name): a tampered bus or `tpm` (A7).
    ResponseInvalid,
    /// The unsealed KEK did not open the envelope.
    EnvelopeOpen,
    /// The unseal succeeded but `tpm` could not confirm the cap of PCR 8
    /// (post-M6 plan P3): the secrets are not released.
    CapFailed,
}

impl UnsealError {
    fn of(f: Failure) -> Self {
        match f.cause {
            Cause::Envelope(_) => UnsealError::EnvelopeInvalid,
            Cause::Entropy => UnsealError::Rng,
            Cause::Buffer | Cause::Order => UnsealError::TpmUnavailable,
            Cause::Response(tpm2_wire::RspError::Tpm(_)) if f.step == Step::Unseal => UnsealError::UnsealRefused,
            Cause::Response(tpm2_wire::RspError::Tpm(_)) => UnsealError::TpmUnavailable,
            Cause::Response(_) => UnsealError::ResponseInvalid,
            Cause::SrkName => UnsealError::SrkMismatch,
            Cause::LoadName | Cause::ResponseHmac | Cause::ResponseAttributes | Cause::OutData => {
                UnsealError::ResponseInvalid
            }
            Cause::Open(_) => UnsealError::EnvelopeOpen,
        }
    }
}

/// Starts the client: fresh entropy per try, the scalar never kept.
fn start<'e>(tpm: &mut impl Transport, envelope: &'e [u8], kind: Kind) -> Result<Client<'e>, UnsealError> {
    let mut entropy = Secret::<CLIENT_ENTROPY_LEN>::zero();
    for _ in 0..ENTROPY_DRAWS {
        if !tpm.random(entropy.as_mut_bytes()) {
            return Err(UnsealError::Rng);
        }
        match Client::new(envelope, kind, &entropy) {
            Ok(client) => return Ok(client),
            Err(f) if f.cause == Cause::Entropy => continue,
            Err(f) => return Err(UnsealError::of(f)),
        }
    }
    Err(UnsealError::Rng)
}

/// One command through `tpm`, asking again while it is Busy. The response
/// length is the label's, bounded by what the reply carried.
fn exchange(tpm: &mut impl Transport, req: &[u8], rsp: &mut [u8; ipc::MSG_BYTES]) -> Option<usize> {
    let mut busy_since = None;
    loop {
        let (label, carried) = tpm.call(ipc::label(ipc::REQ_COMMAND, req.len()), req, rsp);
        match ipc::kind(label) {
            ipc::RSP_OK if ipc::arg(label) <= carried => return Some(ipc::arg(label)),
            ipc::RSP_BUSY => {
                let now = tpm.now_ns();
                let since = *busy_since.get_or_insert(now);
                if now.saturating_sub(since) >= BUSY_TIMEOUT_NS {
                    return None;
                }
                let until = now.saturating_add(BUSY_PAUSE_NS);
                while tpm.now_ns() < until {
                    core::hint::spin_loop();
                }
            }
            _ => return None,
        }
    }
}

/// The cap barrier: asks `tpm` for the cap status, pausing while it is
/// pending, until the cap is confirmed (Ok) or failed (`CapFailed`). Any
/// other answer, or no verdict within `CAP_BARRIER_TIMEOUT_NS`, is
/// `TpmUnavailable`.
pub fn cap_barrier(tpm: &mut impl Transport, rsp: &mut [u8; ipc::MSG_BYTES]) -> Result<(), UnsealError> {
    let since = tpm.now_ns();
    loop {
        let (label, _) = tpm.call(ipc::label(ipc::REQ_CAP_STATUS, 0), &[], rsp);
        if label == ipc::label(ipc::RSP_OK, 0) {
            return Ok(());
        }
        if label == ipc::label(ipc::RSP_REFUSED, ipc::REFUSED_CAP_FAILED) {
            return Err(UnsealError::CapFailed);
        }
        if ipc::kind(label) != ipc::RSP_BUSY {
            return Err(UnsealError::TpmUnavailable);
        }
        let now = tpm.now_ns();
        if now.saturating_sub(since) >= CAP_BARRIER_TIMEOUT_NS {
            return Err(UnsealError::TpmUnavailable);
        }
        let until = now.saturating_add(BUSY_PAUSE_NS);
        while tpm.now_ns() < until {
            core::hint::spin_loop();
        }
    }
}

/// Runs the whole unseal of `envelope` (`kind`'s, read in place) into
/// `out` (the region's size), then tells `tpm` Done or Failed and, after a
/// Done, waits at the cap barrier.
pub fn unseal(tpm: &mut impl Transport, envelope: &[u8], kind: Kind, out: &mut [u8]) -> Result<(), UnsealError> {
    out.fill(0);
    let mut rsp = [0u8; ipc::MSG_BYTES];
    let result = match start(tpm, envelope, kind) {
        Ok(client) => run(tpm, client, out, &mut rsp),
        Err(e) => Err(e),
    };
    // The session's secrets passed through frames below this one that do not
    // wipe their own state (crypto.rs): libcrux's P-256 ECDH in start (the
    // ephemeral scalar and shared point) and its HMAC and KDF frames in run.
    // Clear that stack once the session is over, as open_sealed does for the
    // KEK.
    scrub_session_stack();
    let finish = if result.is_ok() { ipc::REQ_DONE } else { ipc::REQ_FAILED };
    let (label, _) = tpm.call(ipc::label(finish, 0), &[], &mut rsp);
    let result = match result {
        Ok(()) if label == ipc::label(ipc::RSP_OK, 0) => cap_barrier(tpm, &mut rsp),
        // This Done ran the cap, and it failed.
        Ok(()) if label == ipc::label(ipc::RSP_REFUSED, ipc::REFUSED_CAP_FAILED) => Err(UnsealError::CapFailed),
        Ok(()) => Err(UnsealError::TpmUnavailable),
        Err(e) => Err(e),
    };
    rsp.fill(0);
    if result.is_err() {
        out.fill(0);
    }
    result
}

fn run(
    tpm: &mut impl Transport,
    mut client: Client<'_>,
    out: &mut [u8],
    rsp: &mut [u8; ipc::MSG_BYTES],
) -> Result<(), UnsealError> {
    let mut cmd = [0u8; ipc::MSG_BYTES];
    // The first failure that was the transport's, not the TPM's or the
    // client's own: it decides the code.
    let mut transport_failed = false;
    while let Some(n) = client.command(&mut cmd) {
        let reply = match cmd.get(..n) {
            Some(req) => exchange(tpm, req, rsp),
            None => None,
        };
        match reply.and_then(|m| rsp.get(..m)) {
            Some(bytes) => client.response(bytes),
            None => {
                transport_failed |= client.failure().is_none();
                // An empty response fails the client, which still flushes.
                client.response(&[]);
            }
        }
    }
    cmd.fill(0);
    match client.finish(out) {
        Ok(()) => Ok(()),
        Err(_) if transport_failed => Err(UnsealError::TpmUnavailable),
        Err(f) => Err(UnsealError::of(f)),
    }
}

/// Zeroes, with volatile writes, `envelope::OPEN_SCRUB_DEPTH` bytes of stack
/// below the caller's frame. Its own copy of open_sealed's scrub: calling
/// that one from here would enter open_sealed's closure (M4 C10) at a
/// function other than its root.
#[inline(never)]
fn scrub_session_stack() {
    let mut area = [0u64; crate::envelope::OPEN_SCRUB_DEPTH / 8];
    zeroize::Zeroize::zeroize(&mut area);
}
