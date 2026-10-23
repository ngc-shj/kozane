//! One unseal as `key` and `pqkey` run it in `init` (M5 plan C9, C11):
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
//! - `tpm` answers Busy while the other client's flow is under way (swtpm
//!   and small TPMs hold too few objects for two at once). A Busy client
//!   waits `BUSY_PAUSE_NS` and asks again, for at most `BUSY_TIMEOUT_NS`.
//! - Done (or Failed) is sent whatever happened, so `tpm` can cap PCR 8
//!   once both clients have finished. A Done `tpm` does not acknowledge
//!   leaves the PD without its secrets.

use layout::tpm as ipc;

use crate::Secret;
use crate::client::{CLIENT_ENTROPY_LEN, Cause, Client, Failure, Step};
use crate::envelope::Kind;

/// Between two calls of a client `tpm` answered Busy.
pub const BUSY_PAUSE_NS: u64 = 10_000_000;
/// How long a client waits for the other one's flow before giving up:
/// the other flow's TPM commands plus its P-256 work at its PD's budget
/// under TCG, with a wide margin.
pub const BUSY_TIMEOUT_NS: u64 = 120_000_000_000;
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
    Rndr,
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
}

impl UnsealError {
    fn of(f: Failure) -> Self {
        match f.cause {
            Cause::Envelope(_) => UnsealError::EnvelopeInvalid,
            Cause::Entropy => UnsealError::Rndr,
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
            return Err(UnsealError::Rndr);
        }
        match Client::new(envelope, kind, &entropy) {
            Ok(client) => return Ok(client),
            Err(f) if f.cause == Cause::Entropy => continue,
            Err(f) => return Err(UnsealError::of(f)),
        }
    }
    Err(UnsealError::Rndr)
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

/// Runs the whole unseal of `envelope` (`kind`'s, read in place) into
/// `out` (the region's size), then tells `tpm` Done or Failed.
pub fn unseal(tpm: &mut impl Transport, envelope: &[u8], kind: Kind, out: &mut [u8]) -> Result<(), UnsealError> {
    out.fill(0);
    let mut rsp = [0u8; ipc::MSG_BYTES];
    let result = match start(tpm, envelope, kind) {
        Ok(client) => run(tpm, client, out, &mut rsp),
        Err(e) => Err(e),
    };
    // The session key passed through libcrux's HMAC and KDF frames below
    // this one, which do not wipe their own state (crypto.rs); clear that
    // stack once the session is over, as open_sealed does for the KEK.
    crate::envelope::scrub_stack();
    let finish = if result.is_ok() { ipc::REQ_DONE } else { ipc::REQ_FAILED };
    let (label, _) = tpm.call(ipc::label(finish, 0), &[], &mut rsp);
    rsp.fill(0);
    match result {
        Ok(()) if label == ipc::label(ipc::RSP_OK, 0) => Ok(()),
        Ok(()) => {
            out.fill(0);
            Err(UnsealError::TpmUnavailable)
        }
        Err(e) => Err(e),
    }
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
