//! TPM driver PD (M5 plan C9, laws L1/L5): passive, untainted, the only PD
//! that maps the TPM's TIS page (locality 0), and callee of the key PDs
//! (`key`, `pqkey`, `tlskey`) alone. Each call carries one TPM command
//! (`layout::tpm`); the `tpm2_wire` gate decides whether it reaches the
//! device: the allowlist, per-client handle ownership (L2 between the key
//! domains), one flow per client and one flow at a time (Busy), and the
//! cap of PCR 8 once every client sent Done or Failed, and the cap status
//! each Done client asks for before it releases its key (post-M6 plan P3).
//! The TIS FIFO is polled with bounded CNTPCT timeouts, so a device that
//! stops answering gets the caller an error reply, never a hang. No audit
//! channel and no console: what happened shows in the clients' replies.

#![no_std]
#![no_main]

use core::ptr::NonNull;

use layout::tpm::{self as ipc, MSG_BYTES, MSG_WORDS};
use sel4_microkit::{
    Channel, Handler, Infallible, MessageInfo, protection_domain, var, with_msg_regs, with_msg_regs_mut,
};
use tpm2_wire::gate::{CLIENTS, CapStatus, CapTransport, CapVerdict, Gate, Refusal};

const _: () = assert!(MSG_BYTES == tpm2_wire::IPC_MSG_BYTES);

const KEY: Channel = Channel::new(ipc::CH_KEY);
const PQKEY: Channel = Channel::new(ipc::CH_PQKEY);
const TLSKEY: Channel = Channel::new(ipc::CH_TLSKEY);

/// The gate's client index of each caller.
fn client(channel: Channel) -> Option<usize> {
    if channel == KEY {
        Some(0)
    } else if channel == PQKEY {
        Some(1)
    } else if channel == TLSKEY {
        Some(2)
    } else {
        None
    }
}
const _: () = assert!(CLIENTS == 3);

// TIS registers of locality 0 (TCG PC Client Platform TPM Profile, TIS).
const ACCESS: usize = 0x00;
const STS: usize = 0x18;
const DATA_FIFO: usize = 0x24;

const ACCESS_VALID: u8 = 0x80;
const ACCESS_ACTIVE_LOCALITY: u8 = 0x20;
const ACCESS_REQUEST_USE: u8 = 0x02;

const STS_VALID: u32 = 0x80;
const STS_COMMAND_READY: u32 = 0x40;
const STS_GO: u32 = 0x20;
const STS_DATA_AVAIL: u32 = 0x10;
const STS_EXPECT: u32 = 0x08;

/// Locality, command-ready, burst-count and status waits (TIS timeouts A
/// to D are 750 ms to 2 s; TCG slows both sides).
const SHORT_TIMEOUT_NS: u64 = 5_000_000_000;
/// One command's execution: an ECC CreatePrimary on swtpm under TCG takes
/// well under a second; a real TPM's long commands take seconds.
const COMMAND_TIMEOUT_NS: u64 = 60_000_000_000;

/// Why the device did not answer a command; the code is RSP_DEVICE's arg.
#[derive(Clone, Copy)]
enum DeviceError {
    Locality = 1,
    CommandReady = 2,
    Write = 3,
    Expect = 4,
    Execute = 5,
    Read = 6,
    ResponseSize = 7,
    ExcessData = 8,
}

struct Tis {
    base: NonNull<u8>,
}

impl Tis {
    fn read8(&self, offset: usize) -> u8 {
        // SAFETY: `base` is this PD's uncached mapping of the TIS page and
        // `offset` is one of the register constants above, all in the page.
        unsafe { self.base.byte_add(offset).read_volatile() }
    }

    fn write8(&self, offset: usize, value: u8) {
        // SAFETY: as in `read8`.
        unsafe { self.base.byte_add(offset).write_volatile(value) }
    }

    fn sts(&self) -> u32 {
        // SAFETY: as in `read8`; STS is 4-byte aligned.
        unsafe { self.base.byte_add(STS).cast::<u32>().read_volatile() }
    }

    fn burst(sts: u32) -> usize {
        ((sts >> 8) & 0xffff) as usize
    }

    /// Polls `read` until `ok` holds, for at most `timeout_ns` and not past
    /// `limit` (the command's overall deadline, if it has one): each wait is
    /// min(its default, what is left of the deadline).
    fn wait<T: Copy>(read: impl Fn() -> T, ok: impl Fn(T) -> bool, timeout_ns: u64, limit: u64) -> Option<T> {
        let deadline = cpu::now_ns().saturating_add(timeout_ns).min(limit);
        loop {
            let v = read();
            if ok(v) {
                return Some(v);
            }
            if cpu::now_ns() >= deadline {
                return None;
            }
            core::hint::spin_loop();
        }
    }

    fn wait_sts(&self, ok: impl Fn(u32) -> bool, timeout_ns: u64, limit: u64) -> Option<u32> {
        Self::wait(|| self.sts(), ok, timeout_ns, limit)
    }

    /// One command, locality 0: request the locality, wait commandReady,
    /// write the command in bursts, go, wait dataAvail, read the response
    /// (at most `MSG_BYTES`), then idle the TPM and release the locality,
    /// whatever happened. No wait runs past `limit` (`u64::MAX`: none).
    fn transact(&self, cmd: &[u8], rsp: &mut [u8; MSG_BYTES], limit: u64) -> Result<usize, DeviceError> {
        let r = self.exchange(cmd, rsp, limit);
        self.write8(STS, STS_COMMAND_READY as u8);
        self.write8(ACCESS, ACCESS_ACTIVE_LOCALITY);
        if r.is_err() {
            rsp.fill(0);
        }
        r
    }

    fn exchange(&self, cmd: &[u8], rsp: &mut [u8; MSG_BYTES], limit: u64) -> Result<usize, DeviceError> {
        self.write8(ACCESS, ACCESS_REQUEST_USE);
        let active = ACCESS_VALID | ACCESS_ACTIVE_LOCALITY;
        Self::wait(|| self.read8(ACCESS), |a| a & active == active, SHORT_TIMEOUT_NS, limit)
            .ok_or(DeviceError::Locality)?;
        self.write8(STS, STS_COMMAND_READY as u8);
        self.wait_sts(|s| s & STS_COMMAND_READY != 0, SHORT_TIMEOUT_NS, limit).ok_or(DeviceError::CommandReady)?;

        let mut sent = 0;
        while sent < cmd.len() {
            let sts = self.wait_sts(|s| Self::burst(s) > 0, SHORT_TIMEOUT_NS, limit).ok_or(DeviceError::Write)?;
            let end = sent.saturating_add(Self::burst(sts)).min(cmd.len());
            for b in cmd.get(sent..end).unwrap_or(&[]) {
                self.write8(DATA_FIFO, *b);
            }
            sent = end;
        }
        // The TPM must want nothing more: the command's own size field and
        // what was written agree.
        let sts = self.wait_sts(|s| s & STS_VALID != 0, SHORT_TIMEOUT_NS, limit).ok_or(DeviceError::Expect)?;
        if sts & STS_EXPECT != 0 {
            return Err(DeviceError::Expect);
        }
        self.write8(STS, STS_GO as u8);

        let avail = STS_VALID | STS_DATA_AVAIL;
        self.wait_sts(|s| s & avail == avail, COMMAND_TIMEOUT_NS, limit).ok_or(DeviceError::Execute)?;
        let mut len = tpm2_wire::HEADER_LEN;
        let mut got = 0;
        while got < len {
            let sts = self.wait_sts(|s| s & avail == avail && Self::burst(s) > 0, SHORT_TIMEOUT_NS, limit)
                .ok_or(DeviceError::Read)?;
            let end = got.saturating_add(Self::burst(sts)).min(len);
            for b in rsp.get_mut(got..end).ok_or(DeviceError::Read)? {
                *b = self.read8(DATA_FIFO);
            }
            got = end;
            if got == tpm2_wire::HEADER_LEN && len == tpm2_wire::HEADER_LEN {
                // The response's size field, bounded before any more is read.
                let size = rsp.get(2..6).and_then(|s| <[u8; 4]>::try_from(s).ok()).map(u32::from_be_bytes);
                len = size
                    .and_then(|s| usize::try_from(s).ok())
                    .filter(|s| (tpm2_wire::HEADER_LEN..=MSG_BYTES).contains(s))
                    .ok_or(DeviceError::ResponseSize)?;
            }
        }
        let sts = self.wait_sts(|s| s & STS_VALID != 0, SHORT_TIMEOUT_NS, limit).ok_or(DeviceError::Read)?;
        if sts & STS_DATA_AVAIL != 0 {
            return Err(DeviceError::ExcessData);
        }
        Ok(len)
    }
}

/// The cap's PCR_Extend on the TIS, each attempt within its budget (the
/// gate's `CAP_ATTEMPT_DEADLINE_NS`): every wait inside it is bounded by
/// what is left of that deadline.
struct CapDevice<'t> {
    tis: &'t Tis,
    rsp: &'t mut [u8; MSG_BYTES],
}

impl CapTransport for CapDevice<'_> {
    fn attempt(&mut self, cmd: &[u8], budget_ns: u64) -> Option<&[u8]> {
        let limit = cpu::now_ns().saturating_add(budget_ns);
        let n = self.tis.transact(cmd, self.rsp, limit).ok()?;
        self.rsp.get(..n)
    }
}

/// RSP_REFUSED's arg. Busy is never a refusal: it is answered RSP_BUSY.
const fn refusal_code(r: Refusal) -> usize {
    match r {
        Refusal::UnknownClient => 1,
        Refusal::Finished => 2,
        Refusal::Capped => 3,
        Refusal::Malformed => 4,
        Refusal::NotAllowed => 5,
        Refusal::Repeated => 6,
        Refusal::NotOwned => 7,
        Refusal::Hierarchy => 8,
        Refusal::Busy => 9,
        Refusal::NotDone => 10,
    }
}
const _: () = assert!(ipc::REFUSED_CAP_FAILED > refusal_code(Refusal::NotDone));

/// The reply to the Done (or Failed) that ran the cap, and to the cap
/// status once it ran: a cap the device did not confirm is answered as a
/// refusal of its own, so the key PD does not release its key.
fn cap_label(verdict: CapVerdict) -> u64 {
    match verdict {
        CapVerdict::Confirmed => ipc::label(ipc::RSP_OK, 0),
        CapVerdict::Failed => ipc::label(ipc::RSP_REFUSED, ipc::REFUSED_CAP_FAILED),
    }
}

struct Tpm {
    tis: Tis,
    gate: Gate,
    cmd: [u8; MSG_BYTES],
    rsp: [u8; MSG_BYTES],
}

impl Tpm {
    /// The reply to one request: its label and the response bytes in
    /// `self.rsp` (the label's arg).
    fn handle(&mut self, client: usize, label: u64, words: &[u64]) -> u64 {
        let len = ipc::arg(label);
        match ipc::kind(label) {
            ipc::REQ_COMMAND if len <= MSG_BYTES && words.len() == ipc::words(len) => {
                if ipc::unpack(words, len, &mut self.cmd).is_none() {
                    return ipc::label(ipc::RSP_BAD_REQUEST, 0);
                }
                self.command(client, len)
            }
            ipc::REQ_DONE | ipc::REQ_FAILED if len == 0 && words.is_empty() => {
                match self.gate.finish(client, ipc::kind(label) == ipc::REQ_DONE) {
                    Ok(()) => match self.cap() {
                        Some(verdict) => cap_label(verdict),
                        None => ipc::label(ipc::RSP_OK, 0),
                    },
                    Err(r) => ipc::label(ipc::RSP_REFUSED, refusal_code(r)),
                }
            }
            // The cap barrier, next to Done: the gate's command allowlist
            // never sees it.
            ipc::REQ_CAP_STATUS if len == 0 && words.is_empty() => match self.gate.cap_status(client) {
                Ok(CapStatus::Pending) => ipc::label(ipc::RSP_BUSY, 0),
                Ok(CapStatus::Confirmed) => cap_label(CapVerdict::Confirmed),
                Ok(CapStatus::Failed) => cap_label(CapVerdict::Failed),
                Err(r) => ipc::label(ipc::RSP_REFUSED, refusal_code(r)),
            },
            _ => ipc::label(ipc::RSP_BAD_REQUEST, 0),
        }
    }

    fn command(&mut self, client: usize, len: usize) -> u64 {
        let cmd = self.cmd.get(..len).unwrap_or(&[]);
        let fwd = match self.gate.command(client, cmd) {
            Ok(fwd) => fwd,
            // One flow at a time (the gate's rule, M6 plan C12): the client
            // has not started and asks again (tpm2::boot), never refused.
            Err(Refusal::Busy) => return ipc::label(ipc::RSP_BUSY, 0),
            Err(r) => return ipc::label(ipc::RSP_REFUSED, refusal_code(r)),
        };
        match self.tis.transact(cmd, &mut self.rsp, u64::MAX) {
            Ok(n) => {
                self.gate.response(fwd, self.rsp.get(..n).unwrap_or(&[]));
                ipc::label(ipc::RSP_OK, n)
            }
            Err(e) => ipc::label(ipc::RSP_DEVICE, e as usize),
        }
    }

    /// Once every client has finished: the one PCR_Extend the gate issues,
    /// its verdict the gate's `run_cap` (None while not due). The gate
    /// refuses every Unseal from here whatever the device answers; the
    /// device's PCR 8 is what closes RM5-5's window, so the extend is
    /// confirmed by the TPM's own response. A failed cap is answered to
    /// this Done and to every Done client's cap status, and every key PD
    /// then halts without releasing its key (post-M6 plan P3). PCR 8 stays
    /// at its sealed value until reboot, which is RM5-5's accepted state
    /// before the cap; a bus attacker is not stopped by this.
    fn cap(&mut self) -> Option<CapVerdict> {
        let verdict = self.gate.run_cap(&mut CapDevice { tis: &self.tis, rsp: &mut self.rsp });
        self.rsp.fill(0);
        verdict
    }
}

#[protection_domain]
fn init() -> Tpm {
    let vaddr = *var!(tpm_mmio_vaddr: usize = 0);
    let base = NonNull::new(vaddr as *mut u8).unwrap_or_else(|| panic!("tpm: no mmio mapping"));
    Tpm { tis: Tis { base }, gate: Gate::new(), cmd: [0; MSG_BYTES], rsp: [0; MSG_BYTES] }
}

impl Handler for Tpm {
    type Error = Infallible;

    fn protected(&mut self, channel: Channel, msg_info: MessageInfo) -> Result<MessageInfo, Self::Error> {
        let mut words = [0u64; MSG_WORDS];
        let count = msg_info.count();
        let label = match client(channel) {
            Some(c) if count <= MSG_WORDS => {
                with_msg_regs(|mrs| {
                    for (dst, src) in words.iter_mut().zip(mrs.iter().take(count)) {
                        *dst = *src;
                    }
                });
                self.handle(c, msg_info.label(), words.get(..count).unwrap_or(&[]))
            }
            _ => ipc::label(ipc::RSP_BAD_REQUEST, 0),
        };
        words.fill(0);
        let n = if ipc::kind(label) == ipc::RSP_OK {
            ipc::pack(self.rsp.get(..ipc::arg(label)).unwrap_or(&[]), &mut words).unwrap_or(0)
        } else {
            0
        };
        // Every register past the reply is overwritten, so nothing of an
        // earlier, longer reply (another client's) is handed back.
        with_msg_regs_mut(|mrs| {
            for (dst, src) in mrs.iter_mut().zip(words.iter()) {
                *dst = *src;
            }
        });
        self.rsp.fill(0);
        self.cmd.fill(0);
        Ok(MessageInfo::new(label, n))
    }
}
