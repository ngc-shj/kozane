//! Sizes and channel numbers shared by PDs and `system/kozane.system`.
//! The .system file must agree with these (checked by this crate's tests).

#![no_std]

/// Slots per network ring; must be >= `NET_BUFFERS` (asserted in `ring::link`).
pub const NET_RING_SLOTS: usize = 64;
pub const NET_BUFFERS: usize = 64;
pub const NET_BUF_SIZE: usize = 2048;
pub const NET_REGION_SIZE: usize = NET_BUFFERS * NET_BUF_SIZE;

/// `audit` drains at most this many records per producer per notification.
pub const AUDIT_RING_SLOTS: usize = 128;

/// Bytes of the `eth_out_dma` region (virtqueues and virtio bounce buffers).
pub const ETH_OUT_DMA_SIZE: usize = 0x200_000;
/// Offset of the virtio-mmio transport within the `eth_out_mmio` page.
pub const ETH_OUT_MMIO_OFFSET: usize = 0xe00;
/// GIC interrupt of QEMU virt virtio-mmio slot 31 (SPI 47).
pub const ETH_OUT_IRQ: usize = 79;

/// Bytes of the `rng_dma` region (the virtqueue and its bounce buffers;
/// M7 plan C6).
pub const RNG_DMA_SIZE: usize = 0x200_000;
/// virtio-rng sits on virtio-mmio slot 0 (`bus=virtio-mmio-bus.0`), at the
/// start of its page, which no other device shares.
pub const RNG_MMIO_OFFSET: usize = 0;

/// Inside NIC: virtio-mmio slot 23 (0xa002e00, own page), placed with QEMU
/// `bus=virtio-mmio-bus.23`; GIC interrupt 48 + 23.
pub const ETH_IN_DMA_SIZE: usize = 0x200_000;
pub const ETH_IN_MMIO_OFFSET: usize = 0xe00;
pub const ETH_IN_IRQ: usize = 71;

/// `data`'s stack_size: its handler state, returned by value from init,
/// lives there (crates/pds/data asserts it fits).
pub const DATA_STACK_SIZE: usize = 0x40_000;
/// `tls`'s stack_size, which its stack probe paints.
pub const TLS_STACK_SIZE: usize = 0x30_000;

/// sp804 on QEMU virt (coliasgroup patch): 1 MHz input clock, SPI 11.
pub const TIMER_IRQ: usize = 43;
pub const TIMER_FREQ_HZ: u32 = 1_000_000;

pub mod eth_out {
    pub const CH_DEVICE: usize = 0;
    pub const CH_INGRESS: usize = 1;
    pub const CH_AUDIT: usize = 2;
}

pub mod eth_in {
    pub const CH_DEVICE: usize = 0;
    pub const CH_INNER: usize = 1;
    pub const CH_AUDIT: usize = 2;
}

pub mod ingress {
    pub const CH_ETH_OUT: usize = 1;
    pub const CH_AUDIT: usize = 2;
    pub const CH_HS: usize = 3;
    pub const CH_DATA: usize = 4;
    pub const CH_TIMER: usize = 5;
    pub const CH_PQ: usize = 6;
    pub const CH_TLS: usize = 7;
    pub const CH_RNG: usize = 8;
}

pub mod audit {
    pub const CH_SUPERVISOR: usize = 9;
    pub const CH_INGRESS: usize = 1;
    pub const CH_ETH_OUT: usize = 2;
    pub const CH_ETH_IN: usize = 3;
    pub const CH_INNER: usize = 4;
    pub const CH_HS: usize = 5;
    pub const CH_DATA: usize = 6;
    pub const CH_PQ: usize = 7;
    pub const CH_TLS: usize = 8;
}

#[cfg(test)]
mod tests;

pub mod timer {
    pub const CH_DEVICE: usize = 0;
    pub const CH_DATA: usize = 1;
    pub const CH_HS: usize = 2;
    pub const CH_INGRESS: usize = 3;
    pub const CH_PQ: usize = 4;
    pub const CH_TLS: usize = 5;
}

pub mod key {
    pub const CH_HS: usize = 1;
    pub const CH_TPM: usize = 3;
    pub const CH_RNG: usize = 4;
}

pub mod hs {
    pub const CH_KEY: usize = 1;
    pub const CH_INGRESS: usize = 2;
    pub const CH_DATA: usize = 3;
    pub const CH_TIMER: usize = 4;
    pub const CH_AUDIT: usize = 5;
    pub const CH_PQ: usize = 6;
    pub const CH_RNG: usize = 7;
}

pub mod data {
    pub const CH_INGRESS: usize = 1;
    pub const CH_HS: usize = 2;
    pub const CH_INNER: usize = 3;
    pub const CH_TIMER: usize = 4;
    pub const CH_AUDIT: usize = 5;
}

pub mod inner {
    pub const CH_ETH_IN: usize = 1;
    pub const CH_DATA: usize = 2;
    pub const CH_AUDIT: usize = 3;
    pub const CH_TLS: usize = 4;
}

/// M3: the Rosenpass responder (plan C3).
pub mod pq {
    pub const CH_PQKEY: usize = 1;
    pub const CH_INGRESS: usize = 2;
    pub const CH_HS: usize = 3;
    pub const CH_TIMER: usize = 4;
    pub const CH_AUDIT: usize = 5;
    pub const CH_RNG: usize = 6;
}

/// M6: the HTTPS endpoint (plan C1, C3): TCP and TLS on packets `ingress`
/// vetted, its backend reached through `inner`, its signatures from
/// `tlskey` (plan C12).
pub mod tls {
    pub const CH_INGRESS: usize = 1;
    pub const CH_INNER: usize = 2;
    pub const CH_TIMER: usize = 3;
    pub const CH_TLSKEY: usize = 4;
    pub const CH_AUDIT: usize = 5;
    pub const CH_RNG: usize = 6;
}

/// M6: the TLS signing oracle (plan C12), a passive key-role PD.
pub mod tlskey {
    pub const CH_TLS: usize = 1;
    pub const CH_TPM: usize = 3;
    pub const CH_RNG: usize = 4;
}

/// M3: the McEliece decapsulation oracle (plan C2), a passive key-role PD.
pub mod pqkey {
    pub const CH_PQ: usize = 1;
    pub const CH_TPM: usize = 3;
    pub const CH_RNG: usize = 4;
}

/// M7: the supervisor (plan C8), parent of every other PD; its one channel
/// notifies `audit` of a fault record. Child ids are
/// `supervisor_core::CHILDREN`'s indices.
pub mod supervisor {
    pub const CH_AUDIT: usize = 1;
}

/// M7: the entropy driver (plan C6), callee of the PDs that draw
/// randomness; one id per caller, `rng_core::Caller`'s order. One PPC label:
/// `SEED` (no words in) answers `SEED` with the 32-byte seed in four words,
/// or `UNAVAILABLE` with the reason code in one.
pub mod rng {
    pub const CH_HS: usize = 1;
    pub const CH_PQ: usize = 2;
    pub const CH_INGRESS: usize = 3;
    pub const CH_TLS: usize = 4;
    pub const CH_KEY: usize = 5;
    pub const CH_PQKEY: usize = 6;
    pub const CH_TLSKEY: usize = 7;
    pub const SEED: u64 = 0;
    pub const UNAVAILABLE: u64 = 1;
}

/// M5: the TPM driver (plan C9), callee of the key PDs only, and its
/// PPC protocol. One call carries one TPM command or response in the
/// message registers, little-endian bytes packed into words, its byte
/// length in the label: `label = kind << KIND_SHIFT | arg`.
///
/// M8 (plan C3): the `policy` PD's channel carries the four policy
/// requests only, never a TPM command.
pub mod tpm {
    pub const CH_KEY: usize = 1;
    pub const CH_PQKEY: usize = 2;
    pub const CH_TLSKEY: usize = 3;
    /// The `policy` PD (M8 plan C3, C5); 4 is left for `auditkey` (C10).
    pub const CH_POLICY: usize = 5;
    /// Whether the system has the `policy` PD (M8 deviation D-6): `tpm`'s
    /// cap waits for its Done or Failed only then. Set in the same change
    /// that adds the PD to `system/kozane.system`; a test ties the two.
    pub const POLICY_PRESENT: bool = false;

    /// seL4's IPC buffer carries 120 message words.
    pub const MSG_WORDS: usize = 120;
    pub const MSG_BYTES: usize = MSG_WORDS * 8;
    /// The TIS page (locality 0) of QEMU virt's `tpm-tis-device`, the first
    /// device on the platform bus.
    pub const TIS_PADDR: usize = 0xc00_0000;
    pub const TIS_SIZE: usize = 0x1000;

    pub const KIND_SHIFT: u32 = 16;
    pub const ARG_MASK: u64 = (1 << KIND_SHIFT) - 1;
    const _: () = assert!(MSG_BYTES as u64 <= ARG_MASK);

    /// Requests. `arg`: the command's byte length; 0 for Done and Failed.
    pub const REQ_COMMAND: u64 = 1;
    /// The client flushed its handles after a successful unseal.
    pub const REQ_DONE: u64 = 2;
    /// The same after a failed one.
    pub const REQ_FAILED: u64 = 3;
    /// The cap barrier (post-M6 plan P3): a Done client asks whether PCR 8
    /// is capped before it releases its key. A label of this protocol, not
    /// a TPM command: the gate refuses a Done client every command. Answered
    /// RSP_BUSY while the cap is pending, RSP_OK once confirmed, and
    /// RSP_REFUSED with `REFUSED_CAP_FAILED` once failed.
    pub const REQ_CAP_STATUS: u64 = 4;
    /// The policy requests (M8 plan C3), on `CH_POLICY` alone. State: no
    /// words in; answered RSP_OK with `POLICY_STATE_LEN` bytes
    /// (`encode_state`), or RSP_REFUSED with the refusal's code.
    pub const REQ_POLICY_STATE: u64 = 5;
    /// Advance: the expected version, `POLICY_VALUE_LEN` bytes (u32,
    /// little-endian); answered RSP_OK with the version read after the
    /// increment in the same form, or RSP_REFUSED.
    pub const REQ_POLICY_ADVANCE: u64 = 6;
    /// Done and Failed: no words; answered RSP_OK (the cap's verdict goes
    /// to the key PDs' cap barrier, not to `policy`).
    pub const REQ_POLICY_DONE: u64 = 7;
    pub const REQ_POLICY_FAILED: u64 = 8;

    /// The State reply: the logical version (u32, little-endian), then PCR 9.
    pub const POLICY_STATE_LEN: usize = 4 + 32;
    /// The Advance request and reply: one version (u32, little-endian).
    pub const POLICY_VALUE_LEN: usize = 4;

    /// Replies. `arg`: the response's byte length (for Done and Failed, 0).
    pub const RSP_OK: u64 = 1;
    /// The gate refused; `arg` is the refusal's code.
    pub const RSP_REFUSED: u64 = 2;
    /// The device timed out or broke the TIS protocol; `arg` is the step.
    pub const RSP_DEVICE: u64 = 3;
    /// Another client's flow is under way: call again later. Only a
    /// client that has not started is told this.
    pub const RSP_BUSY: u64 = 4;
    /// Not a request of this protocol, or a caller `tpm` does not serve.
    pub const RSP_BAD_REQUEST: u64 = 5;

    /// RSP_REFUSED's arg when the cap failed: to the cap status, and to the
    /// Done (or Failed) whose cap failed. Above every gate refusal's code.
    pub const REFUSED_CAP_FAILED: usize = 11;

    pub const fn label(kind: u64, arg: usize) -> u64 {
        kind << KIND_SHIFT | (arg as u64 & ARG_MASK)
    }

    pub const fn kind(label: u64) -> u64 {
        label >> KIND_SHIFT
    }

    pub const fn arg(label: u64) -> usize {
        (label & ARG_MASK) as usize
    }

    pub fn encode_state(current: u32, pcr9: &[u8; 32]) -> [u8; POLICY_STATE_LEN] {
        let mut out = [0u8; POLICY_STATE_LEN];
        let (version, pcr) = out.split_at_mut(POLICY_VALUE_LEN);
        version.copy_from_slice(&current.to_le_bytes());
        pcr.copy_from_slice(pcr9);
        out
    }

    /// The State reply's version and PCR 9, if `bytes` is exactly one.
    pub fn decode_state(bytes: &[u8]) -> Option<(u32, [u8; 32])> {
        if bytes.len() != POLICY_STATE_LEN {
            return None;
        }
        let (version, pcr) = bytes.split_at(POLICY_VALUE_LEN);
        Some((decode_value(version)?, pcr.try_into().ok()?))
    }

    /// One version, if `bytes` is exactly `POLICY_VALUE_LEN` long.
    pub fn decode_value(bytes: &[u8]) -> Option<u32> {
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }

    /// Words that carry `len` bytes.
    pub const fn words(len: usize) -> usize {
        len.div_ceil(8)
    }

    /// Packs `bytes` into `words` (the tail of the last word zero); returns
    /// the word count, or None if they do not fit.
    pub fn pack(bytes: &[u8], words: &mut [u64]) -> Option<usize> {
        let n = self::words(bytes.len());
        let dst = words.get_mut(..n)?;
        for (w, chunk) in dst.iter_mut().zip(bytes.chunks(8)) {
            let mut b = [0u8; 8];
            b.get_mut(..chunk.len())?.copy_from_slice(chunk);
            *w = u64::from_le_bytes(b);
        }
        Some(n)
    }

    /// Unpacks `len` bytes from `words` into `out`; None if `words` holds
    /// fewer or `out` is shorter.
    pub fn unpack(words: &[u64], len: usize, out: &mut [u8]) -> Option<()> {
        let src = words.get(..self::words(len))?;
        let out = out.get_mut(..len)?;
        for (chunk, w) in out.chunks_mut(8).zip(src) {
            chunk.copy_from_slice(w.to_le_bytes().get(..chunk.len())?);
        }
        Some(())
    }
}
