//! Sizes and channel numbers shared by PDs and `system/secureos.system`.
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

/// Inside NIC: virtio-mmio slot 23 (0xa002e00, own page), placed with QEMU
/// `bus=virtio-mmio-bus.23`; GIC interrupt 48 + 23.
pub const ETH_IN_DMA_SIZE: usize = 0x200_000;
pub const ETH_IN_MMIO_OFFSET: usize = 0xe00;
pub const ETH_IN_IRQ: usize = 71;

/// `data`'s stack_size: its handler state, returned by value from init,
/// lives there (crates/pds/data asserts it fits).
pub const DATA_STACK_SIZE: usize = 0x20_000;
/// `tls`'s stack_size, which its stack probe paints.
pub const TLS_STACK_SIZE: usize = 0x20_000;
/// `tls`'s MCS budget and period (system file µs × 1000): a `TLS_SIGN`
/// runs on this budget, which bounds how long `hs` can wait behind it in
/// `key` (M6 plan C5, the invariant in `hs-core`).
pub const TLS_BUDGET_NS: u64 = 500_000;
pub const PERIOD_NS: u64 = 10_000_000;

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
}

pub mod audit {
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
    pub const CH_TLS: usize = 4;
}

pub mod hs {
    pub const CH_KEY: usize = 1;
    pub const CH_INGRESS: usize = 2;
    pub const CH_DATA: usize = 3;
    pub const CH_TIMER: usize = 4;
    pub const CH_AUDIT: usize = 5;
    pub const CH_PQ: usize = 6;
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
}

/// M6: the HTTPS endpoint (plan C1, C3): TCP and TLS on packets `ingress`
/// vetted, its backend reached through `inner`, its signatures from `key`.
pub mod tls {
    pub const CH_INGRESS: usize = 1;
    pub const CH_INNER: usize = 2;
    pub const CH_TIMER: usize = 3;
    pub const CH_KEY: usize = 4;
    pub const CH_AUDIT: usize = 5;
}

/// M3: the McEliece decapsulation oracle (plan C2), a passive key-role PD.
pub mod pqkey {
    pub const CH_PQ: usize = 1;
    pub const CH_TPM: usize = 3;
}

/// M5: the TPM driver (plan C9), callee of `key` and `pqkey` only, and its
/// PPC protocol. One call carries one TPM command or response in the
/// message registers, little-endian bytes packed into words, its byte
/// length in the label: `label = kind << KIND_SHIFT | arg`.
pub mod tpm {
    pub const CH_KEY: usize = 1;
    pub const CH_PQKEY: usize = 2;

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

    /// Replies. `arg`: the response's byte length (for Done and Failed, 0).
    pub const RSP_OK: u64 = 1;
    /// The gate refused; `arg` is the refusal's code.
    pub const RSP_REFUSED: u64 = 2;
    /// The device timed out or broke the TIS protocol; `arg` is the step.
    pub const RSP_DEVICE: u64 = 3;
    /// The other client's flow is under way: call again later. Only a
    /// client that has not started is told this.
    pub const RSP_BUSY: u64 = 4;
    /// Not a request of this protocol, or a caller `tpm` does not serve.
    pub const RSP_BAD_REQUEST: u64 = 5;

    pub const fn label(kind: u64, arg: usize) -> u64 {
        kind << KIND_SHIFT | (arg as u64 & ARG_MASK)
    }

    pub const fn kind(label: u64) -> u64 {
        label >> KIND_SHIFT
    }

    pub const fn arg(label: u64) -> usize {
        (label & ARG_MASK) as usize
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
