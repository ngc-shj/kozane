//! Rate limits two crates size themselves against (M6 plan C12): the
//! global SYN bucket `ingress` meters new HTTPS connections with
//! (ingress-core), and which `tlskey`'s sign bucket must cover
//! (tlskey-core). A leaf with no dependencies, so neither crate needs the
//! other and neither reruns the other's proofs.

#![no_std]

/// `ingress`'s global SYN bucket: 16 at one per 50 ms (20 per second), the
/// most handshakes it forwards to `tls`, each of which costs one signature.
pub const SYN_GLOBAL_BURST: u64 = 16;
pub const SYN_GLOBAL_INTERVAL_NS: u64 = 50_000_000;

#[cfg(test)]
mod tests;
