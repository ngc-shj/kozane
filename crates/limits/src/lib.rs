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

/// Most peers a bundle can name (M8 plan C1): `data`'s per-peer sessions
/// and replay windows size against it, as `config::MAX_PEERS` did.
pub const MAX_PEERS: usize = 8;
/// Most allowed-IP prefixes one peer's bundle entry can carry (M8 plan C1).
pub const MAX_ALLOWED: usize = 8;
/// Most groups one fleet's bundle can define (M8 plan C1); a peer's group
/// membership is a bitmask this wide.
pub const MAX_GROUPS: usize = 8;
/// Most rules one group can carry (M8 plan C1).
pub const MAX_RULES: usize = 16;
/// Classic McEliece 460896 public key length (M8 plan C1), the rp key
/// every peer and the gateway carry; matches `rosenpass_core::SPK_LEN`.
pub const SPK_LEN: usize = 524_160;
/// The bundle slot's fixed size (M8 plan C1): at least the largest bundle
/// `MAX_PEERS`/`MAX_GROUPS`/`MAX_ALLOWED`/`MAX_RULES`/`SPK_LEN` can encode,
/// so every fleet size fits one slot with no variable-length framing.
pub const BUNDLE_MAX: usize = 0x480_000;

/// Flows `inner` tracks for peer-opened traffic (M8 plan C8, D9): each peer
/// owns `MAX_FLOWS / MAX_PEERS` of them (64), room for a device's working
/// set of LAN connections, while one outbound lookup scans at most 512
/// entries (about 20 KiB, held in a static, not on `inner`'s stack).
pub const MAX_FLOWS: usize = 512;
/// A flow with no packet either way for this long ends: two minutes, the
/// common NAT/conntrack idle bound for UDP, so a quiet TCP connection (an
/// idle SSH session) needs its own keepalives, as it would behind any NAT.
pub const FLOW_IDLE_NS: u64 = 120_000_000_000;
/// A TCP flow stays this long after FIN was seen both ways, so the last ACK
/// and a retransmitted FIN still pass: ten seconds, well above a LAN RTT
/// and short enough that a closed flow frees its slot soon.
pub const FLOW_LINGER_NS: u64 = 10_000_000_000;
const _: () = assert!(MAX_FLOWS.is_multiple_of(MAX_PEERS) && MAX_FLOWS / MAX_PEERS >= 1, "MAX_FLOWS must split into per-peer quotas");
const _: () = assert!(FLOW_LINGER_NS < FLOW_IDLE_NS, "a closed flow outlives an idle one");

#[cfg(test)]
mod tests;
