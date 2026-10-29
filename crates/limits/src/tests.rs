extern crate std;

use super::*;

#[test]
fn the_global_syn_bucket_is_sixteen_at_twenty_per_second() {
    assert_eq!(SYN_GLOBAL_BURST, 16);
    assert_eq!(SYN_GLOBAL_INTERVAL_NS, 50_000_000);
    assert_eq!(1_000_000_000 / SYN_GLOBAL_INTERVAL_NS, 20);
}

/// The value of `pub const NAME: u64 = <value>;` in `source`.
fn const_u64(source: &str, name: &str) -> u64 {
    let prefix = std::format!("pub const {name}: u64 = ");
    let at = source.find(&prefix).unwrap_or_else(|| panic!("no {prefix:?}")) + prefix.len();
    let rest = &source[at..];
    rest[..rest.find(';').unwrap()].replace('_', "").parse().unwrap()
}

/// ingress-core takes the global bucket from here, and its per-source SYN
/// bucket stays within it: the relation its own compile-time asserts state,
/// checked again against the values this crate defines.
#[test]
fn ingress_core_uses_these_values_and_its_source_bucket_stays_within_them() {
    let ingress = include_str!("../../ingress-core/src/lib.rs");
    assert!(ingress.contains("pub use limits::{SYN_GLOBAL_BURST, SYN_GLOBAL_INTERVAL_NS};"));
    assert!(!ingress.contains("pub const SYN_GLOBAL_"), "ingress-core defines its own global SYN bucket");
    let (src_burst, src_interval) = (const_u64(ingress, "SYN_SRC_BURST"), const_u64(ingress, "SYN_SRC_INTERVAL_NS"));
    assert!(src_burst <= SYN_GLOBAL_BURST, "a source's SYN burst {src_burst} above the global {SYN_GLOBAL_BURST}");
    assert!(src_interval >= SYN_GLOBAL_INTERVAL_NS, "a source's SYN rate above the global");
}

#[test]
fn the_m8_bounds_are_the_plans_values() {
    assert_eq!((MAX_PEERS, MAX_ALLOWED, MAX_GROUPS, MAX_RULES), (8, 8, 8, 16));
    assert_eq!(SPK_LEN, 524_160);
    assert_eq!(BUNDLE_MAX, 0x480_000);
}

/// `BUNDLE_MAX` must fit the largest bundle the format in `policy-wire` can
/// encode: the fixed header, `MAX_PEERS` peers each with `MAX_ALLOWED`
/// prefixes and one `SPK_LEN` rp key, `MAX_GROUPS` groups each with
/// `MAX_RULES` rules, and the two signatures (Ed25519 and ML-DSA-65).
#[test]
fn bundle_max_fits_the_largest_encodable_bundle() {
    const HEADER: usize = 4 + 2 + 16 + 4 + 4 + 32 + 32 + 1 + 1;
    const PREFIX: usize = 4 + 1;
    const PEER: usize = 32 + SPK_LEN + 1 + 1 + MAX_ALLOWED * PREFIX;
    const RULE: usize = PREFIX + 1 + 2 + 2;
    const GROUP: usize = 1 + MAX_RULES * RULE;
    const SIGS: usize = 64 + 3309;
    let largest = HEADER + MAX_PEERS * PEER + MAX_GROUPS * GROUP + SIGS;
    assert!(BUNDLE_MAX >= largest, "BUNDLE_MAX {BUNDLE_MAX} < largest encodable bundle {largest}");
}
