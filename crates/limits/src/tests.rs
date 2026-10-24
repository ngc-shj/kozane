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
