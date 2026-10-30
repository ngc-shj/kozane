//! The gateway configuration, validated and compiled in at build time
//! (law L6: no runtime configuration path). See build.rs. The peers are
//! not in it: they arrive in the signed bundle `policy` verifies (M8 plan
//! D4, C7), checked against `node_config()`.

#![no_std]

#[cfg(test)]
extern crate std;

/// An IPv4 prefix (M8 plan C1 R2): `policy-wire`'s type, so the bundle and
/// the build-time configuration share one `contains`/`overlaps`.
pub use policy_wire::Prefix;

#[derive(Debug, Clone, Copy)]
pub struct Neighbor {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
}

include!(concat!(env!("OUT_DIR"), "/config.rs"));

/// The compiled facts a peer-policy bundle is validated against (M8 plan
/// C1, C7): `policy-wire`'s `NodeConfig`, built from this configuration
/// alone.
pub const fn node_config() -> policy_wire::NodeConfig<'static> {
    policy_wire::NodeConfig {
        fleet_id: FLEET_ID,
        inside_prefix: INSIDE_PREFIX,
        inside_ip: INSIDE_IP,
        outside_ip: OUTSIDE_IP,
        neighbors: NEIGHBOR_IPS,
        gateway_wg_public: GATEWAY_PUBLIC,
        gateway_rp_digest: GATEWAY_RP_HASH,
    }
}

#[cfg(test)]
mod tests;
