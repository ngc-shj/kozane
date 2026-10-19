//! The gateway configuration, validated and compiled in at build time
//! (law L6: no runtime configuration path). See build.rs.

#![no_std]

#[cfg(test)]
extern crate std;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    pub addr: [u8; 4],
    pub len: u8,
}

impl Prefix {
    pub const fn contains(&self, ip: [u8; 4]) -> bool {
        let mask = if self.len == 0 { 0 } else { u32::MAX << (32 - self.len as u32) };
        (u32::from_be_bytes(ip) & mask) == (u32::from_be_bytes(self.addr) & mask)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Peer {
    pub public: [u8; 32],
    /// BLAKE2s-256 of the peer's McEliece public key (`pq` checks the
    /// embedded key against it at boot, M3 plan S8).
    pub rp_hash: [u8; 32],
    pub allowed: &'static [Prefix],
}

#[derive(Debug, Clone, Copy)]
pub struct Neighbor {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
}

include!(concat!(env!("OUT_DIR"), "/config.rs"));

/// The peer whose allowed IPs contain `ip` (allowed IPs never overlap).
pub fn peer_for(ip: [u8; 4]) -> Option<usize> {
    PEERS.iter().position(|p| p.allowed.iter().any(|a| a.contains(ip)))
}

#[cfg(test)]
mod tests;
