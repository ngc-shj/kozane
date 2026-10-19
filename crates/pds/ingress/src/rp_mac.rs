//! The PD's Rosenpass envelope mac (M3 plan C4 [T12]): upstream's
//! mac = KH(KH(D_mac, spkm), msg[..mac])[..16], with the incorrect-HMAC KH,
//! through rosenpass-core. The key is public and derived once at init, so
//! the 512 KiB `spkm` is not kept. Free of seL4 and of ingress-core (main.rs
//! plugs it into `RpMac`), so it builds on the host.

use rosenpass_core::crypto::ct_eq;
use rosenpass_core::{CryptoError, Domains, KEY_LEN, SPK_LEN, envelope_mac, mac_key};
use rosenpass_wire::{MAC_LEN, mac_offset};

pub struct RpMacKey {
    /// KH(D_mac, spkm): public, like the WireGuard mac1 key.
    key: [u8; KEY_LEN],
}

impl RpMacKey {
    pub fn new(spkm: &[u8; SPK_LEN]) -> Result<Self, CryptoError> {
        Ok(Self { key: mac_key(&Domains::v02()?, spkm)? })
    }

    /// Whether `msg`'s mac field holds the envelope mac of the bytes before
    /// it. A message too short to hold a mac fails.
    pub fn verify(&self, msg: &[u8]) -> bool {
        let got = msg.get(mac_offset(msg.len())..).and_then(|m| m.first_chunk::<MAC_LEN>());
        match (envelope_mac(&self.key, msg), got) {
            (Ok(want), Some(got)) => ct_eq(&want, got),
            _ => false,
        }
    }
}
