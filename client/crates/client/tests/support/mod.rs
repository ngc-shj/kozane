//! Test support shared by `kozane-client`'s unit tests and the FFI tests
//! (included by `#[path]`): real Classic McEliece key pairs for the client
//! and the gateway, and the real `rosenpass-core` responder as the gateway.

#![allow(
    dead_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::sync::OnceLock;

use rosenpass_core::{
    Conf, Decaps, DecapsError, Kyber512, McEliece460896, Responder, Rng, RngError, SHK_LEN, SPK_LEN, Seams, Secret,
};
use rosenpass_wire::{EMPTY_DATA_LEN, RESP_HELLO_LEN, SCT_LEN};
use secret_blob::pq;

pub const S: u64 = 1_000_000_000;

pub struct SysRng;

impl Rng for SysRng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        getrandom::fill(out).map_err(|_| RngError)
    }
}

pub struct Pair {
    pub public: Box<[u8; SPK_LEN]>,
    /// Round-3 layout, for the gateway's decapsulation.
    pub secret: Box<[u8; pq::SK_LEN]>,
    /// liboqs layout, as `rp.sk` holds it.
    pub secret_oqs: Box<[u8; pq::LIBOQS_SK_LEN]>,
}

fn zeroed<const N: usize>() -> Box<[u8; N]> {
    vec![0u8; N].into_boxed_slice().try_into().unwrap()
}

fn keypair() -> Pair {
    // Key generation needs about 1.1 MB of stack.
    std::thread::Builder::new()
        .stack_size(16 << 20)
        .spawn(|| {
            let (mut public, mut secret) = (zeroed::<SPK_LEN>(), zeroed::<{ pq::SK_LEN }>());
            mce460896::keypair(&mut |out| getrandom::fill(out).map_err(|_| mce460896::RngError), &mut public, &mut secret)
                .unwrap();
            let mut secret_oqs = zeroed::<{ pq::LIBOQS_SK_LEN }>();
            pq::liboqs_sk_from_cmr(&mut secret_oqs, &secret);
            Pair { public, secret, secret_oqs }
        })
        .unwrap()
        .join()
        .unwrap()
}

/// The gateway's and the client's key pairs, generated once per test binary.
pub fn pairs() -> &'static (Pair, Pair) {
    static PAIRS: OnceLock<(Pair, Pair)> = OnceLock::new();
    PAIRS.get_or_init(|| (keypair(), keypair()))
}

pub fn gateway_pair() -> &'static Pair {
    &pairs().0
}

pub fn client_pair() -> &'static Pair {
    &pairs().1
}

struct GwDecaps(&'static [u8; pq::SK_LEN]);

impl Decaps for GwDecaps {
    fn decaps(&mut self, sct: &[u8; SCT_LEN]) -> Result<Secret<SHK_LEN>, DecapsError> {
        let mut shk = Secret::zero();
        mce460896::decaps(self.0, sct, shk.expose_mut());
        Ok(shk)
    }
}

/// The gateway: `rosenpass-core`'s responder with real KEMs, one peer (the
/// client).
pub struct Gateway(Responder<'static>);

impl Gateway {
    pub fn new(now: u64) -> Self {
        let mut r = Responder::new(&gateway_pair().public, &[&client_pair().public], &mut SysRng).unwrap();
        r.tick(now, &mut SysRng).unwrap();
        Self(r)
    }

    pub fn respond(&mut self, ih: &[u8], now: u64) -> [u8; RESP_HELLO_LEN] {
        self.0.tick(now, &mut SysRng).unwrap();
        let mut out = [0u8; RESP_HELLO_LEN];
        let seams = &mut Seams {
            decaps: &mut GwDecaps(&gateway_pair().secret),
            kyber: &mut Kyber512,
            mceliece: &mut McEliece460896,
            rng: &mut SysRng,
        };
        assert_eq!(self.0.handle_init_hello(ih, now, seams, &mut out), Ok(0), "gateway refused the InitHello");
        out
    }

    /// The EmptyData for `ic` and the OSK the gateway installs.
    pub fn confirm(&mut self, ic: &[u8], now: u64) -> ([u8; EMPTY_DATA_LEN], [u8; 32]) {
        let Ok(Conf::Fresh(p)) = self.0.handle_init_conf(ic, now) else {
            panic!("gateway refused the InitConf");
        };
        let osk = *p.psk_install().osk.expose();
        (self.0.commit_conf(p, now).unwrap(), osk)
    }
}
