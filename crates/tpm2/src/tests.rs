#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects)]

extern crate std;

use std::boxed::Box;
use std::vec;
use std::vec::Vec;

use tpm2_wire::{CC_FLUSH_CONTEXT, CC_IMPORT, CC_LOAD, CC_START_AUTH_SESSION, CC_UNSEAL, IPC_MSG_BYTES, Writer};

use super::Secret;
use super::client::{CLIENT_ENTROPY_LEN, Cause, Client, Failure, Step, UNSEAL_ATTRIBUTES};
use super::crypto;
use super::envelope::{self, EnvError, Envelope, HEADER_LEN, KEY_MAX_PEERS, Kind, SEAL_ENTROPY_LEN};

fn hex<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn secret<const N: usize>(bytes: &[u8]) -> Secret<N> {
    let mut s = Secret::<N>::zero();
    s.as_mut_bytes().copy_from_slice(bytes);
    s
}

// Known answers. KDFa, KDFe and ECDH: computed with pyca/cryptography 43.0.0
// (KBKDFHMAC in counter mode, counter before the fixed input, r = 32 and
// L = 32 bits: TPM 2.0 Part 1's KDFa; ConcatKDFHash: Part 1's KDFe;
// ECDH on SECP256R1), an implementation independent of libcrux. Inputs:
// key 00..1f, contextU 40..5f, contextV 80..9f, Z c0..df.
const KEY: [u8; 32] = {
    let mut k = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        k[i] = i as u8;
        i += 1;
    }
    k
};

fn range(start: u8) -> [u8; 32] {
    core::array::from_fn(|i| start + i as u8)
}

#[test]
fn kdfa_matches_sp800_108_counter_mode_known_answers() {
    let (u, v) = (range(0x40), range(0x80));
    let mut out = [0u8; 32];
    crypto::kdfa(&KEY, b"ATH", &u, &v, &mut out).unwrap();
    assert_eq!(out, hex::<32>("4cfbf4144b94620cadfb0b65f86d9772cd5c3fd3adb70f6cdf5ac455e51b0485"));
    let mut out = [0u8; 16];
    crypto::kdfa(&KEY, b"STORAGE", &u[..2], &v, &mut out).unwrap();
    assert_eq!(out, hex::<16>("e4156687441dd07b3a9e60ebb836eb9f"));
    let mut out = [0u8; 64];
    crypto::kdfa(&KEY, b"CFB", &u, &v, &mut out).unwrap();
    assert_eq!(
        out,
        hex::<64>(
            "424b1f1c0d95a520931f772f1c6bbf0b9d23e0375687143b5910c05a21394e14\
             ad70aab49576aefaf878ffac407744a45addb92559dbf01e69912bcd25ac0eba"
        )
    );
}

#[test]
fn kdfe_matches_sp800_56a_concatenation_kdf_known_answer() {
    let mut out = Secret::<32>::zero();
    crypto::kdfe(&mut out, &range(0xc0), b"SECRET", &range(0x40), &range(0x80));
    assert_eq!(out.as_bytes(), &hex::<32>("6cf01a5bcc3b981e799dd9350026306012a3901d1c9bd1c519b696741d5c0cf7"));
}

#[test]
fn p256_public_points_and_ecdh_match_known_answers_both_ways() {
    let d1 = secret::<32>(&range(1));
    let d2 = secret::<32>(&range(33));
    let q1 = crypto::public_point(&d1).unwrap();
    let q2 = crypto::public_point(&d2).unwrap();
    assert_eq!(
        q1,
        hex::<64>(
            "515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f\
             4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354"
        )
    );
    assert_eq!(
        q2,
        hex::<64>(
            "1f140146bfb1b251f84f4ddbe0d4cdcfd77afd984a9520e35794021f8312bb9e\
             ec995a08b1fa7704df3dcc0b50a9665263fb7711f95f9f8a449c5096e47c892b"
        )
    );
    let z = hex::<32>("4fe243908f378aa1c2a69538822e6ed908c3225d8692575507c649901245150a");
    let mut z12 = Secret::<32>::zero();
    crypto::ecdh(&mut z12, &d1, &q2).unwrap();
    let mut z21 = Secret::<32>::zero();
    crypto::ecdh(&mut z21, &d2, &q1).unwrap();
    assert_eq!((z12.as_bytes(), z21.as_bytes()), (&z, &z));
}

#[test]
fn ecdh_refuses_a_point_off_the_curve_and_a_zero_scalar() {
    let d = secret::<32>(&range(1));
    let mut bad = crypto::public_point(&d).unwrap();
    bad[63] ^= 1;
    assert!(crypto::ecdh(&mut Secret::zero(), &d, &bad).is_none());
    assert!(crypto::public_point(&Secret::<32>::zero()).is_none());
}

// NIST SP 800-38A F.3.13, CFB128-AES128.Encrypt.
const CFB_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const CFB_IV: &str = "000102030405060708090a0b0c0d0e0f";
const CFB_PLAIN: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                         30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
const CFB_CIPHER: &str = "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b\
                          26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6";

#[test]
fn cfb_matches_sp800_38a_and_decrypts_back() {
    let mut data = hex::<64>(CFB_PLAIN);
    crypto::cfb(&hex(CFB_KEY), &hex(CFB_IV), &mut data, false);
    assert_eq!(data, hex::<64>(CFB_CIPHER));
    crypto::cfb(&hex(CFB_KEY), &hex(CFB_IV), &mut data, true);
    assert_eq!(data, hex::<64>(CFB_PLAIN));
}

#[test]
fn cfb_truncates_a_short_last_block() {
    let mut data: [u8; 20] = hex::<64>(CFB_PLAIN)[..20].try_into().unwrap();
    crypto::cfb(&hex(CFB_KEY), &hex(CFB_IV), &mut data, false);
    assert_eq!(data[..], hex::<64>(CFB_CIPHER)[..20]);
}

#[test]
fn hmac_and_sha256_match_rfc_4231_and_fips_180_vectors() {
    let mut out = [0u8; 32];
    crypto::hmac(&mut out, b"Jefe", &[b"what do ya ", b"want for nothing?"]).unwrap();
    assert_eq!(out, hex::<32>("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    assert_eq!(
        crypto::sha256(&[b"a", b"bc"]),
        hex::<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn policy_digest_extends_the_pcr_policy_with_policy_auth_value() {
    let pcr = [7u8; 32];
    let pcr_only = crypto::policy_pcr_digest(&pcr);
    assert_eq!(crypto::policy_digest(&pcr), crypto::sha256(&[&pcr_only, &0x16Bu32.to_be_bytes()]));
    assert_ne!(crypto::policy_digest(&pcr), crypto::policy_digest(&[8u8; 32]));
}

// A test SRK whose private scalar the fake TPM below holds.
fn srk_scalar() -> Secret<32> {
    secret(&range(0x21))
}

fn srk_public() -> Vec<u8> {
    let q = crypto::public_point(&srk_scalar()).unwrap();
    let mut p = tpm2_wire::SRK_PUBLIC_PREFIX.to_vec();
    p.extend_from_slice(&crypto::ecc_point(&q));
    p
}

const PCR8: [u8; 32] = [0x42; 32];

fn seal_entropy(tag: u8) -> Secret<SEAL_ENTROPY_LEN> {
    let mut s = Secret::<SEAL_ENTROPY_LEN>::zero();
    for (i, b) in s.as_mut_bytes().iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7) ^ tag;
    }
    s
}

fn kek(tag: u8) -> [u8; 32] {
    seal_entropy(tag).as_bytes()[..32].try_into().unwrap()
}

fn region(kind: Kind, len: usize) -> Vec<u8> {
    let mut r = vec![0u8; kind.region_size()];
    for (i, b) in r.iter_mut().take(len).enumerate() {
        *b = (i as u8) | 0x80;
    }
    r
}

fn sealed(kind: Kind, plain: &[u8], tag: u8) -> Vec<u8> {
    let mut out = vec![0u8; kind.region_size()];
    envelope::seal(&mut out, kind, plain, &srk_public(), &PCR8, &seal_entropy(tag)).unwrap();
    out
}

fn open(env: &[u8], kind: Kind, kek: &[u8; 32]) -> (Result<(), EnvError>, Vec<u8>) {
    let mut out = vec![0xAAu8; kind.region_size()];
    let r = Envelope::parse(env, kind).and_then(|e| e.open(&wg_core::crypto::Key32::copy_from(kek), &mut out));
    (r, out)
}

#[test]
fn sealed_envelope_parses_and_opens_to_the_region_both_kinds() {
    for (kind, len) in [(Kind::Key, 1000), (Kind::Pq, secret_blob::pq::USED_LEN)] {
        let plain = region(kind, len);
        let env = sealed(kind, &plain, 1);
        let e = Envelope::parse(&env, kind).unwrap();
        assert_eq!(e.payload_len(), len);
        assert_eq!(e.srk_public(), &srk_public()[..]);
        assert_eq!(e.object_policy(), &crypto::policy_digest(&PCR8));
        let (r, out) = open(&env, kind, &kek(1));
        assert_eq!(r, Ok(()));
        assert!(out == plain, "{kind:?} did not open to its region");
    }
}

/// The payload is the region without its trailing zeros: a blob whose last
/// used bytes are zero seals a shorter payload and still opens to the whole
/// region, byte for byte (`open` zero-fills before the AEAD writes).
#[test]
fn a_region_ending_in_zero_bytes_opens_to_itself() {
    let mut plain = region(Kind::Key, 1000);
    plain[990..1000].fill(0);
    plain[995] = 0x01;
    let env = sealed(Kind::Key, &plain, 1);
    assert_eq!(Envelope::parse(&env, Kind::Key).unwrap().payload_len(), 996);
    let (r, out) = open(&env, Kind::Key, &kek(1));
    assert_eq!(r, Ok(()));
    assert!(out == plain, "a region ending in zero bytes did not open to itself");
}

#[test]
fn the_envelope_header_offsets_are_the_documented_ones() {
    let env = sealed(Kind::Key, &region(Kind::Key, 10), 1);
    assert_eq!(&env[..8], b"SOSSEAL1");
    assert_eq!(&env[20..54], &crypto::name(&srk_public())[..]);
    assert_eq!(&env[54..56], &[0, 90]);
    assert_eq!(&env[146..156], &tpm2_wire::PCR_SELECTION);
    assert_eq!(&env[156..188], &crypto::policy_digest(&PCR8));
    assert_eq!(&env[188..190], &[0, 78]);
    assert_eq!(&env[268..270], &[0, 108]);
    assert_eq!(&env[378..380], &[0, 68]);
    assert_eq!(HEADER_LEN, 448);
}

#[test]
fn every_flipped_byte_in_header_or_ciphertext_is_refused_and_leaves_no_plaintext() {
    let plain = region(Kind::Key, 100);
    let env = sealed(Kind::Key, &plain, 1);
    let end = HEADER_LEN + 100 + 16;
    for i in 0..end + 8 {
        let mut bad = env.clone();
        bad[i] ^= 0x01;
        // Refused by the parser, or else by the AEAD with the output zeroed.
        if let Ok(e) = Envelope::parse(&bad, Kind::Key) {
            let mut out = vec![0xAAu8; Kind::Key.region_size()];
            let r = e.open(&wg_core::crypto::Key32::copy_from(&kek(1)), &mut out);
            assert!(r.is_err(), "byte {i} flipped and the envelope opened");
            assert!(out.iter().all(|b| *b == 0), "byte {i}: output not zeroed");
        }
    }
}

#[test]
fn a_wrong_kek_does_not_open_the_envelope() {
    let env = sealed(Kind::Key, &region(Kind::Key, 100), 1);
    let (r, out) = open(&env, Kind::Key, &kek(2));
    assert_eq!(r, Err(EnvError::Auth));
    assert!(out.iter().all(|b| *b == 0));
}

#[test]
fn parse_refuses_each_malformed_field() {
    let env = sealed(Kind::Key, &region(Kind::Key, 100), 1);
    let with = |at: usize, bytes: &[u8]| {
        let mut e = env.clone();
        e[at..at + bytes.len()].copy_from_slice(bytes);
        Envelope::parse(&e, Kind::Key).err()
    };
    assert_eq!(Envelope::parse(&env, Kind::Pq).err(), Some(EnvError::Size));
    assert_eq!(Envelope::parse(&env[..4095], Kind::Key).err(), Some(EnvError::Size));
    assert_eq!(with(0, b"SOSSECR1"), Some(EnvError::BadMagic));
    assert_eq!(with(8, &2u32.to_le_bytes()), Some(EnvError::BadVersion));
    assert_eq!(with(12, &2u32.to_le_bytes()), Some(EnvError::BadKind));
    let too_long = u32::try_from(Kind::Key.capacity() + 1).unwrap();
    assert_eq!(with(16, &too_long.to_le_bytes()), Some(EnvError::BadLength));
    assert_eq!(with(20, &[0xFF]), Some(EnvError::SrkName));
    assert_eq!(with(54, &[0, 89]), Some(EnvError::SrkPublic));
    assert_eq!(with(56, &[0, 0x24]), Some(EnvError::SrkPublic));
    assert_eq!(with(146, &[0, 0, 0, 2]), Some(EnvError::PcrSelection));
    assert_eq!(with(156, &[0xFF]), Some(EnvError::Policy));
    assert_eq!(with(190 + 4, &[0, 0, 0x04, 0x40]), Some(EnvError::ObjectPublic));
    assert_eq!(with(268, &[0, 107]), Some(EnvError::Duplicate));
    assert_eq!(with(270, &[0, 31]), Some(EnvError::Duplicate));
    assert_eq!(with(378, &[0, 67]), Some(EnvError::Seed));
    assert_eq!(with(380, &[0, 31]), Some(EnvError::Seed));
    assert_eq!(with(4095, &[1]), Some(EnvError::NonZeroPadding));
}

#[test]
fn the_object_public_carries_the_seal_policy_and_userwithauth_clear() {
    let env = sealed(Kind::Key, &region(Kind::Key, 10), 1);
    let e = Envelope::parse(&env, Kind::Key).unwrap();
    let public = e.object_public();
    let attributes = u32::from_be_bytes(public[4..8].try_into().unwrap());
    assert_eq!(attributes & 0x40, 0, "userWithAuth set");
    assert_eq!(attributes & 0x32, 0, "fixedTPM, fixedParent or sensitiveDataOrigin set");
    assert_eq!(e.object_name(), crypto::name(public));
}

#[test]
fn seal_refuses_a_payload_past_the_capacity_and_a_short_region() {
    let mut out = vec![0u8; Kind::Key.region_size()];
    let e = seal_entropy(1);
    let long = region(Kind::Key, Kind::Key.capacity() + 1);
    assert_eq!(envelope::seal(&mut out, Kind::Key, &long, &srk_public(), &PCR8, &e), Err(EnvError::Seal));
    assert!(out.iter().all(|b| *b == 0));
    let fits = region(Kind::Key, Kind::Key.capacity());
    assert_eq!(envelope::seal(&mut out, Kind::Key, &fits, &srk_public(), &PCR8, &e), Ok(()));
    assert_eq!(envelope::seal(&mut out, Kind::Key, &fits[..100], &srk_public(), &PCR8, &e), Err(EnvError::Seal));
}

#[test]
fn a_key_blob_with_key_max_peers_seals_and_one_more_does_not() {
    let blob = |peers: usize| {
        let mut r = Box::new([0u8; secret_blob::REGION_SIZE]);
        let publics: Vec<[u8; 32]> = (0..peers).map(|i| [i as u8 | 1; 32]).collect();
        secret_blob::write(&mut r, &[1; 32], &[2; 32], &publics).unwrap();
        r
    };
    let mut out = vec![0u8; Kind::Key.region_size()];
    let e = seal_entropy(1);
    assert_eq!(envelope::seal(&mut out, Kind::Key, &blob(KEY_MAX_PEERS)[..], &srk_public(), &PCR8, &e), Ok(()));
    let r = envelope::seal(&mut out, Kind::Key, &blob(KEY_MAX_PEERS + 1)[..], &srk_public(), &PCR8, &e);
    assert_eq!(r, Err(EnvError::Seal));
}

#[test]
fn seal_refuses_an_srk_public_that_is_not_the_template() {
    let mut out = vec![0u8; Kind::Key.region_size()];
    let mut public = srk_public();
    public[7] ^= 0x40; // userWithAuth
    let r = envelope::seal(&mut out, Kind::Key, &region(Kind::Key, 10), &public, &PCR8, &seal_entropy(1));
    assert_eq!(r, Err(EnvError::SrkPublic));
}

/// A TPM that knows the test SRK's private scalar: enough of CreatePrimary,
/// StartAuthSession, Import, Load and Unseal to run the client's whole
/// flow, with knobs for the deny cases. It checks the client's Unseal HMAC
/// against the Name it expects.
struct FakeTpm {
    kek: [u8; 32],
    session_key: [u8; 32],
    nonce_tpm: [u8; 32],
    expected_name: [u8; 34],
    load_name: Option<[u8; 34]>,
    unseal_attributes: u8,
    flip_unseal_hmac: bool,
    flushed: Vec<u32>,
}

const SRK_HANDLE: u32 = 0x8000_0000;
const OBJECT_HANDLE: u32 = 0x8000_0001;
const SESSION_HANDLE: u32 = 0x0300_0000;

fn reply(rc_ok: bool, f: impl FnOnce(&mut Writer<'_>)) -> Vec<u8> {
    let mut buf = [0u8; IPC_MSG_BYTES];
    let mut w = Writer::new(&mut buf);
    w.u16(if rc_ok { 0x8002 } else { 0x8001 }).unwrap();
    w.u32(0).unwrap();
    w.u32(0).unwrap();
    f(&mut w);
    let n = w.finish().unwrap();
    buf[..n].to_vec()
}

fn no_sessions(f: impl FnOnce(&mut Writer<'_>)) -> Vec<u8> {
    reply(false, f)
}

/// parameterSize, the parameters, then a password session's response.
fn with_password(handle: Option<u32>, params: &[u8]) -> Vec<u8> {
    reply(true, |w| {
        if let Some(h) = handle {
            w.u32(h).unwrap();
        }
        w.u32(params.len() as u32).unwrap();
        w.bytes(params).unwrap();
        w.tpm2b(&[]).unwrap();
        w.u8(1).unwrap();
        w.tpm2b(&[]).unwrap();
    })
}

impl FakeTpm {
    fn new(env: &[u8], tag: u8) -> Self {
        FakeTpm {
            kek: kek(tag),
            session_key: [0; 32],
            nonce_tpm: [0x77; 32],
            expected_name: Envelope::parse(env, Kind::Key).unwrap().object_name(),
            load_name: None,
            unseal_attributes: UNSEAL_ATTRIBUTES,
            flip_unseal_hmac: false,
            flushed: Vec::new(),
        }
    }

    fn respond(&mut self, cmd: &[u8]) -> Vec<u8> {
        let cc = u32::from_be_bytes(cmd[6..10].try_into().unwrap());
        match cc {
            0x131 => {
                let public = srk_public();
                let mut p = Vec::new();
                p.extend_from_slice(&(public.len() as u16).to_be_bytes());
                p.extend_from_slice(&public);
                p.extend_from_slice(&[0, 0, 0, 0, 0x80, 0x21, 0x40, 0, 0, 1, 0, 0]);
                p.extend_from_slice(&[0, 34]);
                p.extend_from_slice(&crypto::name(&public));
                with_password(Some(SRK_HANDLE), &p)
            }
            CC_START_AUTH_SESSION => {
                let nonce_caller = &cmd[20..52];
                let point = &cmd[54..54 + 68];
                let qe = crypto::xy(point[2..34].try_into().unwrap(), point[36..68].try_into().unwrap());
                let mut z = Secret::<32>::zero();
                crypto::ecdh(&mut z, &srk_scalar(), &qe).unwrap();
                let srk = srk_public();
                let mut salt = Secret::<32>::zero();
                crypto::kdfe(&mut salt, z.as_bytes(), b"SECRET", &qe[..32], &srk[24..56]);
                crypto::kdfa(salt.as_bytes(), b"ATH", &self.nonce_tpm, nonce_caller, &mut self.session_key).unwrap();
                no_sessions(|w| {
                    w.u32(SESSION_HANDLE).unwrap();
                    w.tpm2b(&self.nonce_tpm).unwrap();
                })
            }
            CC_IMPORT => with_password(None, &[&[0, 4][..], &[1, 2, 3, 4]].concat()),
            CC_LOAD => {
                let name = self.load_name.unwrap_or(self.expected_name);
                with_password(Some(OBJECT_HANDLE), &[&[0, 34][..], &name].concat())
            }
            CC_UNSEAL => self.unseal(cmd),
            CC_FLUSH_CONTEXT => {
                self.flushed.push(u32::from_be_bytes(cmd[10..14].try_into().unwrap()));
                no_sessions(|_| {})
            }
            _ => no_sessions(|_| {}), // PolicyPCR, PolicyAuthValue
        }
    }

    fn unseal(&mut self, cmd: &[u8]) -> Vec<u8> {
        let nonce_caller = &cmd[24..56];
        let attributes = cmd[56];
        let cp_hash = crypto::sha256(&[&CC_UNSEAL.to_be_bytes(), &self.expected_name]);
        let mut hmac = [0u8; 32];
        crypto::hmac(&mut hmac, &self.session_key, &[&cp_hash, nonce_caller, &self.nonce_tpm, &[attributes]]).unwrap();
        assert_eq!(&cmd[59..91], &hmac, "the client's Unseal HMAC");
        let nonce_new = [0x99u8; 32];
        let mut key_iv = [0u8; 32];
        crypto::kdfa(&self.session_key, b"CFB", &nonce_new, nonce_caller, &mut key_iv).unwrap();
        let mut data = self.kek;
        crypto::cfb(key_iv[..16].try_into().unwrap(), key_iv[16..].try_into().unwrap(), &mut data, false);
        let params = [&[0, 32][..], &data].concat();
        let rp_hash = crypto::sha256(&[&0u32.to_be_bytes(), &CC_UNSEAL.to_be_bytes(), &params]);
        let mut rhmac = [0u8; 32];
        let attrs = self.unseal_attributes;
        crypto::hmac(&mut rhmac, &self.session_key, &[&rp_hash, &nonce_new, nonce_caller, &[attrs]]).unwrap();
        if self.flip_unseal_hmac {
            rhmac[31] ^= 1;
        }
        reply(true, |w| {
            w.u32(params.len() as u32).unwrap();
            w.bytes(&params).unwrap();
            w.tpm2b(&nonce_new).unwrap();
            w.u8(attrs).unwrap();
            w.tpm2b(&rhmac).unwrap();
        })
    }
}

fn client_entropy() -> Secret<CLIENT_ENTROPY_LEN> {
    let mut s = Secret::<CLIENT_ENTROPY_LEN>::zero();
    for (i, b) in s.as_mut_bytes().iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(13).wrapping_add(5);
    }
    s
}

/// Runs the client against `tpm`; the steps it sent, and its result.
fn run(env: &[u8], tpm: &mut FakeTpm) -> (Vec<Step>, Result<(), Failure>, Vec<u8>) {
    let mut client = Client::new(env, Kind::Key, &client_entropy()).unwrap();
    let mut buf = [0u8; IPC_MSG_BYTES];
    let mut steps = Vec::new();
    while let Some(n) = client.command(&mut buf) {
        steps.push(client.step());
        client.response(&tpm.respond(&buf[..n]));
    }
    let mut out = vec![0xAAu8; Kind::Key.region_size()];
    let r = client.finish(&mut out);
    (steps, r, out)
}

const FULL_FLOW: [Step; 10] = [
    Step::CreatePrimary,
    Step::StartAuthSession,
    Step::PolicyPcr,
    Step::PolicyAuthValue,
    Step::Import,
    Step::Load,
    Step::Unseal,
    Step::FlushObject,
    Step::FlushSession,
    Step::FlushPrimary,
];

#[test]
fn client_runs_the_whole_flow_and_opens_the_envelope() {
    let plain = region(Kind::Key, 500);
    let env = sealed(Kind::Key, &plain, 3);
    let mut tpm = FakeTpm::new(&env, 3);
    let (steps, r, out) = run(&env, &mut tpm);
    assert_eq!(steps, FULL_FLOW);
    assert_eq!(r, Ok(()));
    assert!(out == plain);
    assert_eq!(tpm.flushed, [OBJECT_HANDLE, SESSION_HANDLE, SRK_HANDLE]);
}

#[test]
fn a_load_with_a_substituted_name_is_refused_before_unseal_and_handles_are_flushed() {
    let env = sealed(Kind::Key, &region(Kind::Key, 500), 3);
    let mut tpm = FakeTpm::new(&env, 3);
    let mut other = tpm.expected_name;
    other[33] ^= 1;
    tpm.load_name = Some(other);
    let (steps, r, out) = run(&env, &mut tpm);
    assert_eq!(r, Err(Failure { step: Step::Load, cause: Cause::LoadName }));
    assert!(!steps.contains(&Step::Unseal));
    assert_eq!(tpm.flushed, [OBJECT_HANDLE, SESSION_HANDLE, SRK_HANDLE]);
    assert!(out.iter().all(|b| *b == 0));
}

#[test]
fn a_forged_unseal_response_hmac_is_refused_and_no_kek_is_used() {
    let env = sealed(Kind::Key, &region(Kind::Key, 500), 3);
    let mut tpm = FakeTpm::new(&env, 3);
    tpm.flip_unseal_hmac = true;
    let (_, r, out) = run(&env, &mut tpm);
    assert_eq!(r, Err(Failure { step: Step::Unseal, cause: Cause::ResponseHmac }));
    assert!(out.iter().all(|b| *b == 0));
}

#[test]
fn an_authenticated_response_without_encrypt_is_refused() {
    let env = sealed(Kind::Key, &region(Kind::Key, 500), 3);
    let mut tpm = FakeTpm::new(&env, 3);
    tpm.unseal_attributes = UNSEAL_ATTRIBUTES & !tpm2_wire::SESSION_ENCRYPT;
    let (_, r, out) = run(&env, &mut tpm);
    assert_eq!(r, Err(Failure { step: Step::Unseal, cause: Cause::ResponseAttributes }));
    assert!(out.iter().all(|b| *b == 0));
}

#[test]
fn an_srk_whose_name_differs_from_the_pinned_one_ends_the_flow_after_its_flush() {
    let mut env = sealed(Kind::Key, &region(Kind::Key, 500), 3);
    let mut tpm = FakeTpm::new(&env, 3);
    // Pin another SRK (any valid point) and re-pin its Name; the fake TPM
    // still answers with the test SRK.
    let other = crypto::public_point(&secret(&range(0x55))).unwrap();
    env[56 + 22..56 + 90].copy_from_slice(&crypto::ecc_point(&other));
    let name = crypto::name(&env[56..146]);
    env[20..54].copy_from_slice(&name);
    let (steps, r, _) = run(&env, &mut tpm);
    assert_eq!(r, Err(Failure { step: Step::CreatePrimary, cause: Cause::SrkName }));
    assert_eq!(steps, [Step::CreatePrimary, Step::FlushPrimary]);
}

#[test]
fn a_tpm_error_mid_flow_flushes_what_the_client_holds() {
    let env = sealed(Kind::Key, &region(Kind::Key, 500), 3);
    let mut client = Client::new(&env, Kind::Key, &client_entropy()).unwrap();
    let mut tpm = FakeTpm::new(&env, 3);
    let mut buf = [0u8; IPC_MSG_BYTES];
    let mut steps = Vec::new();
    while let Some(n) = client.command(&mut buf) {
        steps.push(client.step());
        let rsp = if client.step() == Step::Import {
            vec![0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x8B] // TPM_RC_HANDLE
        } else {
            tpm.respond(&buf[..n])
        };
        client.response(&rsp);
    }
    assert_eq!(
        client.failure(),
        Some(Failure { step: Step::Import, cause: Cause::Response(tpm2_wire::RspError::Tpm(0x18B)) })
    );
    let tail: Vec<Step> = steps[5..].to_vec();
    assert_eq!(tail, [Step::FlushSession, Step::FlushPrimary]);
    assert_eq!(tpm.flushed, [SESSION_HANDLE, SRK_HANDLE]);
    assert!(client.finish(&mut buf).is_err());
}

#[test]
fn a_response_without_a_command_and_an_early_finish_are_order_failures() {
    let env = sealed(Kind::Key, &region(Kind::Key, 500), 3);
    let mut client = Client::new(&env, Kind::Key, &client_entropy()).unwrap();
    client.response(&[0x80, 0x01, 0, 0, 0, 10, 0, 0, 0, 0]);
    assert_eq!(client.failure(), Some(Failure { step: Step::CreatePrimary, cause: Cause::Order }));
    let client = Client::new(&env, Kind::Key, &client_entropy()).unwrap();
    let mut out = vec![0u8; Kind::Key.region_size()];
    assert_eq!(client.finish(&mut out).unwrap_err().cause, Cause::Order);
}

#[test]
fn a_zero_ephemeral_scalar_and_a_malformed_envelope_fail_before_any_command() {
    let env = sealed(Kind::Key, &region(Kind::Key, 500), 3);
    let zero = Secret::<CLIENT_ENTROPY_LEN>::zero();
    assert_eq!(Client::new(&env, Kind::Key, &zero).err().map(|f| f.cause), Some(Cause::Entropy));
    let mut bad = env.clone();
    bad[0] = b'X';
    assert_eq!(
        Client::new(&bad, Kind::Key, &client_entropy()).err().map(|f| f.cause),
        Some(Cause::Envelope(EnvError::BadMagic))
    );
}

#[test]
fn every_command_of_the_flow_fits_one_ipc_message() {
    let env = sealed(Kind::Key, &region(Kind::Key, 500), 3);
    let mut client = Client::new(&env, Kind::Key, &client_entropy()).unwrap();
    let mut tpm = FakeTpm::new(&env, 3);
    let mut buf = [0u8; IPC_MSG_BYTES];
    while let Some(n) = client.command(&mut buf) {
        assert!(n <= tpm2_wire::MAX_COMMAND);
        let rsp = tpm.respond(&buf[..n]);
        assert!(rsp.len() <= tpm2_wire::MAX_RESPONSE);
        client.response(&rsp);
    }
}

// --- boot: the unseal over PPC to `tpm` (C9) -------------------------------

use layout::tpm as ipc;
use tpm2_wire::gate::{Gate, State};

use super::boot::{self, BUSY_PAUSE_NS, BUSY_TIMEOUT_NS, Transport, UnsealError};

/// `tpm` as the PD runs it: the gate in front of the fake TPM, with knobs
/// for the transport's failures.
struct FakePpc {
    tpm: FakeTpm,
    gate: Gate,
    /// (request kind, length) of every call.
    calls: Vec<(u64, usize)>,
    /// Busy replies before the gate sees a command.
    busy: usize,
    clock: u64,
    random_ok: bool,
    /// The command code the device fails on.
    device_error_at: Option<u32>,
    /// Unseal answered with this response code.
    unseal_rc: Option<u32>,
    /// Replaces the reply to Done or Failed.
    finish_reply: Option<u64>,
    /// The reply words carry 8 bytes fewer than the label's length.
    short_words: bool,
}

impl FakePpc {
    fn new(env: &[u8]) -> Self {
        FakePpc {
            tpm: FakeTpm::new(env, 3),
            gate: Gate::new(),
            calls: Vec::new(),
            busy: 0,
            clock: 0,
            random_ok: true,
            device_error_at: None,
            unseal_rc: None,
            finish_reply: None,
            short_words: false,
        }
    }

    fn commands(&self) -> usize {
        self.calls.iter().filter(|(k, _)| *k == ipc::REQ_COMMAND).count()
    }

    fn last(&self) -> u64 {
        self.calls.last().unwrap().0
    }
}

impl Transport for FakePpc {
    fn call(&mut self, label: u64, req: &[u8], rsp: &mut [u8; ipc::MSG_BYTES]) -> (u64, usize) {
        self.calls.push((ipc::kind(label), ipc::arg(label)));
        match ipc::kind(label) {
            ipc::REQ_COMMAND => {
                assert_eq!(ipc::arg(label), req.len(), "the label carries the command's length");
                if self.busy > 0 {
                    self.busy -= 1;
                    return (ipc::label(ipc::RSP_BUSY, 0), 0);
                }
                let fwd = match self.gate.command(0, req) {
                    Ok(fwd) => fwd,
                    Err(r) => return (ipc::label(ipc::RSP_REFUSED, r as usize), 0),
                };
                let cc = fwd.command_code();
                if self.device_error_at == Some(cc) {
                    return (ipc::label(ipc::RSP_DEVICE, 1), 0);
                }
                let r = match self.unseal_rc {
                    Some(rc) if cc == CC_UNSEAL => {
                        let mut r = vec![0x80, 0x01, 0, 0, 0, 10];
                        r.extend_from_slice(&rc.to_be_bytes());
                        r
                    }
                    _ => self.tpm.respond(req),
                };
                self.gate.response(fwd, &r);
                rsp[..r.len()].copy_from_slice(&r);
                let carried = if self.short_words { r.len() - 8 } else { ipc::words(r.len()) * 8 };
                (ipc::label(ipc::RSP_OK, r.len()), carried)
            }
            kind => {
                assert!(kind == ipc::REQ_DONE || kind == ipc::REQ_FAILED, "unknown request {kind}");
                assert!(req.is_empty());
                let ok = self.gate.finish(0, kind == ipc::REQ_DONE).is_ok();
                let reply = if ok { ipc::label(ipc::RSP_OK, 0) } else { ipc::label(ipc::RSP_REFUSED, 1) };
                (self.finish_reply.unwrap_or(reply), 0)
            }
        }
    }

    fn now_ns(&mut self) -> u64 {
        self.clock += 1_000_000;
        self.clock
    }

    fn random(&mut self, out: &mut [u8]) -> bool {
        out.copy_from_slice(&client_entropy().as_bytes()[..out.len()]);
        self.random_ok
    }
}

fn boot_unseal(env: &[u8], ppc: &mut FakePpc) -> (Result<(), UnsealError>, Vec<u8>) {
    let mut out = vec![0xAAu8; Kind::Key.region_size()];
    let r = boot::unseal(ppc, env, Kind::Key, &mut out);
    (r, out)
}

#[test]
fn boot_unseals_through_the_gate_and_sends_done() {
    let plain = region(Kind::Key, 500);
    let env = sealed(Kind::Key, &plain, 3);
    let mut ppc = FakePpc::new(&env);
    let (r, out) = boot_unseal(&env, &mut ppc);
    assert_eq!(r, Ok(()));
    assert!(out == plain);
    assert_eq!(ppc.commands(), FULL_FLOW.len());
    assert_eq!(ppc.last(), ipc::REQ_DONE);
    assert_eq!(ppc.gate.state(0), Some(State::Done));
    assert_eq!(ppc.tpm.flushed, [OBJECT_HANDLE, SESSION_HANDLE, SRK_HANDLE]);
}

#[test]
fn a_busy_tpm_is_asked_again_after_a_pause() {
    let plain = region(Kind::Key, 500);
    let env = sealed(Kind::Key, &plain, 3);
    let mut ppc = FakePpc::new(&env);
    ppc.busy = 3;
    let (r, out) = boot_unseal(&env, &mut ppc);
    assert_eq!(r, Ok(()));
    assert!(out == plain);
    assert_eq!(ppc.commands(), FULL_FLOW.len() + 3);
    assert!(ppc.clock >= 3 * BUSY_PAUSE_NS, "asked again without pausing: {} ns", ppc.clock);
}

#[test]
fn a_tpm_busy_past_the_timeout_leaves_tpm_unavailable_and_sends_failed() {
    let env = sealed(Kind::Key, &region(Kind::Key, 500), 3);
    let mut ppc = FakePpc::new(&env);
    ppc.busy = usize::MAX;
    let (r, out) = boot_unseal(&env, &mut ppc);
    assert_eq!(r, Err(UnsealError::TpmUnavailable));
    assert!(out.iter().all(|b| *b == 0));
    assert_eq!(ppc.last(), ipc::REQ_FAILED);
    assert!(ppc.clock >= BUSY_TIMEOUT_NS);
}

#[test]
fn a_device_error_mid_flow_is_tpm_unavailable_after_the_flushes() {
    let env = sealed(Kind::Key, &region(Kind::Key, 500), 3);
    let mut ppc = FakePpc::new(&env);
    ppc.device_error_at = Some(CC_LOAD);
    let (r, out) = boot_unseal(&env, &mut ppc);
    assert_eq!(r, Err(UnsealError::TpmUnavailable));
    assert!(out.iter().all(|b| *b == 0));
    assert_eq!(ppc.tpm.flushed, [SESSION_HANDLE, SRK_HANDLE]);
    assert_eq!(ppc.last(), ipc::REQ_FAILED);
    assert_eq!(ppc.gate.state(0), Some(State::Failed));
}

#[test]
fn an_unseal_the_tpm_refuses_is_unseal_refused() {
    let env = sealed(Kind::Key, &region(Kind::Key, 500), 3);
    let mut ppc = FakePpc::new(&env);
    ppc.unseal_rc = Some(0x99D); // TPM_RC_POLICY_FAIL: PCR 8 is another value
    let (r, out) = boot_unseal(&env, &mut ppc);
    assert_eq!(r, Err(UnsealError::UnsealRefused));
    assert!(out.iter().all(|b| *b == 0));
    assert_eq!(ppc.last(), ipc::REQ_FAILED);
}

#[test]
fn a_forged_unseal_response_is_response_invalid() {
    let env = sealed(Kind::Key, &region(Kind::Key, 500), 3);
    let mut ppc = FakePpc::new(&env);
    ppc.tpm.flip_unseal_hmac = true;
    let (r, out) = boot_unseal(&env, &mut ppc);
    assert_eq!(r, Err(UnsealError::ResponseInvalid));
    assert!(out.iter().all(|b| *b == 0));
}

#[test]
fn another_tpms_srk_is_srk_mismatch() {
    let mut env = sealed(Kind::Key, &region(Kind::Key, 500), 3);
    let mut ppc = FakePpc::new(&env);
    let other = crypto::public_point(&secret(&range(0x55))).unwrap();
    env[56 + 22..56 + 90].copy_from_slice(&crypto::ecc_point(&other));
    let name = crypto::name(&env[56..146]);
    env[20..54].copy_from_slice(&name);
    let (r, _) = boot_unseal(&env, &mut ppc);
    assert_eq!(r, Err(UnsealError::SrkMismatch));
    assert_eq!(ppc.last(), ipc::REQ_FAILED);
}

#[test]
fn a_plaintext_blob_is_envelope_invalid_and_reaches_no_tpm_command() {
    let mut blob = Box::new([0u8; secret_blob::REGION_SIZE]);
    secret_blob::write(&mut blob, &[1; 32], &[2; 32], &[[3; 32]]).unwrap();
    let env = sealed(Kind::Key, &region(Kind::Key, 500), 3);
    let mut ppc = FakePpc::new(&env);
    let (r, out) = boot_unseal(&blob[..], &mut ppc);
    assert_eq!(r, Err(UnsealError::EnvelopeInvalid));
    assert!(out.iter().all(|b| *b == 0));
    assert_eq!(ppc.commands(), 0);
    assert_eq!(ppc.calls, [(ipc::REQ_FAILED, 0)]);
}

#[test]
fn a_failed_random_source_is_rndr() {
    let env = sealed(Kind::Key, &region(Kind::Key, 500), 3);
    let mut ppc = FakePpc::new(&env);
    ppc.random_ok = false;
    let (r, _) = boot_unseal(&env, &mut ppc);
    assert_eq!(r, Err(UnsealError::Rndr));
    assert_eq!(ppc.calls, [(ipc::REQ_FAILED, 0)]);
}

#[test]
fn a_done_tpm_does_not_acknowledge_leaves_no_plaintext() {
    let env = sealed(Kind::Key, &region(Kind::Key, 500), 3);
    let mut ppc = FakePpc::new(&env);
    ppc.finish_reply = Some(ipc::label(ipc::RSP_REFUSED, 2));
    let (r, out) = boot_unseal(&env, &mut ppc);
    assert_eq!(r, Err(UnsealError::TpmUnavailable));
    assert!(out.iter().all(|b| *b == 0));
}

#[test]
fn a_response_longer_than_its_reply_words_is_refused() {
    let env = sealed(Kind::Key, &region(Kind::Key, 500), 3);
    let mut ppc = FakePpc::new(&env);
    ppc.short_words = true;
    let (r, out) = boot_unseal(&env, &mut ppc);
    assert_eq!(r, Err(UnsealError::TpmUnavailable));
    assert!(out.iter().all(|b| *b == 0));
}

#[test]
fn open_sealed_wipes_the_kek_on_success_and_on_failure() {
    let plain = region(Kind::Key, 100);
    let env = sealed(Kind::Key, &plain, 1);
    let e = Envelope::parse(&env, Kind::Key).unwrap();
    for (tag, want) in [(1, Ok(())), (2, Err(EnvError::Auth))] {
        let mut k = secret::<32>(&kek(tag));
        let mut out = vec![0xAAu8; Kind::Key.region_size()];
        assert_eq!(envelope::open_sealed(&e, &mut k, &mut out), want);
        assert!(k.as_bytes().iter().all(|b| *b == 0), "KEK {tag} not wiped");
        assert_eq!(out == plain, want.is_ok());
    }
}
