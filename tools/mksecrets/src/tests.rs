#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use tpm2::envelope::Kind;
use std::os::unix::fs::PermissionsExt;

const TEMPLATE: &str = include_str!("../../../config/gateway.toml");

#[test]
fn encode_key_round_trips_through_the_config_decoder() {
    for seed in [[0u8; 32], [0xff; 32], core::array::from_fn(|i| i as u8)] {
        assert_eq!(validate::decode_key(&encode_key(&seed)), Ok(seed));
    }
}

#[test]
fn encode_key_matches_a_known_wireguard_key() {
    let k = validate::decode_key("YBS8Ds6hLNV9RKN63rn+Z7o/7hO6Iwmh1xhxEHInuGg=").unwrap_or([0; 32]);
    assert_eq!(encode_key(&k), "YBS8Ds6hLNV9RKN63rn+Z7o/7hO6Iwmh1xhxEHInuGg=");
}

fn unbase64(s: &str) -> Vec<u8> {
    let mut bits: u32 = 0;
    let mut n = 0;
    let mut out = Vec::new();
    for c in s.bytes().filter(|c| *c != b'=' && *c != b'\n') {
        bits = (bits << 6) | ALPHABET.iter().position(|a| *a == c).expect("base64") as u32;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    out
}

/// The DER inside a PEM SubjectPublicKeyInfo.
fn pem_der(pem: &str) -> Vec<u8> {
    let body = pem.strip_prefix("-----BEGIN PUBLIC KEY-----\n").and_then(|b| b.strip_suffix("-----END PUBLIC KEY-----\n"));
    unbase64(body.expect("PEM framing"))
}

/// One request to the stand-in issuer: (tls.pub, name, negative).
type Request = (String, String, bool);
type Asked = std::sync::Mutex<Vec<Request>>;
type Files = Vec<(String, Vec<u8>)>;

/// mkcert's stand-in: a "certificate" that is the SPKI between two bytes,
/// which is all config's check reads, and a CA file.
fn fake_issue(asked: &Asked) -> impl Fn(&str, &str, bool) -> Result<Files, String> + '_ {
    move |pem: &str, name: &str, negative: bool| {
        asked.lock().unwrap().push((pem.to_string(), name.to_string(), negative));
        let cert = [&[0x30u8][..], &pem_der(pem), &[0x00]].concat();
        Ok(vec![("devca.pem".to_string(), b"ca".to_vec()), ("tls.der".to_string(), cert)])
    }
}

fn generated(peers: usize, endpoint: &str, tls_name: Option<&str>, mismatch_blob: bool) -> Result<(Deployment, Vec<Request>), String> {
    let asked = Asked::default();
    let d = {
        let issue = fake_issue(&asked);
        let tls = TlsOptions { name: tls_name, negative: false, mismatch_blob, issue: &issue };
        generate(TEMPLATE, peers, endpoint, None, &tls)?
    };
    Ok((d, asked.into_inner().unwrap()))
}

/// One two-peer deployment shared (read-only) by the tests that inspect a
/// deployment: McEliece keygen dominates their run time in debug builds.
/// It has the TLS-mismatch blob.
fn deployment() -> &'static (Deployment, Vec<Request>) {
    static D: std::sync::OnceLock<(Deployment, Vec<Request>)> = std::sync::OnceLock::new();
    D.get_or_init(|| generated(2, "192.0.2.7:51820", None, true).unwrap_or_else(|e| panic!("{e}")))
}

/// The deployment's key files, served the way build.rs reads them.
fn loader(d: &Deployment) -> impl Fn(&str) -> Result<Vec<u8>, String> + '_ {
    move |name: &str| {
        if name == GATEWAY_RP_PUBLIC {
            return Ok(d.gateway_rp_public.to_vec());
        }
        if let Some((_, c)) = d.certs.iter().find(|(n, _)| n == name) {
            return Ok(c.clone());
        }
        (0..d.peers.len())
            .find(|i| peer_rp_public(*i) == name)
            .map(|i| d.peers[i].rp_public.to_vec())
            .ok_or_else(|| format!("{name}: not in the deployment"))
    }
}

fn checked(d: &Deployment) -> validate::Checked {
    validate::check(&d.config, validate::MAX_PEERS, &loader(d)).unwrap_or_else(|e| panic!("{e}"))
}

fn decapsulate(sk: &[u8; pq::SK_LEN], ct: &[u8; pq::CT_LEN]) -> [u8; 32] {
    let mut shk = [0u8; 32];
    mce460896::decaps(sk, ct, &mut shk);
    shk
}

#[test]
fn generated_blob_matches_generated_config() {
    let d = &deployment().0;
    let checked = checked(d);
    let blob = secret_blob::Blob::parse(&d.blob[..], 2).unwrap_or_else(|e| panic!("{}", e.message()));

    let mut public = [0u8; 32];
    libcrux_curve25519::secret_to_public(&mut public, blob.gateway_private());
    assert_eq!(public, checked.gateway_public);
    for (i, peer) in checked.peers.iter().enumerate() {
        let hash = blob.peer(i).unwrap_or_else(|| panic!("peer {i} missing"));
        assert_eq!(*hash, secret_blob::blake2s(&[&peer.public]));
    }
}

#[test]
fn pqkey_blob_binds_the_configured_gateway_key_and_its_kat_decapsulates() {
    let d = &deployment().0;
    let checked = checked(d);
    let blob = pq::Blob::parse(&d.pq_blob[..]).unwrap_or_else(|e| panic!("{}", e.message()));
    assert_eq!(*blob.spkm_hash(), checked.gateway_rp.hash);
    assert_eq!(checked.gateway_rp.hash, secret_blob::blake2s(&[&d.gateway_rp_public[..]]));
    // The KAT was encapsulated to the configured key and the stored secret
    // key survived keygen (mce460896 writes into caller buffers and zeroes
    // nothing on its own; the copy mksecrets keeps is the only one taken).
    assert!(blob.secret_key().iter().any(|b| *b != 0));
    let shk = decapsulate(blob.secret_key(), blob.kat_ct());
    assert_eq!(secret_blob::blake2s(&[&shk]), *blob.kat_shk_hash());
    assert_ne!(blob.blob_seed(), secret_blob::Blob::parse(&d.blob[..], 2).map(|b| *b.boot_seed()).unwrap_or_default().as_slice());
}

#[test]
fn client_mceliece_key_is_exported_in_the_liboqs_layout() {
    let d = &deployment().0;
    let checked = checked(d);
    let mut rng = Urandom::open().unwrap();
    for (bundle, peer) in d.peers.iter().zip(&checked.peers) {
        assert_eq!(peer.rp.hash, secret_blob::blake2s(&[&bundle.rp_public[..]]));
        let mut ct = [0u8; pq::CT_LEN];
        let mut shared = [0u8; 32];
        mce460896::encaps(&bundle.rp_public, &mut |out| rng.fill(out), &mut ct, &mut shared).unwrap();
        let mut sk = Box::new([0u8; pq::SK_LEN]);
        pq::cmr_sk_from_liboqs(&mut sk, &bundle.rp_secret);
        assert_eq!(decapsulate(&sk, &ct), shared);
    }
}

#[test]
fn peer_config_has_no_preshared_key_and_names_the_gateway() {
    let d = &deployment().0;
    let checked = checked(d);
    let conf = &d.peers[0].wg_conf;
    assert!(!conf.contains("PresharedKey ="), "{conf}");
    assert!(conf.contains(&format!("PublicKey = {}\n", encode_key(&checked.gateway_public))));
    assert!(conf.contains("Endpoint = 192.0.2.7:51820\n"));
}

#[test]
fn rosenpass_config_names_the_bundle_files_and_the_rp_port() {
    let d = &deployment().0;
    let t: toml::Table = toml::from_str(&d.peers[1].rp_toml).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(t["public_key"].as_str(), Some("peer-1.rp.pk"));
    assert_eq!(t["secret_key"].as_str(), Some("peer-1.rp.sk"));
    let peer = &t["peers"].as_array().unwrap()[0];
    assert_eq!(peer["public_key"].as_str(), Some(GATEWAY_RP_PUBLIC));
    assert_eq!(peer["endpoint"].as_str(), Some("192.0.2.7:51819"));
    assert_eq!(peer["key_out"].as_str(), Some("peer-1.osk"));
    assert_eq!(peer["protocol_version"].as_str(), Some("V02"));
}

#[test]
fn rosenpass_endpoint_defaults_to_the_wireguard_host_and_can_be_overridden() {
    assert_eq!(rosenpass_endpoint("[::1]:51820", None, 51819), Ok("[::1]:51819".into()));
    assert_eq!(rosenpass_endpoint("x:1", Some("y:2"), 51819), Ok("y:2".into()));
    assert!(rosenpass_endpoint("no-port", None, 51819).is_err());
}

#[test]
fn two_runs_produce_different_keys() {
    let (a, _) = generated(1, "x:1", None, false).unwrap_or_else(|e| panic!("{e}"));
    let (b, _) = generated(1, "x:1", None, false).unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(a.blob[..], b.blob[..]);
    assert_ne!(a.tls_pub_pem, b.tls_pub_pem);
    assert_ne!(a.pq_blob[..], b.pq_blob[..]);
    assert_ne!(a.peers[0].rp_secret[..], b.peers[0].rp_secret[..]);
}

#[test]
fn rejects_peer_counts_outside_the_deployable_range() {
    assert!(generated(0, "x:1", None, false).is_err());
    let e = generated(validate::MAX_PEERS + 1, "x:1", None, false).err().unwrap_or_default();
    assert!(e.contains("--peers must be 1..=8"), "{e}");
}

// Upstream interop (M3 plan C6/T11): a committed `rp genkey` output from
// rosenpass 9e72f1eb and a liboqs 0.8.0 encapsulation to its public key
// (provenance in crates/pqkey-core/src/tests.rs).
const RP_GENKEY_SK: &[u8; pq::LIBOQS_SK_LEN] = include_bytes!("../../../crates/pqkey-core/testdata/rp-genkey-a.pqsk");
const LIBOQS_CT: &[u8; pq::CT_LEN] = include_bytes!("../../../crates/pqkey-core/testdata/liboqs-a.ct");
const LIBOQS_SHK: &[u8; 32] = include_bytes!("../../../crates/pqkey-core/testdata/liboqs-a.shk");

#[test]
fn imported_rp_genkey_secret_decapsulates_a_liboqs_ciphertext() {
    let mut sk = Box::new([0u8; pq::SK_LEN]);
    pq::cmr_sk_from_liboqs(&mut sk, RP_GENKEY_SK);
    assert_eq!(decapsulate(&sk, LIBOQS_CT), *LIBOQS_SHK);
    // And back: the export reproduces upstream's file byte for byte.
    let mut oqs = Box::new([0u8; pq::LIBOQS_SK_LEN]);
    pq::liboqs_sk_from_cmr(&mut oqs, &sk);
    assert_eq!(&oqs[..], &RP_GENKEY_SK[..]);
}

#[test]
fn imported_rp_genkey_secret_with_swapped_halves_does_not_decapsulate() {
    // The conversion done the wrong way round: liboqs's leading 576 bytes
    // left in front. Implicit rejection gives a different key, not an error.
    let mut sk = Box::new([0u8; pq::SK_LEN]);
    sk[40..40 + 576].copy_from_slice(&RP_GENKEY_SK[..576]);
    sk[40 + 576..].copy_from_slice(&RP_GENKEY_SK[576..]);
    assert_ne!(decapsulate(&sk, LIBOQS_CT), *LIBOQS_SHK);
}

/// A per-test scratch directory removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let d = std::env::temp_dir().join(format!("mksecrets-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Scratch(d.canonicalize().unwrap())
    }

    fn dir(&self, sub: &str) -> PathBuf {
        let d = self.0.join(sub);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn out_dir_inside_a_forbidden_root_is_refused() {
    let s = Scratch::new("inside");
    let root = s.dir("forbidden");
    let e = check_out_dir(&root.join("secrets"), std::slice::from_ref(&root)).unwrap_err();
    assert!(e.contains("is inside"), "{e}");
}

#[test]
fn out_dir_reached_through_a_symlink_into_a_forbidden_root_is_refused() {
    let s = Scratch::new("symlink");
    let root = s.dir("forbidden");
    let link = s.dir("outside").join("link");
    std::os::unix::fs::symlink(&root, &link).unwrap();
    let e = check_out_dir(&link.join("secrets"), std::slice::from_ref(&root)).unwrap_err();
    assert!(e.contains("is inside"), "{e}");
}

#[test]
fn out_dir_outside_forbidden_roots_is_accepted() {
    let s = Scratch::new("ok");
    let root = s.dir("forbidden");
    assert!(check_out_dir(&s.0.join("ok"), &[root]).is_ok());
}

#[test]
fn the_repository_is_a_forbidden_root() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    assert!(forbidden_roots().unwrap().contains(&repo));
}

#[test]
fn run_writes_the_three_blobs_the_key_files_and_one_bundle_per_peer() {
    let s = Scratch::new("run");
    let out = s.0.join("deploy");
    let template = format!("{}/../../config/gateway.toml", env!("CARGO_MANIFEST_DIR"));
    let args: Vec<String> = [
        "--template",
        &template,
        "--peers",
        "1",
        "--out",
        out.to_str().unwrap(),
        "--test-negative",
        "--tls-mismatch-blob",
    ]
    .iter()
    .map(|a| a.to_string())
    .collect();
    run(&args).unwrap_or_else(|e| panic!("{e}"));
    let mut names: Vec<String> =
        std::fs::read_dir(&out).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    let want = [
        "devca.pem",
        "gateway.rp.pk",
        "gateway.toml",
        "negative-form.der",
        "negative-name.der",
        "peer-0.conf",
        "peer-0.rosenpass.toml",
        "peer-0.rp.pk",
        "peer-0.rp.sk",
        "pqkey-secrets.bin",
        "secrets.bin",
        "tls-secrets-mismatch.bin",
        "tls-secrets.bin",
        "tls.der",
        "tls.pub",
    ];
    assert_eq!(names, want);
    let size = |n: &str| std::fs::metadata(out.join(n)).unwrap().len() as usize;
    assert_eq!(size("pqkey-secrets.bin"), pq::REGION_SIZE);
    assert_eq!(size("secrets.bin"), secret_blob::REGION_SIZE);
    assert_eq!(size("tls-secrets.bin"), secret_blob::tls::REGION_SIZE);
    assert_eq!(size("tls-secrets-mismatch.bin"), secret_blob::tls::REGION_SIZE);
    assert_eq!(size("peer-0.rp.pk"), pq::PK_LEN);
    assert_eq!(size("peer-0.rp.sk"), pq::LIBOQS_SK_LEN);
    // The written config builds against the written key files.
    let text = std::fs::read_to_string(out.join("gateway.toml")).unwrap();
    let load = |name: &str| std::fs::read(out.join(name)).map_err(|e| e.to_string());
    assert!(validate::check(&text, validate::MAX_PEERS, &load).is_ok());
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("mksecrets-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir(&d).unwrap();
    d
}

fn leftovers(parent: &Path) -> Vec<String> {
    std::fs::read_dir(parent).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect()
}

#[test]
fn staged_output_is_published_owner_only() {
    let parent = scratch("ok");
    let out = parent.join("deploy");
    stage_and_publish(&out, |s| write_private(&s.join("secrets.bin"), b"k")).unwrap();
    assert_eq!(leftovers(&parent), ["deploy"], "only the published directory remains");
    assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(std::fs::read(out.join("secrets.bin")).unwrap(), b"k");
    std::fs::remove_dir_all(&parent).unwrap();
}

#[test]
fn a_failed_write_publishes_nothing_and_leaves_no_staging() {
    let parent = scratch("fail");
    let out = parent.join("deploy");
    let r = stage_and_publish(&out, |s| {
        write_private(&s.join("secrets.bin"), b"k")?;
        Err("disk full".into())
    });
    assert_eq!(r, Err("disk full".into()));
    assert!(leftovers(&parent).is_empty(), "left behind: {:?}", leftovers(&parent));
    std::fs::remove_dir_all(&parent).unwrap();
}

#[test]
fn an_output_that_appeared_is_never_replaced() {
    let parent = scratch("exists");
    let out = parent.join("deploy");
    std::fs::create_dir(&out).unwrap();
    let r = stage_and_publish(&out, |s| write_private(&s.join("secrets.bin"), b"k"));
    assert!(r.is_err_and(|e| e.starts_with("cannot publish")), "an existing (even empty) output must refuse");
    assert_eq!(leftovers(&parent), ["deploy"], "no staging left beside it");
    assert!(leftovers(&out).is_empty(), "the existing output was not touched");
    std::fs::remove_dir_all(&parent).unwrap();
}

#[test]
fn the_signal_mask_is_restored_after_staging() {
    let parent = scratch("mask");
    // SAFETY: queries the current mask into a zeroed set.
    let mask = || unsafe {
        let mut m: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut m);
        libc::sigismember(&m, libc::SIGTERM)
    };
    let before = mask();
    let r = stage_and_publish(&parent.join("x"), |_| Err("no".into()));
    assert!(r.is_err());
    assert_eq!(mask(), before, "SIGTERM left blocked after a failed staging");
    std::fs::remove_dir_all(&parent).unwrap();
}

#[test]
fn a_staging_directory_that_already_exists_is_left_untouched() {
    let parent = scratch("taken");
    let staging = parent.join(".deploy.mksecrets-taken");
    std::fs::create_dir(&staging).unwrap();
    std::fs::write(staging.join("theirs"), b"x").unwrap();
    let r = stage_and_publish_at(&parent.join("deploy"), &staging, |s| write_private(&s.join("secrets.bin"), b"k"));
    assert!(r.is_err(), "a taken staging name must refuse");
    assert_eq!(leftovers(&staging), ["theirs"], "someone else's staging directory was modified");
    assert_eq!(leftovers(&parent), [".deploy.mksecrets-taken"], "nothing was published");
    std::fs::remove_dir_all(&parent).unwrap();
}

/// A TPM2B_PUBLIC of the SRK template with a valid P-256 point, as
/// `tpm2_readpublic -o` writes it.
fn srk_tpm2b() -> Vec<u8> {
    let mut scalar = Secret::<32>::zero();
    scalar.as_mut_bytes().copy_from_slice(&[0x21; 32]);
    let point = tpm2::crypto::public_point(&scalar).unwrap();
    let mut public = tpm2_wire::SRK_PUBLIC_PREFIX.to_vec();
    public.extend_from_slice(&tpm2::crypto::ecc_point(&point));
    let mut out = (public.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&public);
    out
}

/// PCRs 0-8 as `tools/package` writes them: PCR 0 TF-A's, 1-7 untouched,
/// 8 U-Boot's (with the trailing newline the file has).
const PCRS_HEX: &str = "3d4b8c2a9e1f0067a5c3b2d1e0f9a8b7c6d5e4f30112233445566778899aabbc,\
0000000000000000000000000000000000000000000000000000000000000000,\
0000000000000000000000000000000000000000000000000000000000000000,\
0000000000000000000000000000000000000000000000000000000000000000,\
0000000000000000000000000000000000000000000000000000000000000000,\
0000000000000000000000000000000000000000000000000000000000000000,\
0000000000000000000000000000000000000000000000000000000000000000,\
0000000000000000000000000000000000000000000000000000000000000000,\
f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b\n";

/// The blobs of the shared deployment (`key`'s, `pqkey`'s, `tlskey`'s),
/// written where `seal` reads them, and the SRK file.
fn blob_files(s: &Scratch) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let d = &deployment().0;
    let dir = s.dir("in");
    let (key, pqb, tls, srk) =
        (dir.join("secrets.bin"), dir.join("pqkey-secrets.bin"), dir.join("tls-secrets.bin"), dir.join("srk.pub"));
    std::fs::write(&key, &d.blob[..]).unwrap();
    std::fs::write(&pqb, &d.pq_blob[..]).unwrap();
    std::fs::write(&tls, &d.tls_blob[..]).unwrap();
    std::fs::write(&srk, srk_tpm2b()).unwrap();
    (key, pqb, tls, srk)
}

#[test]
fn seal_writes_envelopes_that_parse_for_their_kind() {
    let s = Scratch::new("seal");
    let (key, pqb, tls, srk) = blob_files(&s);
    for (kind, name, blob) in [("key", "secrets.env", &key), ("pq", "pq_secrets.env", &pqb), ("tls", "tls_secrets.env", &tls)] {
        let out = s.0.join(name);
        let args: Vec<String> = [
            "--kind", kind, "--blob", blob.to_str().unwrap(), "--srk-public", srk.to_str().unwrap(),
            "--pcrs", PCRS_HEX, "--out", out.to_str().unwrap(),
        ]
        .iter()
        .map(|a| a.to_string())
        .collect();
        run_seal(&args).unwrap_or_else(|e| panic!("{e}"));
        let bytes = std::fs::read(&out).unwrap();
        let kind = parse_kind(kind).unwrap();
        let env = tpm2::envelope::Envelope::parse(&bytes, kind).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(env.object_policy(), &tpm2::crypto::policy_digest(&pcrs(PCRS_HEX).unwrap()));
        assert_eq!(env.srk_public(), &srk_tpm2b()[2..]);
        // The output is never replaced.
        assert!(run_seal(&args).is_err());
    }
}

/// S13 / T13: the KEK is fresh per envelope, so sealing one blob twice
/// gives two ciphertexts.
#[test]
fn two_seals_of_one_blob_give_different_ciphertexts() {
    let s = Scratch::new("seal-twice");
    let (key, _, _, _) = blob_files(&s);
    let srk = srk_tpm2b();
    let pcr = pcrs(PCRS_HEX).unwrap();
    // The encrypted body without its tag: the tag covers the header, which
    // differs between seals whatever the KEK.
    let body = |e: &[u8]| {
        let ct = tpm2::envelope::Envelope::parse(e, Kind::Key).unwrap().ciphertext().to_vec();
        ct[..ct.len() - 16].to_vec()
    };
    let first = seal_file(Kind::Key, &key, srk_public(&srk).unwrap(), &pcr).unwrap();
    let second = seal_file(Kind::Key, &key, srk_public(&srk).unwrap(), &pcr).unwrap();
    assert!(body(&first) != body(&second), "seal: identical ciphertexts from two seals of one blob (the KEK is not fresh)");
}

#[test]
fn seal_refuses_a_blob_of_the_other_kind_bad_pcrs_and_a_bad_srk_file() {
    let s = Scratch::new("seal-refuse");
    let (key, pqb, tls, _) = blob_files(&s);
    let srk = srk_tpm2b();
    let pcr = pcrs(PCRS_HEX).unwrap();
    let e = seal_file(Kind::Key, &pqb, srk_public(&srk).unwrap(), &pcr).unwrap_err();
    assert!(e.contains("a Key blob is 4096"), "{e}");
    // The key and TLS blobs are both 4096 bytes: the magic keeps them apart.
    let e = seal_file(Kind::Key, &tls, srk_public(&srk).unwrap(), &pcr).unwrap_err();
    assert!(e.contains("bad magic"), "{e}");
    let e = seal_file(Kind::Tls, &key, srk_public(&srk).unwrap(), &pcr).unwrap_err();
    assert!(e.contains("bad magic"), "{e}");
    let mut corrupt = deployment().0.blob.to_vec();
    corrupt[100] ^= 1;
    let bad = s.dir("bad").join("secrets.bin");
    std::fs::write(&bad, &corrupt).unwrap();
    let e = seal_file(Kind::Key, &bad, srk_public(&srk).unwrap(), &pcr).unwrap_err();
    assert!(e.contains("checksum mismatch"), "{e}");
    assert!(pcrs("f5a5").is_err());
    let zeros = |n: usize| vec!["00".repeat(32); n].join(",");
    assert!(pcrs(&zeros(9).replacen("00", "zz", 1)).is_err());
    // Exactly PCRs 0-8: one value short or one too many is refused, nine pass.
    assert!(pcrs(&zeros(8)).is_err());
    assert!(pcrs(&zeros(10)).is_err());
    assert!(pcrs(&zeros(9)).is_ok());
    assert!(srk_public(&srk[..50]).is_err());
    let mut other = srk.clone();
    other[9] ^= 0x40; // userWithAuth off: not the template
    let e = seal_file(Kind::Key, &key, srk_public(&other).unwrap(), &pcr).unwrap_err();
    assert!(e.contains("SrkPublic"), "{e}");
}

/// C12: the release verifier's envelope check. Allow: sealed to the
/// manifest's PCRs 0-8. Deny: another PCR 0 or 8, the other kind, a header
/// policy that differs from the object public's.
#[test]
fn check_envelope_accepts_its_own_pcrs_only() {
    let s = Scratch::new("check-envelope");
    let (key, _, tls, _) = blob_files(&s);
    let srk = srk_tpm2b();
    let pcr = pcrs(PCRS_HEX).unwrap();
    let env = seal_file(Kind::Key, &key, srk_public(&srk).unwrap(), &pcr).unwrap();
    assert_eq!(envelope_sealed_to(&env, Kind::Key, &pcr), Ok(()));
    for i in [0, 8] {
        let mut other = pcr;
        other[i][0] ^= 1;
        assert_eq!(
            envelope_sealed_to(&env, Kind::Key, &other),
            Err("the envelope's sealed object enforces other PCRs 0-8".into()),
            "PCR {i}"
        );
    }
    assert!(envelope_sealed_to(&env, Kind::Pq, &pcr).is_err());
    // `Key` and `Tls` envelopes have one size: the kind refuses each as the other.
    assert_eq!(envelope_sealed_to(&env, Kind::Tls, &pcr), Err("envelope: BadKind".into()));
    let tls_env = seal_file(Kind::Tls, &tls, srk_public(&srk).unwrap(), &pcr).unwrap();
    assert_eq!(envelope_sealed_to(&tls_env, Kind::Tls, &pcr), Ok(()));
    assert_eq!(envelope_sealed_to(&tls_env, Kind::Key, &pcr), Err("envelope: BadKind".into()));
    let policy = tpm2::crypto::policy_digest(&pcr);
    let at = env.windows(32).position(|w| w == policy).expect("header policy copy");
    let mut tampered = env.clone();
    tampered[at] ^= 1;
    assert!(envelope_sealed_to(&tampered, Kind::Key, &pcr).is_err());
}

fn tls_point(private: &[u8; 32]) -> Option<[u8; validate::TLS_PUBLIC_LEN]> {
    let mut s = Secret::<32>::zero();
    s.as_mut_bytes().copy_from_slice(private);
    let xy = tpm2::crypto::public_point(&s)?;
    let mut p = [0x04; validate::TLS_PUBLIC_LEN];
    p[1..].copy_from_slice(&xy);
    Some(p)
}

/// M6 plan C5, C11, C12: the TLS blob's scalar is the key of the config's
/// `tls_public`, of `tls.pub` and of what mkcert was handed.
#[test]
fn generated_tls_scalar_matches_the_config_tls_pub_and_the_issued_key() {
    let (d, asked) = deployment();
    let checked = checked(d);
    let blob = secret_blob::tls::Blob::parse(&d.tls_blob[..]).unwrap_or_else(|e| panic!("{}", e.message()));
    assert_eq!(tls_point(blob.tls_private()), Some(checked.tls_public));
    let spki = [&validate::P256_SPKI_PREFIX[..], &checked.tls_public[..]].concat();
    assert_eq!(pem_der(&d.tls_pub_pem), spki);
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].0, d.tls_pub_pem);
    assert!(d.config.contains("tls_cert = \"tls.der\"\n"));
}

#[test]
fn tls_name_defaults_to_the_outside_ip_and_can_be_given() {
    let (_, asked) = deployment();
    assert_eq!((asked[0].1.as_str(), asked[0].2), ("10.0.2.15", false));
    let (_, asked) = generated(1, "x:1", Some("gw.example"), false).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(asked[0].1, "gw.example");
}

/// The TLS key failure case (M6 plan C12, case 8): the deployment's TLS
/// blob with another valid scalar, its boot seed equal.
#[test]
fn the_tls_mismatch_blob_differs_from_the_tls_blob_in_its_scalar_alone() {
    let (d, _) = deployment();
    let checked = checked(d);
    let other = d.tls_mismatch_blob.as_ref().expect("asked for");
    let (a, b) = (secret_blob::tls::Blob::parse(&d.tls_blob[..]).unwrap(), secret_blob::tls::Blob::parse(&other[..]).unwrap());
    assert_eq!(a.boot_seed(), b.boot_seed());
    assert_ne!(a.tls_private(), b.tls_private());
    let point = tls_point(b.tls_private()).expect("a valid scalar");
    assert_ne!(point, checked.tls_public);
}

/// M6 plan C12: `tlskey`'s boot seed is drawn on its own, and `key`'s blob
/// holds no TLS scalar.
#[test]
fn the_tls_blob_has_its_own_boot_seed_and_the_key_blob_no_tls_scalar() {
    let (d, _) = deployment();
    let key = secret_blob::Blob::parse(&d.blob[..], 2).unwrap();
    let tls = secret_blob::tls::Blob::parse(&d.tls_blob[..]).unwrap();
    assert_ne!(key.boot_seed(), tls.boot_seed());
    assert!(!d.blob.windows(32).any(|w| w == tls.tls_private()), "the TLS scalar is in key's blob");
}

#[test]
fn no_tls_mismatch_blob_unless_asked() {
    let (d, _) = generated(1, "x:1", None, false).unwrap_or_else(|e| panic!("{e}"));
    assert!(d.tls_mismatch_blob.is_none());
}

#[test]
fn config_carries_the_template_tls_ports_and_backend() {
    let (d, _) = deployment();
    let checked = checked(d);
    let template = validate::check(
        TEMPLATE,
        validate::MAX_PEERS,
        &|n: &str| std::fs::read(format!("{}/../../config/{n}", env!("CARGO_MANIFEST_DIR"))).map_err(|e| e.to_string()),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!((checked.tls_ports, checked.backend), (template.tls_ports, template.backend));
}

#[test]
fn an_issuer_failure_or_a_certificate_for_another_key_fails_the_run() {
    let fail = |_: &str, _: &str, _: bool| -> Result<Files, String> { Err("mkcert: no".into()) };
    let tls = TlsOptions { name: None, negative: false, mismatch_blob: false, issue: &fail };
    assert_eq!(generate(TEMPLATE, 1, "x:1", None, &tls).err(), Some("mkcert: no".into()));
    let wrong = |_: &str, _: &str, _: bool| -> Result<Files, String> {
        Ok(vec![("tls.der".to_string(), [&validate::P256_SPKI_PREFIX[..], &[0x04; 65]].concat())])
    };
    let tls = TlsOptions { name: None, negative: false, mismatch_blob: false, issue: &wrong };
    let e = generate(TEMPLATE, 1, "x:1", None, &tls).err().unwrap_or_default();
    assert!(e.contains("generated config invalid") && e.contains("does not hold tls_public"), "{e}");
}

/// The real tools/mkcert, as `run` calls it: the leaf it issues for the
/// PEM mksecrets writes holds that key (the interface between the two).
#[test]
fn mkcert_issues_a_leaf_holding_the_written_public_key() {
    let (_, public) = p256_keypair().unwrap();
    let files = mkcert_issue(&public_key_pem(&public), "10.0.2.15", true).unwrap_or_else(|e| panic!("{e}"));
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["devca.pem", "negative-form.der", "negative-name.der", "tls.der"]);
    let leaf = &files[3].1;
    let spki = [&validate::P256_SPKI_PREFIX[..], &public[..]].concat();
    assert!(leaf.windows(spki.len()).any(|w| w == spki.as_slice()));
}
