//! Interop against swtpm (M5 plan C10, C11; S2, S9, S13, S17, RM5-5): the
//! client and the offline sealing drive a software TPM over its socket the
//! way `key`/`pqkey` will through `tpm`, with a relay in between where a
//! case needs one (A7). tpm2-tools serves as the oracle for the SRK
//! template and the policy digest.
//!
//! Each test starts its own swtpm with its own state directory; dropping
//! the handle kills it and removes the directory, on every exit path
//! (RT11). The flow tests also pass `--terminate`, so a test process that
//! dies without unwinding takes its swtpm with it (the data connection
//! closes).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tpm2::Secret;
use tpm2::client::{CLIENT_ENTROPY_LEN, Cause, Client, Step, UNSEAL_ATTRIBUTES};
use tpm2::crypto;
use tpm2::envelope::{self, Kind, SEAL_ENTROPY_LEN};
use tpm2_wire::gate::{CAP_DIGEST, Gate};
use tpm2_wire::{IPC_MSG_BYTES, RspError, SESSION_CONTINUE, SESSION_ENCRYPT};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Swtpm {
    child: Child,
    dir: PathBuf,
    sock: PathBuf,
}

impl Swtpm {
    fn start(tag: &str, terminate: bool) -> Swtpm {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("tpm2-swtpm-{}-{tag}-{n}", std::process::id()));
        std::fs::create_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        let sock = dir.join("tpm.sock");
        let mut cmd = Command::new("swtpm");
        cmd.arg("socket")
            .arg("--tpm2")
            .arg("--server")
            .arg(format!("type=unixio,path={}", sock.display()))
            .arg("--ctrl")
            .arg(format!("type=unixio,path={}.ctrl", sock.display()))
            .arg("--flags")
            .arg("not-need-init,startup-clear")
            .arg("--tpmstate")
            .arg(format!("dir={}", dir.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if terminate {
            cmd.arg("--terminate");
        }
        let child = cmd.spawn().unwrap_or_else(|e| {
            let _ = std::fs::remove_dir_all(&dir);
            panic!("swtpm: {e}")
        });
        Swtpm { child, dir, sock }
    }

    /// Connects once swtpm listens (a readiness poll, bounded at 10 s).
    fn connect(&mut self) -> Tpm {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(stream) = UnixStream::connect(&self.sock) {
                stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
                return Tpm { stream };
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!("swtpm exited before listening: {status}");
            }
            assert!(Instant::now() < deadline, "swtpm did not listen on {}", self.sock.display());
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn tcti(&self) -> String {
        format!("swtpm:path={}", self.sock.display())
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct Tpm {
    stream: UnixStream,
}

impl Tpm {
    fn transact(&mut self, cmd: &[u8]) -> Vec<u8> {
        self.stream.write_all(cmd).unwrap();
        let mut header = [0u8; 10];
        self.stream.read_exact(&mut header).unwrap();
        let size = u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize;
        assert!((10..=4096).contains(&size), "response size {size}");
        let mut rsp = header.to_vec();
        rsp.resize(size, 0);
        self.stream.read_exact(&mut rsp[10..]).unwrap();
        rsp
    }

    fn pcr_extend(&mut self, digest: &[u8; 32]) {
        let mut buf = [0u8; IPC_MSG_BYTES];
        let n = tpm2_wire::pcr_extend(&mut buf, digest).unwrap();
        tpm2_wire::parse_pcr_extend(&self.transact(&buf[..n])).unwrap();
    }

    fn pcr8(&mut self) -> [u8; 32] {
        let mut buf = [0u8; IPC_MSG_BYTES];
        let n = tpm2_wire::pcr_read(&mut buf).unwrap();
        *tpm2_wire::parse_pcr_read(&self.transact(&buf[..n])).unwrap()
    }

    /// The SRK's TPMT_PUBLIC and Name, by the crate's own CreatePrimary;
    /// the handle is flushed again.
    fn srk(&mut self) -> (Vec<u8>, Vec<u8>) {
        let mut buf = [0u8; IPC_MSG_BYTES];
        let n = tpm2_wire::create_primary(&mut buf).unwrap();
        let rsp = self.transact(&buf[..n]);
        let r = tpm2_wire::parse_create_primary(&rsp).unwrap();
        let out = (r.public.to_vec(), r.name.to_vec());
        let n = tpm2_wire::flush_context(&mut buf, r.handle).unwrap();
        tpm2_wire::parse_empty(&self.transact(&buf[..n])).unwrap();
        out
    }
}

/// Deterministic entropy per label (SHA-256 in counter mode): the tests
/// need distinct values, not unpredictable ones.
fn entropy<const N: usize>(label: &str) -> Secret<N> {
    let mut s = Secret::<N>::zero();
    for (i, chunk) in s.as_mut_bytes().chunks_mut(32).enumerate() {
        let block = crypto::sha256(&[label.as_bytes(), &(i as u32).to_be_bytes()]);
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
    s
}

/// The two extends U-Boot performs (descriptor, then image), stood in for
/// by two fixed digests; returns the PCR 8 they produce.
const BOOT_DIGESTS: [[u8; 32]; 2] = [[0x11; 32], [0x22; 32]];

fn extend(pcr: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    crypto::sha256(&[pcr, digest])
}

fn expected_pcr8() -> [u8; 32] {
    BOOT_DIGESTS.iter().fold([0u8; 32], |pcr, d| extend(&pcr, d))
}

/// PCRs 0-8 as the seal policy names them: no firmware runs here, so PCR
/// 0-7 hold their reset value.
fn expected_pcrs() -> crypto::PolicyPcrs {
    let mut pcrs = [[0u8; 32]; tpm2_wire::POLICY_PCR_COUNT];
    pcrs[8] = expected_pcr8();
    pcrs
}

fn measured_boot(tpm: &mut Tpm) {
    for d in &BOOT_DIGESTS {
        tpm.pcr_extend(d);
    }
    assert_eq!(tpm.pcr8(), expected_pcr8(), "swtpm's PCR 8 after the boot extends");
}

/// A `key` blob stand-in: a region with a recognisable prefix.
fn blob(kind: Kind, label: &str) -> Vec<u8> {
    let mut b = vec![0u8; kind.region_size()];
    let fill = crypto::sha256(&[label.as_bytes()]);
    for (i, x) in b.iter_mut().take(1000).enumerate() {
        *x = fill[i % 32] ^ (i as u8) | 1;
    }
    b
}

fn seal(kind: Kind, region: &[u8], srk_public: &[u8], pcrs: &crypto::PolicyPcrs, label: &str) -> Vec<u8> {
    let mut out = vec![0u8; kind.region_size()];
    let e = entropy::<SEAL_ENTROPY_LEN>(label);
    envelope::seal(&mut out, kind, region, srk_public, pcrs, &e).unwrap();
    out
}

/// The KEK `seal` put into the envelope sealed under `label`.
fn kek_of(label: &str) -> [u8; 32] {
    entropy::<SEAL_ENTROPY_LEN>(label).as_bytes()[..32].try_into().unwrap()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    Command,
    Response,
}

enum Action {
    Forward,
    /// Do not forward the command; give the client this response instead.
    Reply(Vec<u8>),
}

/// Runs the client to the end through `relay`, and through `gate` as
/// client `id` if given (every command must be forwarded); returns the
/// client's result with the region it opened.
fn drive(
    tpm: &mut Tpm,
    mut client: Client<'_>,
    kind: Kind,
    mut gate: Option<(&mut Gate, usize)>,
    mut relay: impl FnMut(Step, Dir, &mut Vec<u8>, &mut Tpm) -> Action,
) -> (Result<(), tpm2::client::Failure>, Vec<u8>) {
    let mut buf = [0u8; IPC_MSG_BYTES];
    while let Some(n) = client.command(&mut buf) {
        let step = client.step();
        let mut cmd = buf[..n].to_vec();
        let rsp = match relay(step, Dir::Command, &mut cmd, tpm) {
            Action::Reply(rsp) => rsp,
            Action::Forward => {
                let fwd = gate.as_mut().map(|(g, id)| {
                    g.command(*id, &cmd).unwrap_or_else(|r| panic!("gate refused {step:?}: {r:?}"))
                });
                let mut rsp = tpm.transact(&cmd);
                if let (Some((g, _)), Some(fwd)) = (gate.as_mut(), fwd) {
                    g.response(fwd, &rsp);
                }
                let _ = relay(step, Dir::Response, &mut rsp, tpm);
                rsp
            }
        };
        client.response(&rsp);
    }
    let mut out = vec![0u8; kind.region_size()];
    let r = client.finish(&mut out);
    (r, out)
}

fn pass(_: Step, _: Dir, _: &mut Vec<u8>, _: &mut Tpm) -> Action {
    Action::Forward
}

fn client<'e>(env: &'e [u8], kind: Kind, label: &str) -> Client<'e> {
    Client::new(env, kind, &entropy::<CLIENT_ENTROPY_LEN>(label)).unwrap()
}

fn rc(rsp: &[u8]) -> u32 {
    u32::from_be_bytes(rsp[6..10].try_into().unwrap())
}

/// TPM_RC format-one errors carry the session or handle number in bits
/// 8..11; the error itself is bits 0..5 plus RC_FMT1.
fn fmt1_error(rc: u32) -> u32 {
    rc & 0xBF
}
/// TPM_RC_BAD_AUTH: the HMAC check failed on an entity exempt from
/// dictionary-attack lockout (the sealed object is noDA; with DA it would
/// be TPM_RC_AUTH_FAIL).
const RC_BAD_AUTH: u32 = 0x0A2;
const RC_POLICY_FAIL: u32 = 0x09D;

fn tool(swtpm: &Swtpm, args: &[&str]) {
    let out = Command::new(args[0])
        .args(&args[1..])
        .env("TPM2TOOLS_TCTI", swtpm.tcti())
        .output()
        .unwrap_or_else(|e| panic!("{}: {e}", args[0]));
    assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn srk_public_and_name_match_tpm2_createprimary() {
    let mut swtpm = Swtpm::start("oracle-srk", false);
    let (public, name) = {
        let mut tpm = swtpm.connect();
        tpm.srk()
    };
    let ctx = swtpm.dir.join("srk.ctx");
    let pubfile = swtpm.dir.join("srk.pub");
    let namefile = swtpm.dir.join("srk.name");
    tool(
        &swtpm,
        &[
            "tpm2_createprimary",
            "-Q",
            "-C",
            "o",
            "-G",
            "ecc256:aes128cfb",
            "-g",
            "sha256",
            "-a",
            "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt",
            "-c",
            ctx.to_str().unwrap(),
        ],
    );
    tool(
        &swtpm,
        &[
            "tpm2_readpublic",
            "-Q",
            "-c",
            ctx.to_str().unwrap(),
            "-o",
            pubfile.to_str().unwrap(),
            "-n",
            namefile.to_str().unwrap(),
        ],
    );
    let oracle = read(&pubfile);
    assert_eq!(&oracle[2..], &public[..], "TPMT_PUBLIC differs from tpm2_createprimary's");
    assert_eq!(read(&namefile), name, "Name differs from tpm2-tools'");
    assert_eq!(crypto::name(&public).to_vec(), name, "the crate's Name computation");
}

#[test]
fn policy_digest_matches_a_tpm2_tools_trial_session() {
    // The independent adjudicator of the policy digest (M7 plan C4, TE4):
    // tpm2-tools over sha256:0-8, reading the values from swtpm itself
    // after the boot extends (its -f file takes at most eight PCRs).
    let mut swtpm = Swtpm::start("oracle-policy", false);
    let mut tpm = swtpm.connect();
    measured_boot(&mut tpm);
    drop(tpm);
    let pcr = expected_pcrs();
    let session = swtpm.dir.join("trial.ctx");
    let policy = swtpm.dir.join("policy.bin");
    let s = session.to_str().unwrap();
    let p = policy.to_str().unwrap();
    tool(&swtpm, &["tpm2_startauthsession", "-Q", "-S", s]);
    tool(&swtpm, &["tpm2_policypcr", "-Q", "-S", s, "-l", "sha256:0,1,2,3,4,5,6,7,8", "-L", p]);
    assert_eq!(read(&policy), crypto::policy_pcr_digest(&pcr), "PolicyPCR digest");
    tool(&swtpm, &["tpm2_policyauthvalue", "-Q", "-S", s, "-L", p]);
    assert_eq!(read(&policy), crypto::policy_digest(&pcr), "PolicyPCR ∧ PolicyAuthValue digest");
    tool(&swtpm, &["tpm2_flushcontext", "-Q", s]);
}

#[test]
fn sealed_envelope_unseals_to_the_original_blob_through_the_gate_and_the_cap_follows() {
    let mut swtpm = Swtpm::start("allow", true);
    let mut tpm = swtpm.connect();
    let (srk_public, _) = tpm.srk();
    measured_boot(&mut tpm);
    let key_blob = blob(Kind::Key, "key");
    let pq_blob = blob(Kind::Pq, "pq");
    let key_env = seal(Kind::Key, &key_blob, &srk_public, &expected_pcrs(), "seal-key");
    let pq_env = seal(Kind::Pq, &pq_blob, &srk_public, &expected_pcrs(), "seal-pq");
    let tls_blob = blob(Kind::Tls, "tls");
    let tls_env = seal(Kind::Tls, &tls_blob, &srk_public, &expected_pcrs(), "seal-tls");

    let mut gate = Gate::new();
    let (r, out) = drive(&mut tpm, client(&key_env, Kind::Key, "c-key"), Kind::Key, Some((&mut gate, 0)), pass);
    assert_eq!(r, Ok(()));
    assert!(out == key_blob, "the key envelope did not open to its blob");
    gate.finish(0, true).unwrap();
    let mut buf = [0u8; IPC_MSG_BYTES];
    assert_eq!(gate.cap(&mut buf), None, "capped before every client finished");

    let (r, out) = drive(&mut tpm, client(&pq_env, Kind::Pq, "c-pq"), Kind::Pq, Some((&mut gate, 1)), pass);
    assert_eq!(r, Ok(()));
    assert!(out == pq_blob, "the pq envelope did not open to its blob");
    gate.finish(1, true).unwrap();
    assert_eq!(gate.cap(&mut buf), None, "capped before the third client finished");

    // M6 plan C12: `tlskey`'s envelope, the third client.
    let (r, out) = drive(&mut tpm, client(&tls_env, Kind::Tls, "c-tls"), Kind::Tls, Some((&mut gate, 2)), pass);
    assert_eq!(r, Ok(()));
    assert!(out == tls_blob, "the tls envelope did not open to its blob");
    gate.finish(2, true).unwrap();

    let n = gate.cap(&mut buf).expect("cap after every client is done");
    tpm2_wire::parse_pcr_extend(&tpm.transact(&buf[..n])).unwrap();
    assert_eq!(tpm.pcr8(), extend(&expected_pcr8(), &CAP_DIGEST), "PCR 8 after the cap");
    // After the cap the same envelope no longer unseals, even for a client
    // that bypasses the gate.
    let (r, out) = drive(&mut tpm, client(&key_env, Kind::Key, "c-key-2"), Kind::Key, None, pass);
    let f = r.unwrap_err();
    assert_eq!(f.step, Step::Unseal);
    assert!(matches!(f.cause, Cause::Response(RspError::Tpm(rc)) if fmt1_error(rc) == RC_POLICY_FAIL), "{f:?}");
    assert!(out.iter().all(|b| *b == 0));
}

#[test]
fn wrong_pcr8_fails_unseal_with_a_policy_error_and_no_plaintext() {
    let mut swtpm = Swtpm::start("wrong-pcr", true);
    let mut tpm = swtpm.connect();
    let (srk_public, _) = tpm.srk();
    // A different image: the second extend differs.
    tpm.pcr_extend(&BOOT_DIGESTS[0]);
    tpm.pcr_extend(&[0x33; 32]);
    let key_blob = blob(Kind::Key, "key");
    let env = seal(Kind::Key, &key_blob, &srk_public, &expected_pcrs(), "seal");
    let (r, out) = drive(&mut tpm, client(&env, Kind::Key, "c"), Kind::Key, None, pass);
    let f = r.unwrap_err();
    assert_eq!(f.step, Step::Unseal);
    assert!(matches!(f.cause, Cause::Response(RspError::Tpm(rc)) if fmt1_error(rc) == RC_POLICY_FAIL), "{f:?}");
    assert!(out.iter().all(|b| *b == 0), "plaintext after a failed unseal");
}

#[test]
fn envelope_sealed_to_a_foreign_tpm_fails_the_srk_name_check() {
    let mut other = Swtpm::start("foreign-other", true);
    let foreign_public = other.connect().srk().0;
    drop(other);
    let mut swtpm = Swtpm::start("foreign", true);
    let mut tpm = swtpm.connect();
    measured_boot(&mut tpm);
    let env = seal(Kind::Key, &blob(Kind::Key, "key"), &foreign_public, &expected_pcrs(), "seal");
    let mut sent = Vec::new();
    let (r, out) = drive(&mut tpm, client(&env, Kind::Key, "c"), Kind::Key, None, |step, dir, _, _| {
        if dir == Dir::Command {
            sent.push(step);
        }
        Action::Forward
    });
    assert_eq!(r.unwrap_err(), tpm2::client::Failure { step: Step::CreatePrimary, cause: Cause::SrkName });
    // Nothing after CreatePrimary but the flush of the SRK it created.
    assert_eq!(sent, [Step::CreatePrimary, Step::FlushPrimary]);
    assert!(out.iter().all(|b| *b == 0));
}

#[test]
fn every_flipped_byte_of_the_unseal_response_is_refused_and_outdata_never_used() {
    let mut swtpm = Swtpm::start("flip", true);
    let mut tpm = swtpm.connect();
    let (srk_public, _) = tpm.srk();
    measured_boot(&mut tpm);
    let env = seal(Kind::Key, &blob(Kind::Key, "key"), &srk_public, &expected_pcrs(), "seal");
    // An unmodified relay first: the response length to iterate over.
    let mut len = 0;
    let (r, _) = drive(&mut tpm, client(&env, Kind::Key, "c-0"), Kind::Key, None, |step, dir, rsp, _| {
        if step == Step::Unseal && dir == Dir::Response {
            len = rsp.len();
        }
        Action::Forward
    });
    assert_eq!(r, Ok(()));
    let mut hmac_failures = 0;
    for i in 0..len {
        let (r, out) = drive(&mut tpm, client(&env, Kind::Key, &format!("c-{i}")), Kind::Key, None, |step, dir, rsp, _| {
            if step == Step::Unseal && dir == Dir::Response {
                rsp[i] ^= 0x01;
            }
            Action::Forward
        });
        let f = r.expect_err(&format!("byte {i} flipped and accepted"));
        assert_eq!(f.step, Step::Unseal, "byte {i}");
        // Header and length fields fail to parse; everything the HMAC
        // covers fails it.
        assert!(matches!(f.cause, Cause::ResponseHmac | Cause::Response(_)), "byte {i}: {f:?}");
        if f.cause == Cause::ResponseHmac {
            hmac_failures += 1;
        }
        assert!(out.iter().all(|b| *b == 0), "byte {i}: plaintext");
    }
    // outData (32), the nonce (32), the attributes and the hmac (32) at least.
    assert!(hmac_failures >= 97, "only {hmac_failures} flips reached the HMAC check");
}

/// The Unseal command's session attributes byte: after the header (10),
/// the object handle (4), the auth size (4), the session handle (4) and
/// the nonce (2 + 32).
const UNSEAL_ATTRIBUTES_AT: usize = 10 + 4 + 4 + 4 + 2 + 32;

#[test]
fn stripping_encrypt_from_unseal_gets_a_bad_auth_and_no_outdata() {
    let mut swtpm = Swtpm::start("strip", true);
    let mut tpm = swtpm.connect();
    let (srk_public, _) = tpm.srk();
    measured_boot(&mut tpm);
    let env = seal(Kind::Key, &blob(Kind::Key, "key"), &srk_public, &expected_pcrs(), "seal");
    let mut seen = Vec::new();
    let (r, out) = drive(&mut tpm, client(&env, Kind::Key, "c"), Kind::Key, None, |step, dir, bytes, _| {
        if step == Step::Unseal {
            match dir {
                Dir::Command => {
                    assert_eq!(bytes[UNSEAL_ATTRIBUTES_AT], UNSEAL_ATTRIBUTES);
                    bytes[UNSEAL_ATTRIBUTES_AT] &= !SESSION_ENCRYPT;
                }
                Dir::Response => seen = bytes.clone(),
            }
        }
        Action::Forward
    });
    assert_eq!(fmt1_error(rc(&seen)), RC_BAD_AUTH, "swtpm's response code {:#x}", rc(&seen));
    assert_eq!(seen.len(), 10, "an auth failure carries no outData");
    let f = r.unwrap_err();
    assert_eq!(f.step, Step::Unseal);
    assert!(out.iter().all(|b| *b == 0));
}

/// The plan's red-proof for PolicyAuthValue (S9) does not hold, and this
/// pins what does: sealed under PolicyPCR alone, with the client's
/// PolicyAuthValue dropped by the relay (answered by the relay itself),
/// stripping `encrypt` still gets TPM_RC_BAD_AUTH and no outData. The TPM
/// checks a policy session's command HMAC whether or not the policy holds
/// PolicyAuthValue (libtpms SessionProcess.c, CheckAuthSession, as the TCG
/// reference code): the key is the salted session key, which the relay
/// does not have. PolicyAuthValue only adds the authValue, which is empty,
/// to that key.
#[test]
fn without_policy_auth_value_a_stripped_encrypt_still_fails_the_salted_session_hmac() {
    let mut swtpm = Swtpm::start("weak", true);
    let mut tpm = swtpm.connect();
    let (srk_public, _) = tpm.srk();
    measured_boot(&mut tpm);
    let region = blob(Kind::Key, "key");
    let mut env = vec![0u8; Kind::Key.region_size()];
    let policy = crypto::policy_pcr_digest(&expected_pcrs());
    envelope::seal_with_policy(&mut env, Kind::Key, &region, &srk_public, &policy, &entropy("seal-weak")).unwrap();
    let mut seen = Vec::new();
    let (r, out) = drive(&mut tpm, client(&env, Kind::Key, "c"), Kind::Key, None, |step, dir, bytes, _| {
        match (step, dir) {
            (Step::PolicyAuthValue, Dir::Command) => {
                return Action::Reply(vec![0x80, 0x01, 0, 0, 0, 10, 0, 0, 0, 0]);
            }
            (Step::Unseal, Dir::Command) => bytes[UNSEAL_ATTRIBUTES_AT] &= !SESSION_ENCRYPT,
            (Step::Unseal, Dir::Response) => seen = bytes.clone(),
            _ => {}
        }
        Action::Forward
    });
    assert_eq!(fmt1_error(rc(&seen)), RC_BAD_AUTH, "swtpm's response code {:#x}", rc(&seen));
    assert_eq!(seen.len(), 10, "an auth failure carries no outData");
    assert_eq!(r.unwrap_err().step, Step::Unseal);
    assert!(out.iter().all(|b| *b == 0));
}

/// Unseal's nonceCaller and hmac, as `UNSEAL_ATTRIBUTES_AT` counts.
const UNSEAL_NONCE_AT: usize = UNSEAL_ATTRIBUTES_AT - 32;
const UNSEAL_HMAC_AT: usize = UNSEAL_ATTRIBUTES_AT + 1 + 2;
/// StartAuthSession's nonceCaller: after the header and two handles.
const START_NONCE_AT: usize = 10 + 4 + 4 + 2;

/// What the salt is for, and the limit of C9's "cannot unsalt" claim
/// (RM5-5): a relay that rewrites the client's StartAuthSession into an
/// unsalted one gets a session whose key is empty. It then recomputes
/// Unseal's HMAC with that empty key (PolicyAuthValue's authValue is empty
/// too), strips `encrypt`, and reads the KEK in plaintext. The client
/// still refuses the response (its own response HMAC), so integrity holds;
/// confidentiality against an active A7 does not, as RM5-5 states.
#[test]
fn rm5_5_a_relay_that_unsalts_the_session_reads_the_kek_and_the_client_refuses() {
    let mut swtpm = Swtpm::start("unsalt", true);
    let mut tpm = swtpm.connect();
    let (srk_public, _) = tpm.srk();
    measured_boot(&mut tpm);
    let label = "seal";
    let env = seal(Kind::Key, &blob(Kind::Key, "key"), &srk_public, &expected_pcrs(), label);
    let name = envelope::Envelope::parse(&env, Kind::Key).unwrap().object_name();
    let mut nonce_tpm = Vec::new();
    let mut leaked = None;
    let (r, out) = drive(&mut tpm, client(&env, Kind::Key, "c"), Kind::Key, None, |step, dir, bytes, _| {
        match (step, dir) {
            (Step::StartAuthSession, Dir::Command) => {
                let nonce: [u8; 32] = bytes[START_NONCE_AT..START_NONCE_AT + 32].try_into().unwrap();
                *bytes = unsalted_start_auth_session(&nonce);
            }
            (Step::StartAuthSession, Dir::Response) => {
                nonce_tpm = tpm2_wire::parse_start_auth_session(bytes).unwrap().nonce_tpm.to_vec();
            }
            (Step::Unseal, Dir::Command) => {
                let attributes = SESSION_CONTINUE;
                bytes[UNSEAL_ATTRIBUTES_AT] = attributes;
                let cp_hash = crypto::sha256(&[&tpm2_wire::CC_UNSEAL.to_be_bytes(), &name]);
                let mut hmac = [0u8; 32];
                let nonce_caller = bytes[UNSEAL_NONCE_AT..UNSEAL_NONCE_AT + 32].to_vec();
                crypto::hmac(&mut hmac, &[], &[&cp_hash, &nonce_caller, &nonce_tpm, &[attributes]]).unwrap();
                bytes[UNSEAL_HMAC_AT..UNSEAL_HMAC_AT + 32].copy_from_slice(&hmac);
            }
            (Step::Unseal, Dir::Response) => {
                leaked = Some(tpm2_wire::parse_unseal(bytes).expect("the unsalted Unseal").out_data.to_vec());
            }
            _ => {}
        }
        Action::Forward
    });
    assert_eq!(leaked.as_deref(), Some(&kek_of(label)[..]), "the KEK crossed the relay in plaintext");
    assert_eq!(r.unwrap_err(), tpm2::client::Failure { step: Step::Unseal, cause: Cause::ResponseHmac });
    assert!(out.iter().all(|b| *b == 0));
}

/// StartAuthSession for an unsalted, unbound policy session.
fn unsalted_start_auth_session(nonce_caller: &[u8; 32]) -> Vec<u8> {
    let mut buf = [0u8; IPC_MSG_BYTES];
    let mut w = tpm2_wire::Writer::new(&mut buf);
    w.u16(tpm2_wire::ST_NO_SESSIONS).unwrap();
    w.u32(0).unwrap();
    w.u32(tpm2_wire::CC_START_AUTH_SESSION).unwrap();
    w.u32(tpm2_wire::RH_NULL).unwrap();
    w.u32(tpm2_wire::RH_NULL).unwrap();
    w.tpm2b(nonce_caller).unwrap();
    w.tpm2b(&[]).unwrap();
    w.u8(tpm2_wire::SE_POLICY).unwrap();
    w.u16(tpm2_wire::ALG_NULL).unwrap();
    w.u16(tpm2_wire::ALG_SHA256).unwrap();
    let n = w.finish().unwrap();
    buf[..n].to_vec()
}

/// Documents RM5-5: the policy binds the KEK to the TPM and PCR 8, not to
/// the caller. A relay that runs its own (unsalted) policy session against
/// the client's loaded object, while PCR 8 holds the expected value,
/// unseals the KEK. C14's A7 case is integrity evidence only.
#[test]
fn rm5_5_a_relay_running_its_own_session_on_the_loaded_object_unseals_the_kek() {
    let mut swtpm = Swtpm::start("rm5-5", true);
    let mut tpm = swtpm.connect();
    let (srk_public, _) = tpm.srk();
    measured_boot(&mut tpm);
    let label = "seal";
    let env = seal(Kind::Key, &blob(Kind::Key, "key"), &srk_public, &expected_pcrs(), label);
    let parsed = envelope::Envelope::parse(&env, Kind::Key).unwrap();
    let mut stolen = None;
    let (r, out) = drive(&mut tpm, client(&env, Kind::Key, "c"), Kind::Key, None, |step, dir, bytes, tpm| {
        if step == Step::Load && dir == Dir::Response {
            let object = tpm2_wire::parse_load(bytes).unwrap().handle;
            stolen = Some(own_session_unseal(tpm, object, &parsed.object_name()));
        }
        Action::Forward
    });
    assert_eq!(stolen.as_deref(), Some(&kek_of(label)[..]), "the relay's own session unsealed the KEK");
    // The client's own flow is unaffected.
    assert_eq!(r, Ok(()));
    assert!(out == blob(Kind::Key, "key"));
}

/// An unsalted, unbound policy session: the session key is empty, so the
/// HMAC key is the empty authValue, which anyone can compute.
fn own_session_unseal(tpm: &mut Tpm, object: u32, name: &[u8; 34]) -> Vec<u8> {
    let mut buf = [0u8; IPC_MSG_BYTES];
    let nonce_caller = [0x5A; 32];
    let rsp = tpm.transact(&unsalted_start_auth_session(&nonce_caller));
    let s = tpm2_wire::parse_start_auth_session(&rsp).unwrap();
    let (session, nonce_tpm) = (s.handle, s.nonce_tpm.to_vec());
    let n = tpm2_wire::policy_pcr(&mut buf, session).unwrap();
    tpm2_wire::parse_empty(&tpm.transact(&buf[..n])).unwrap();
    let n = tpm2_wire::policy_auth_value(&mut buf, session).unwrap();
    tpm2_wire::parse_empty(&tpm.transact(&buf[..n])).unwrap();
    let cp_hash = crypto::sha256(&[&tpm2_wire::CC_UNSEAL.to_be_bytes(), name]);
    let mut hmac = [0u8; 32];
    crypto::hmac(&mut hmac, &[], &[&cp_hash, &nonce_caller, &nonce_tpm, &[SESSION_CONTINUE]]).unwrap();
    let n = tpm2_wire::unseal(&mut buf, object, session, &nonce_caller, SESSION_CONTINUE, &hmac).unwrap();
    let rsp = tpm.transact(&buf[..n]);
    let kek = tpm2_wire::parse_unseal(&rsp).expect("the relay's own Unseal").out_data.to_vec();
    let n = tpm2_wire::flush_context(&mut buf, session).unwrap();
    tpm2_wire::parse_empty(&tpm.transact(&buf[..n])).unwrap();
    kek
}

/// S2: a fake TPM that answers client A's Unseal with client B's valid
/// response (another session, another KEK) is refused by A's response
/// HMAC; nothing of B's KEK is accepted.
#[test]
fn the_other_clients_valid_unseal_response_is_refused() {
    let mut swtpm = Swtpm::start("swap", true);
    let mut tpm = swtpm.connect();
    let (srk_public, _) = tpm.srk();
    measured_boot(&mut tpm);
    let env_b = seal(Kind::Key, &blob(Kind::Key, "b"), &srk_public, &expected_pcrs(), "seal-b");
    let env_a = seal(Kind::Key, &blob(Kind::Key, "a"), &srk_public, &expected_pcrs(), "seal-a");
    let mut b_unseal = Vec::new();
    let (r, _) = drive(&mut tpm, client(&env_b, Kind::Key, "c-b"), Kind::Key, None, |step, dir, rsp, _| {
        if step == Step::Unseal && dir == Dir::Response {
            b_unseal = rsp.clone();
        }
        Action::Forward
    });
    assert_eq!(r, Ok(()), "client B's own flow");
    let (r, out) = drive(&mut tpm, client(&env_a, Kind::Key, "c-a"), Kind::Key, None, |step, dir, rsp, _| {
        if step == Step::Unseal && dir == Dir::Response {
            *rsp = b_unseal.clone();
        }
        Action::Forward
    });
    assert_eq!(r.unwrap_err(), tpm2::client::Failure { step: Step::Unseal, cause: Cause::ResponseHmac });
    assert!(out.iter().all(|b| *b == 0));
}

/// S13: two seals of one blob carry different KEKs, so different
/// ciphertexts, and both unseal to the blob.
#[test]
fn two_seals_of_one_blob_differ_and_both_unseal() {
    let mut swtpm = Swtpm::start("twice", true);
    let mut tpm = swtpm.connect();
    let (srk_public, _) = tpm.srk();
    measured_boot(&mut tpm);
    let region = blob(Kind::Key, "key");
    let first = seal(Kind::Key, &region, &srk_public, &expected_pcrs(), "seal-1");
    let second = seal(Kind::Key, &region, &srk_public, &expected_pcrs(), "seal-2");
    // The encrypted body alone: under one KEK the stream cipher would give
    // the same bytes whatever the AAD (only the tag would differ).
    let body = |e: &[u8]| {
        let ct = envelope::Envelope::parse(e, Kind::Key).unwrap().ciphertext().to_vec();
        ct[..ct.len() - 16].to_vec()
    };
    assert_ne!(body(&first), body(&second), "identical ciphertexts from two seals");
    for (env, label) in [(&first, "c-1"), (&second, "c-2")] {
        let (r, out) = drive(&mut tpm, client(env, Kind::Key, label), Kind::Key, None, pass);
        assert_eq!(r, Ok(()));
        assert!(out == region);
    }
}

/// The `tpm` PD as crates/pds/tpm runs it (the gate with its
/// one-flow-at-a-time Busy rule answered RSP_BUSY, the cap after every
/// client finished, the cap status of the barrier), over swtpm, shared by
/// three client threads.
struct PdModel {
    tpm: Tpm,
    gate: Gate,
    busy: usize,
}

/// The cap's device: swtpm, which always answers.
struct CapDevice<'t> {
    tpm: &'t mut Tpm,
    rsp: Vec<u8>,
}

impl tpm2_wire::gate::CapTransport for CapDevice<'_> {
    fn attempt(&mut self, cmd: &[u8], _budget_ns: u64) -> Option<&[u8]> {
        self.rsp = self.tpm.transact(cmd);
        Some(&self.rsp)
    }
}

/// The PD's reply to the Done that ran the cap and to the cap status.
fn cap_label(verdict: CapVerdict) -> u64 {
    match verdict {
        CapVerdict::Confirmed => ipc::label(ipc::RSP_OK, 0),
        CapVerdict::Failed => ipc::label(ipc::RSP_REFUSED, ipc::REFUSED_CAP_FAILED),
    }
}

struct PdCall<'m> {
    pd: &'m std::sync::Mutex<PdModel>,
    client: usize,
    start: Instant,
}

impl tpm2::boot::Transport for PdCall<'_> {
    fn call(&mut self, label: u64, req: &[u8], rsp: &mut [u8; ipc::MSG_BYTES]) -> (u64, usize) {
        let mut pd = self.pd.lock().unwrap();
        match ipc::kind(label) {
            ipc::REQ_COMMAND => {
                let fwd = match pd.gate.command(self.client, req) {
                    Ok(fwd) => fwd,
                    Err(Refusal::Busy) => {
                        pd.busy += 1;
                        return (ipc::label(ipc::RSP_BUSY, 0), 0);
                    }
                    Err(_) => return (ipc::label(ipc::RSP_REFUSED, 1), 0),
                };
                let r = pd.tpm.transact(req);
                pd.gate.response(fwd, &r);
                rsp[..r.len()].copy_from_slice(&r);
                (ipc::label(ipc::RSP_OK, r.len()), ipc::words(r.len()) * 8)
            }
            ipc::REQ_CAP_STATUS => match pd.gate.cap_status(self.client) {
                Ok(CapStatus::Pending) => (ipc::label(ipc::RSP_BUSY, 0), 0),
                Ok(CapStatus::Confirmed) => (cap_label(CapVerdict::Confirmed), 0),
                Ok(CapStatus::Failed) => (cap_label(CapVerdict::Failed), 0),
                Err(_) => (ipc::label(ipc::RSP_REFUSED, 2), 0),
            },
            kind => {
                if pd.gate.finish(self.client, kind == ipc::REQ_DONE).is_err() {
                    return (ipc::label(ipc::RSP_REFUSED, 2), 0);
                }
                let PdModel { tpm, gate, .. } = &mut *pd;
                match gate.run_cap(&mut CapDevice { tpm, rsp: Vec::new() }) {
                    Some(verdict) => (cap_label(verdict), 0),
                    None => (ipc::label(ipc::RSP_OK, 0), 0),
                }
            }
        }
    }

    fn now_ns(&mut self) -> u64 {
        self.start.elapsed().as_nanos() as u64
    }

    fn random(&mut self, out: &mut [u8]) -> bool {
        let e = entropy::<CLIENT_ENTROPY_LEN>(&format!("boot-{}", self.client));
        out.copy_from_slice(&e.as_bytes()[..out.len()]);
        true
    }
}

use layout::tpm as ipc;
use tpm2_wire::gate::{CapStatus, CapVerdict, Refusal};

#[test]
fn every_key_pd_unseals_concurrently_through_the_pd_model_and_pcr8_is_capped() {
    let mut swtpm = Swtpm::start("boot-both", true);
    let mut tpm = swtpm.connect();
    let (srk_public, _) = tpm.srk();
    measured_boot(&mut tpm);
    let key_blob = blob(Kind::Key, "key");
    let pq_blob = blob(Kind::Pq, "pq");
    let key_env = seal(Kind::Key, &key_blob, &srk_public, &expected_pcrs(), "boot-seal-key");
    let pq_env = seal(Kind::Pq, &pq_blob, &srk_public, &expected_pcrs(), "boot-seal-pq");
    let tls_blob = blob(Kind::Tls, "tls");
    let tls_env = seal(Kind::Tls, &tls_blob, &srk_public, &expected_pcrs(), "boot-seal-tls");
    let pd = std::sync::Mutex::new(PdModel { tpm, gate: Gate::new(), busy: 0 });
    let start = Instant::now();
    // Two flows at once would need four transient objects (swtpm has
    // three): the Busy rule serialises the three, whichever starts first.
    let run = |client: usize, env: &[u8], kind: Kind| {
        let mut out = vec![0xAAu8; kind.region_size()];
        let r = tpm2::boot::unseal(&mut PdCall { pd: &pd, client, start }, env, kind, &mut out);
        (r, out)
    };
    let (key, pq, tls) = std::thread::scope(|s| {
        let a = s.spawn(|| run(0, &key_env, Kind::Key));
        let b = s.spawn(|| run(1, &pq_env, Kind::Pq));
        let c = s.spawn(|| run(2, &tls_env, Kind::Tls));
        (a.join().unwrap(), b.join().unwrap(), c.join().unwrap())
    });
    assert_eq!(key.0, Ok(()));
    assert!(key.1 == key_blob, "key's region");
    assert_eq!(pq.0, Ok(()));
    assert!(pq.1 == pq_blob, "pqkey's region");
    assert_eq!(tls.0, Ok(()));
    assert!(tls.1 == tls_blob, "tlskey's region");
    let mut pd = pd.into_inner().unwrap();
    assert!(pd.gate.is_capped());
    assert_eq!(pd.tpm.pcr8(), extend(&expected_pcr8(), &CAP_DIGEST), "PCR 8 after the cap");
    eprintln!("busy replies: {}", pd.busy);
}
