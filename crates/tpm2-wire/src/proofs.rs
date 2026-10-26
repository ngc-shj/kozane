//! Kani harnesses for the response parsers and the `tpm` gate (M5 plan
//! C9, C10). Run with `cargo kani -p tpm2-wire`. The gate's symbolic state
//! is kept small: concrete command shapes with symbolic handles, codes and
//! clients.

use super::gate::{ALLOWED, CAP_ATTEMPTS, CapStatus, CapTransport, Gate, Refusal};
use super::*;

const MAX_LEN: usize = 64;

fn any_bytes(buf: &[u8; MAX_LEN]) -> &[u8] {
    let len: usize = kani::any();
    kani::assume(len <= MAX_LEN);
    buf.get(..len).unwrap_or(&[])
}

fn inside(outer: &[u8], inner: &[u8]) -> bool {
    let (o, i) = (outer.as_ptr_range(), inner.as_ptr_range());
    inner.is_empty() || (o.start <= i.start && i.end <= o.end)
}

/// Every parser is total on arbitrary bytes, and what it returns lies
/// inside the input with the lengths the flow allows.
#[kani::proof]
#[kani::unwind(12)]
fn response_parsers_are_total_and_in_bounds() {
    let buf: [u8; MAX_LEN] = kani::any();
    let bytes = any_bytes(&buf);
    if let Ok(r) = parse_start_auth_session(bytes) {
        assert!(inside(bytes, r.nonce_tpm));
        assert!(r.nonce_tpm.len() >= NONCE_MIN && r.nonce_tpm.len() <= NONCE_LEN);
    }
    if let Ok(r) = parse_load(bytes) {
        assert!(inside(bytes, r.name) && r.name.len() <= NAME_LEN);
    }
    if let Ok(p) = parse_import(bytes) {
        assert!(inside(bytes, p) && p.len() <= MAX_PRIVATE);
    }
    let _ = parse_empty(bytes);
    let _ = parse_pcr_extend(bytes);
    let _ = parse_pcr_read(bytes);
}

const UNSEAL_MAX: usize = 120;

/// Unseal's parser over a buffer as long as a real response (117 bytes):
/// params, outData and the auth fields stay inside the input, and the hmac
/// has exactly the digest length the caller compares.
#[kani::proof]
#[kani::unwind(12)]
fn unseal_parse_is_total_and_in_bounds() {
    let buf: [u8; UNSEAL_MAX] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= UNSEAL_MAX);
    let bytes = buf.get(..len).unwrap_or(&[]);
    let r = parse_unseal(bytes);
    if let Ok(u) = r {
        assert!(inside(bytes, u.params) && inside(u.params, u.out_data));
        assert!(inside(bytes, u.auth.nonce) && inside(bytes, u.auth.hmac));
        assert!(u.auth.hmac.len() == DIGEST_LEN && u.auth.nonce.len() >= NONCE_MIN);
    }
}

const CMD_MAX: usize = 32;

/// Deny: a command code off the allowlist (any u32, PCR_Extend included)
/// is refused, whatever else the command holds, so no device write follows.
#[kani::proof]
#[kani::unwind(12)]
fn unlisted_command_codes_never_reach_the_device() {
    let mut buf: [u8; CMD_MAX] = kani::any();
    let len: usize = kani::any();
    kani::assume(len >= HEADER_LEN && len <= CMD_MAX);
    let cc: u32 = kani::any();
    kani::assume(!ALLOWED.contains(&cc));
    if let Some(field) = buf.get_mut(6..10) {
        field.copy_from_slice(&cc.to_be_bytes());
    }
    let client: usize = kani::any();
    kani::assume(client < gate::CLIENTS);
    let mut g = Gate::new();
    let r = g.command(client, buf.get(..len).unwrap_or(&[]));
    assert!(r == Err(Refusal::NotAllowed));
    assert!(g.state(client) == Some(gate::State::Fresh));
}

fn handle_rsp(handle: u32) -> [u8; 14] {
    let mut r = [0x80, 0x01, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 0];
    if let Some(h) = r.get_mut(10..14) {
        h.copy_from_slice(&handle.to_be_bytes());
    }
    r
}

const OK: [u8; 10] = [0x80, 0x01, 0, 0, 0, 10, 0, 0, 0, 0];

fn send(g: &mut Gate, client: usize, cmd: &[u8], rsp: &[u8]) -> bool {
    match g.command(client, cmd) {
        Ok(fwd) => {
            g.response(fwd, rsp);
            true
        }
        Err(_) => false,
    }
}

fn any_transient() -> u32 {
    let h: u32 = kani::any();
    kani::assume(h >> 24 == 0x80);
    h
}

fn any_policy_session() -> u32 {
    let h: u32 = kani::any();
    kani::assume(h >> 24 == 0x03);
    h
}

/// Builds one command of the flow, chosen by `which`, on handles
/// `primary`, `session` and `object`.
fn flow_command(buf: &mut [u8; MAX_LOAD_CMD_LEN], which: u8, primary: u32, session: u32, object: u32) -> usize {
    let n = match which {
        0 => start_auth_session(buf, primary, &[1; NONCE_LEN], &[2; POINT_LEN]),
        1 => policy_pcr(buf, session),
        2 => policy_auth_value(buf, session),
        3 => import(buf, primary, &[0; SEALED_PUBLIC_LEN], &[0; DUPLICATE_LEN], &[0; POINT_LEN]),
        4 => load(buf, primary, &[0; 4], &[0; SEALED_PUBLIC_LEN]),
        5 => unseal(buf, object, session, &[3; NONCE_LEN], 0x41, &[4; DIGEST_LEN]),
        6 => flush_context(buf, primary),
        7 => flush_context(buf, session),
        _ => flush_context(buf, object),
    };
    n.unwrap_or(0)
}

/// Owner's flow up to the loaded object: CreatePrimary, StartAuthSession,
/// PolicyPCR, PolicyAuthValue, Import, Load; true if all were forwarded.
fn owner_setup(g: &mut Gate, client: usize, primary: u32, session: u32, object: u32) -> bool {
    let mut buf = [0u8; MAX_LOAD_CMD_LEN];
    let n = create_primary(&mut buf).unwrap_or(0);
    let mut ok = send(g, client, buf.get(..n).unwrap_or(&[]), &handle_rsp(primary));
    let n = flow_command(&mut buf, 0, primary, session, object);
    ok &= send(g, client, buf.get(..n).unwrap_or(&[]), &handle_rsp(session));
    for which in [1u8, 2, 3] {
        let n = flow_command(&mut buf, which, primary, session, object);
        ok &= send(g, client, buf.get(..n).unwrap_or(&[]), &OK);
    }
    let n = flow_command(&mut buf, 4, primary, session, object);
    ok &= send(g, client, buf.get(..n).unwrap_or(&[]), &handle_rsp(object));
    ok
}

/// Allow: the owner's CreatePrimary → StartAuthSession → PolicyPCR →
/// PolicyAuthValue → Import → Load → Unseal → three flushes all pass, for
/// any handle values the TPM returns, and Done ends the flow.
#[kani::proof]
#[kani::unwind(12)]
fn the_owners_flow_is_forwarded() {
    let (primary, session, object) = (any_transient(), any_policy_session(), any_transient());
    kani::assume(primary != object);
    let client: usize = kani::any();
    kani::assume(client < gate::CLIENTS);
    let mut g = Gate::new();
    assert!(owner_setup(&mut g, client, primary, session, object));
    let mut buf = [0u8; MAX_LOAD_CMD_LEN];
    for which in [5u8, 8, 7, 6] {
        let n = flow_command(&mut buf, which, primary, session, object);
        assert!(send(&mut g, client, buf.get(..n).unwrap_or(&[]), &OK));
    }
    assert!(g.finish(client, true).is_ok());
    assert!(g.state(client) == Some(gate::State::Done));
}

/// Two distinct symbolic clients below `CLIENTS`: the owner and the other.
fn any_two_clients() -> (usize, usize) {
    let owner: usize = kani::any();
    let other: usize = kani::any();
    kani::assume(owner < gate::CLIENTS && other < gate::CLIENTS && owner != other);
    (owner, other)
}

/// Deny: a Fresh attacker is refused every handle-carrying command of the
/// flow on the owner's handles, PolicyAuthValue on its session included.
/// NotOwned is decided before Busy, so it is what the attacker gets while
/// the owner's flow is under way (M6 plan C12).
#[kani::proof]
#[kani::unwind(12)]
fn cross_client_handles_are_refused() {
    let (primary, session, object) = (any_transient(), any_policy_session(), any_transient());
    kani::assume(primary != object);
    let (owner, attacker) = any_two_clients();
    let mut g = Gate::new();
    kani::assume(owner_setup(&mut g, owner, primary, session, object));
    kani::cover!(true, "the owner's setup was forwarded");
    let which: u8 = kani::any();
    kani::assume(which <= 8);
    let mut buf = [0u8; MAX_LOAD_CMD_LEN];
    let n = flow_command(&mut buf, which, primary, session, object);
    let r = g.command(attacker, buf.get(..n).unwrap_or(&[]));
    assert!(r == Err(Refusal::NotOwned));
}

/// Deny: an attacker that starts after the owner finished without
/// flushing, and has a flow of its own under way, is refused the owner's
/// handles all the same.
#[kani::proof]
#[kani::unwind(12)]
fn a_later_attacker_is_refused_the_unflushed_handles_of_a_finished_owner() {
    let (primary, session, object) = (any_transient(), any_policy_session(), any_transient());
    kani::assume(primary != object);
    let (owner, attacker) = any_two_clients();
    let mut g = Gate::new();
    kani::assume(owner_setup(&mut g, owner, primary, session, object));
    kani::cover!(true, "the owner's setup was forwarded");
    let ok: bool = kani::any();
    assert!(g.finish(owner, ok).is_ok());
    let own = any_transient();
    kani::assume(own != primary && own != object);
    let mut buf = [0u8; MAX_LOAD_CMD_LEN];
    let n = create_primary(&mut buf).unwrap_or(0);
    assert!(send(&mut g, attacker, buf.get(..n).unwrap_or(&[]), &handle_rsp(own)));
    assert!(g.state(attacker) == Some(gate::State::Unsealing));
    let which: u8 = kani::any();
    kani::assume(which <= 8);
    let n = flow_command(&mut buf, which, primary, session, object);
    assert!(g.command(attacker, buf.get(..n).unwrap_or(&[])) == Err(Refusal::NotOwned));
}

/// Deny: a client that sent Done or Failed is refused any command bytes.
#[kani::proof]
#[kani::unwind(12)]
fn a_finished_client_is_refused() {
    let buf: [u8; CMD_MAX] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= CMD_MAX);
    let client: usize = kani::any();
    kani::assume(client < gate::CLIENTS);
    let ok: bool = kani::any();
    let mut g = Gate::new();
    assert!(g.finish(client, ok).is_ok());
    let r = g.command(client, buf.get(..len).unwrap_or(&[]));
    assert!(r == Err(Refusal::Finished));
}

/// Deny: the cap is withheld while any client has not finished, whichever
/// subset finished and however; it comes once every client is Done or
/// Failed.
#[kani::proof]
#[kani::unwind(12)]
fn the_cap_is_withheld_until_every_client_finishes() {
    let mut g = Gate::new();
    let mut cap = [0u8; PCR_EXTEND_CMD_LEN];
    let finished: [bool; gate::CLIENTS] = kani::any();
    for (client, done) in finished.iter().enumerate() {
        if *done {
            let ok: bool = kani::any();
            assert!(g.finish(client, ok).is_ok());
        }
    }
    let all = finished.iter().all(|f| *f);
    kani::cover!(!all, "some client has not finished");
    assert!(g.cap(&mut cap).is_some() == all);
    assert!(g.is_capped() == all);
    if !all {
        for (client, done) in finished.iter().enumerate() {
            if !*done {
                assert!(g.finish(client, true).is_ok());
            }
        }
        assert!(g.cap(&mut cap).is_some());
    }
}

/// Deny: once every client is finished the cap is issued, and Unseal is
/// refused from then on, by any client, even on a handle it owned.
#[kani::proof]
#[kani::unwind(12)]
fn unseal_after_the_cap_is_refused() {
    let (primary, session, object) = (any_transient(), any_policy_session(), any_transient());
    kani::assume(primary != object);
    let owner: usize = kani::any();
    kani::assume(owner < gate::CLIENTS);
    let mut g = Gate::new();
    kani::assume(owner_setup(&mut g, owner, primary, session, object));
    kani::cover!(true, "the owner's setup was forwarded");
    for client in 0..gate::CLIENTS {
        let ok: bool = kani::any();
        assert!(g.finish(client, ok).is_ok());
    }
    let mut cap = [0u8; PCR_EXTEND_CMD_LEN];
    assert!(g.cap(&mut cap).is_some());
    assert!(g.is_capped());
    let client: usize = kani::any();
    kani::assume(client < gate::CLIENTS);
    let mut buf = [0u8; MAX_LOAD_CMD_LEN];
    let n = flow_command(&mut buf, 5, primary, session, object);
    assert!(g.command(client, buf.get(..n).unwrap_or(&[])) == Err(Refusal::Capped));
}

/// One flow at a time (M6 plan C12): while the owner is Unsealing, a Fresh
/// client's well-formed first command (CreatePrimary or PCR_Read) is Busy
/// and leaves the gate, its once-bits and every state, exactly as it was;
/// once the owner has finished, the same client's whole setup is forwarded.
#[kani::proof]
#[kani::unwind(12)]
fn a_fresh_client_is_busy_without_effect_and_runs_after_the_owner_finishes() {
    let (owner, other) = any_two_clients();
    let owner_primary = any_transient();
    let mut g = Gate::new();
    let mut buf = [0u8; MAX_LOAD_CMD_LEN];
    let n = create_primary(&mut buf).unwrap_or(0);
    assert!(send(&mut g, owner, buf.get(..n).unwrap_or(&[]), &handle_rsp(owner_primary)));
    let first: bool = kani::any();
    let n = (if first { create_primary(&mut buf) } else { pcr_read(&mut buf) }).unwrap_or(0);
    let before = g.clone();
    assert!(g.command(other, buf.get(..n).unwrap_or(&[])) == Err(Refusal::Busy));
    assert!(g == before);
    let ok: bool = kani::any();
    assert!(g.finish(owner, ok).is_ok());
    let (primary, session, object) = (any_transient(), any_policy_session(), any_transient());
    kani::assume(primary != object && primary != owner_primary && object != owner_primary);
    assert!(owner_setup(&mut g, other, primary, session, object));
    assert!(g.state(other) == Some(gate::State::Unsealing));
}

/// Allow: a handle number client A flushed is client B's once the TPM hands
/// it to B (after A finished: one flow at a time), and a Fresh third client
/// is refused it as not its own.
#[kani::proof]
#[kani::unwind(12)]
fn a_flushed_handle_number_is_usable_by_the_other_client() {
    let primary = any_transient();
    let (a, b) = any_two_clients();
    let third: usize = kani::any();
    kani::assume(third < gate::CLIENTS && third != a && third != b);
    let mut g = Gate::new();
    let mut buf = [0u8; MAX_LOAD_CMD_LEN];
    let n = create_primary(&mut buf).unwrap_or(0);
    assert!(send(&mut g, a, buf.get(..n).unwrap_or(&[]), &handle_rsp(primary)));
    let n = flush_context(&mut buf, primary).unwrap_or(0);
    assert!(send(&mut g, a, buf.get(..n).unwrap_or(&[]), &OK));
    assert!(g.finish(a, true).is_ok());
    let n = create_primary(&mut buf).unwrap_or(0);
    assert!(send(&mut g, b, buf.get(..n).unwrap_or(&[]), &handle_rsp(primary)));
    let n = flow_command(&mut buf, 0, primary, 0, 0);
    let salted = buf.get(..n).unwrap_or(&[]);
    assert!(g.command(third, salted) == Err(Refusal::NotOwned));
    assert!(g.command(b, salted).is_ok());
}

/// PCR_Extend's success (a password session, no parameters) and a refusal
/// (TPM_RC_FAILURE).
const EXTEND_OK: [u8; 19] = [0x80, 0x02, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0];
const EXTEND_REFUSED: [u8; 10] = [0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x01];

/// A device whose attempts answer as its symbolic script says: nothing, a
/// refusal, or the success; `confirmed` records that it ever answered the
/// success.
struct ScriptedDevice {
    script: [u8; CAP_ATTEMPTS],
    next: usize,
    confirmed: bool,
}

impl CapTransport for ScriptedDevice {
    fn attempt(&mut self, _cmd: &[u8], _budget_ns: u64) -> Option<&[u8]> {
        let kind = self.script.get(self.next).copied().unwrap_or(0);
        self.next = self.next.saturating_add(1);
        match kind {
            0 => None,
            1 => Some(&EXTEND_REFUSED),
            _ => {
                self.confirmed = true;
                Some(&EXTEND_OK)
            }
        }
    }
}

/// The cap barrier (post-M6 plan P3): `cap_status` changes nothing, answers
/// a Done client only, and is never Confirmed unless every client finished
/// and the device confirmed the extend; whichever subset finished and
/// however, whether the cap ran or not, whatever the device answered.
#[kani::proof]
#[kani::unwind(12)]
fn cap_status_is_pure_and_never_confirmed_before_a_confirmed_extend() {
    let mut g = Gate::new();
    let finished: [bool; gate::CLIENTS] = kani::any();
    for (client, done) in finished.iter().enumerate() {
        if *done {
            let ok: bool = kani::any();
            assert!(g.finish(client, ok).is_ok());
        }
    }
    let mut device = ScriptedDevice { script: kani::any(), next: 0, confirmed: false };
    let ran: bool = kani::any();
    if ran {
        let _ = g.run_cap(&mut device);
    }
    let client: usize = kani::any();
    let before = g.clone();
    let status = g.cap_status(client);
    assert!(g == before);
    if status.is_ok() {
        assert!(g.state(client) == Some(gate::State::Done));
    }
    if status == Ok(CapStatus::Confirmed) {
        assert!(finished.iter().all(|f| *f));
        assert!(device.confirmed);
    }
    kani::cover!(status == Ok(CapStatus::Confirmed), "a confirmed cap");
    kani::cover!(status == Ok(CapStatus::Failed), "a failed cap");
    kani::cover!(status == Ok(CapStatus::Pending), "a pending cap");
}
