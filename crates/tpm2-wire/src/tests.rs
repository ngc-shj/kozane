#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

extern crate std;

use std::vec;
use std::vec::Vec;

use super::gate::{ALLOWED, CAP_DIGEST, CLIENTS, Gate, Refusal, State};
use super::*;

fn hex(s: &str) -> Vec<u8> {
    let s: std::string::String = s.split_whitespace().collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// swtpm 0.7.1's response to `create_primary` (captured 2026-10-23).
const SWTPM_CREATE_PRIMARY_RSP: &str = "
    8002 0000013a 00000000 80000000 00000123
    005a 0023000b00030472000000060080004300100003 0010
      0020 8bd421e2de8be9c3a63d461757bed28e9ce0c10b5b8c5c15aec38d7145832e35
      0020 e274ef70d764d4a20f1b52784cd9be8fdcd38e0d27bd7f8683e4d997fd8061f4
    0037 00000000 0020 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      01 0010 0004 40000001 0004 40000001 0000
    0020 5da041bac0ee3135aebb0cadfba497c6a1877fae832dd3d1f8f7a871b825e854
    8021 40000001 0040 f7fabc4f21eb70b72ca7cef25e2896afb8074d22e80309062fc45c47564c3d11
                       2aad65e8680f126a5ac7fcca73712f539dce5b4c26f638885bca8a9224074024
    0022 000b3b1d3345ce1690cff1b06c13ab5fd058379c77f2805ea4a4c889fd3f692a1c7a
    0000 01 0000";

#[test]
fn create_primary_is_the_command_swtpm_accepted() {
    let mut buf = [0u8; IPC_MSG_BYTES];
    let n = create_primary(&mut buf).unwrap();
    assert_eq!(n, CREATE_PRIMARY_CMD_LEN);
    assert_eq!(
        buf[..n],
        hex("8002 00000043 00000131 40000001 00000009 40000009 0000 01 0000
             0004 0000 0000 001a 0023000b00030472000000060080004300100003 0010 0000 0000 0000 00000000")[..]
    );
}

#[test]
fn every_builder_writes_its_documented_length_into_the_header() {
    let mut buf = [0u8; IPC_MSG_BYTES];
    let cases: [(Option<usize>, usize); 10] = [
        (create_primary(&mut buf), CREATE_PRIMARY_CMD_LEN),
        (start_auth_session(&mut buf, 0x8000_0000, &[1; 32], &[2; POINT_LEN]), START_AUTH_SESSION_CMD_LEN),
        (policy_pcr(&mut buf, 0x0300_0000), POLICY_PCR_CMD_LEN),
        (policy_auth_value(&mut buf, 0x0300_0000), POLICY_AUTH_VALUE_CMD_LEN),
        (import(&mut buf, 1, &[0; SEALED_PUBLIC_LEN], &[0; DUPLICATE_LEN], &[0; POINT_LEN]), IMPORT_CMD_LEN),
        (load(&mut buf, 1, &[0; MAX_PRIVATE], &[0; SEALED_PUBLIC_LEN]), MAX_LOAD_CMD_LEN),
        (unseal(&mut buf, 1, 2, &[3; 32], 0x41, &[4; 32]), UNSEAL_CMD_LEN),
        (flush_context(&mut buf, 1), FLUSH_CONTEXT_CMD_LEN),
        (pcr_read(&mut buf), PCR_READ_CMD_LEN),
        (pcr_extend(&mut buf, &[5; 32]), PCR_EXTEND_CMD_LEN),
    ];
    for (i, (got, want)) in cases.iter().enumerate() {
        assert_eq!(*got, Some(*want), "builder {i}");
    }
    let n = pcr_extend(&mut buf, &[5; 32]).unwrap();
    assert_eq!(u32::from_be_bytes(buf[2..6].try_into().unwrap()) as usize, n);
}

#[test]
fn builders_refuse_a_short_buffer_and_load_an_oversized_private() {
    let mut buf = [0u8; 40];
    assert_eq!(create_primary(&mut buf), None);
    let mut big = [0u8; IPC_MSG_BYTES];
    assert_eq!(load(&mut big, 1, &[0; MAX_PRIVATE + 1], &[0; SEALED_PUBLIC_LEN]), None);
}

#[test]
fn swtpm_create_primary_response_parses() {
    let rsp = hex(SWTPM_CREATE_PRIMARY_RSP);
    let r = parse_create_primary(&rsp).unwrap();
    assert_eq!(r.handle, 0x8000_0000);
    assert_eq!(r.public.len(), SRK_PUBLIC_LEN);
    assert!(srk_point(r.public).is_some());
    assert_eq!(r.name[..2], [0x00, 0x0B]);
}

#[test]
fn every_truncation_and_extension_of_a_response_is_refused() {
    let rsp = hex(SWTPM_CREATE_PRIMARY_RSP);
    for n in 0..rsp.len() {
        assert!(parse_create_primary(&rsp[..n]).is_err(), "truncated to {n}");
    }
    let mut longer = rsp.clone();
    longer.push(0);
    let size = longer.len() as u32;
    longer[2..6].copy_from_slice(&size.to_be_bytes());
    assert_eq!(parse_create_primary(&longer), Err(RspError::Malformed));
}

#[test]
fn response_header_checks_size_tag_and_error_codes() {
    assert_eq!(parse_empty(&hex("8001 0000000a 00000000")), Ok(()));
    assert_eq!(parse_empty(&hex("8001 0000000b 00000000")), Err(RspError::Size));
    assert_eq!(parse_empty(&hex("8002 0000000a 00000000")), Err(RspError::Tag));
    assert_eq!(parse_empty(&hex("8001 0000000a 0000099d")), Err(RspError::Tpm(0x99D)));
    // An error response with anything after the header is not one.
    assert_eq!(parse_empty(&hex("8001 0000000b 0000099d 00")), Err(RspError::Malformed));
    assert_eq!(parse_empty(&hex("8001 0000000b 00000000 00")), Err(RspError::Malformed));
    let mut long = vec![0u8; MAX_RESPONSE + 1];
    long[..10].copy_from_slice(&hex("8001 00000000 00000000"));
    long[2..6].copy_from_slice(&((MAX_RESPONSE + 1) as u32).to_be_bytes());
    assert_eq!(parse_empty(&long), Err(RspError::Size));
}

fn unseal_rsp(out_data: usize, nonce: usize, hmac: usize) -> Vec<u8> {
    let mut buf = [0u8; IPC_MSG_BYTES];
    let mut w = Writer::new(&mut buf);
    w.u16(ST_SESSIONS).unwrap();
    w.u32(0).unwrap();
    w.u32(0).unwrap();
    w.u32((2 + out_data) as u32).unwrap();
    w.tpm2b(&vec![7; out_data]).unwrap();
    w.tpm2b(&vec![8; nonce]).unwrap();
    w.u8(0x41).unwrap();
    w.tpm2b(&vec![9; hmac]).unwrap();
    let n = w.finish().unwrap();
    buf[..n].to_vec()
}

#[test]
fn unseal_response_exposes_params_and_auth_and_checks_their_lengths() {
    let rsp = unseal_rsp(32, 32, 32);
    let u = parse_unseal(&rsp).unwrap();
    assert_eq!((u.params.len(), u.out_data, u.auth.attributes), (34, &[7u8; 32][..], 0x41));
    assert_eq!((u.auth.nonce.len(), u.auth.hmac.len()), (32, 32));
    assert_eq!(parse_unseal(&unseal_rsp(32, 15, 32)), Err(RspError::Malformed));
    assert_eq!(parse_unseal(&unseal_rsp(32, 33, 32)), Err(RspError::Malformed));
    assert_eq!(parse_unseal(&unseal_rsp(32, 32, 31)), Err(RspError::Malformed));
    let mut bad_param_size = rsp.clone();
    bad_param_size[13] = 35;
    assert!(parse_unseal(&bad_param_size).is_err());
}

#[test]
fn start_auth_session_needs_a_nonce_of_at_least_sixteen_bytes() {
    let rsp = |n: usize| {
        let mut v = hex("8001 00000000 00000000 03000000");
        v.extend_from_slice(&(n as u16).to_be_bytes());
        v.extend(vec![1u8; n]);
        let len = v.len() as u32;
        v[2..6].copy_from_slice(&len.to_be_bytes());
        v
    };
    assert_eq!(parse_start_auth_session(&rsp(16)).unwrap().handle, 0x0300_0000);
    assert_eq!(parse_start_auth_session(&rsp(15)), Err(RspError::Malformed));
    assert_eq!(parse_start_auth_session(&rsp(33)), Err(RspError::Malformed));
}

#[test]
fn password_responses_must_have_an_empty_nonce_and_hmac() {
    let load = |nonce: &str| {
        let mut v = hex(&std::format!("8002 00000000 00000000 80000001 00000024 0022 {} {nonce} 01 0000", "00".repeat(34)));
        let len = v.len() as u32;
        v[2..6].copy_from_slice(&len.to_be_bytes());
        v
    };
    assert!(parse_load(&load("0000")).is_ok());
    assert_eq!(parse_load(&load("0001 aa")), Err(RspError::Malformed));
}

#[test]
fn pcr_read_requires_the_selection_it_asked_for() {
    let rsp = |sel: &str| {
        let mut v = hex(&std::format!("8001 00000000 00000000 00000005 {sel} 00000001 0020 {}", "ab".repeat(32)));
        let len = v.len() as u32;
        v[2..6].copy_from_slice(&len.to_be_bytes());
        v
    };
    assert_eq!(parse_pcr_read(&rsp("00000001 000b 03 000100")), Ok(&[0xAB; 32]));
    assert_eq!(parse_pcr_read(&rsp("00000001 000b 03 000200")), Err(RspError::Malformed));
}

#[test]
fn srk_point_and_sealed_policy_accept_only_their_shapes() {
    let mut public = SRK_PUBLIC_PREFIX.to_vec();
    public.extend_from_slice(&[0, 32]);
    public.extend_from_slice(&[1; 32]);
    public.extend_from_slice(&[0, 32]);
    public.extend_from_slice(&[2; 32]);
    assert_eq!(srk_point(&public), Some((&[1; 32], &[2; 32])));
    let mut rsa = public.clone();
    rsa[1] = 0x01;
    assert_eq!(srk_point(&rsa), None);
    assert_eq!(srk_point(&public[..public.len() - 1]), None);
    let mut sealed = [0u8; SEALED_PUBLIC_LEN];
    sealed_public(&mut sealed, &[3; 32], &[4; 32]).unwrap();
    assert_eq!(sealed_policy(&sealed), Some(&[3; 32]));
    let mut with_user = sealed;
    with_user[7] |= 0x40;
    assert_eq!(sealed_policy(&with_user), None);
}

// The gate (C9).

const OWNER: usize = 0;
const OTHER: usize = 1;
const THIRD: usize = 2;

fn cmd(f: impl FnOnce(&mut [u8]) -> Option<usize>) -> Vec<u8> {
    let mut buf = [0u8; IPC_MSG_BYTES];
    let n = f(&mut buf).unwrap();
    buf[..n].to_vec()
}

/// A success response with an output handle.
fn handle_rsp(handle: u32) -> Vec<u8> {
    let mut v = hex("8001 0000000e 00000000");
    v.extend_from_slice(&handle.to_be_bytes());
    v
}

const OK: [u8; 10] = [0x80, 0x01, 0, 0, 0, 10, 0, 0, 0, 0];

fn forward(g: &mut Gate, client: usize, c: &[u8], rsp: &[u8]) {
    let fwd = g.command(client, c).unwrap_or_else(|r| panic!("refused: {r:?}"));
    g.response(fwd, rsp);
}

/// Runs a client's flow through the gate up to the loaded object.
fn setup(g: &mut Gate, client: usize, primary: u32, session: u32, object: u32) {
    forward(g, client, &cmd(create_primary), &handle_rsp(primary));
    forward(g, client, &cmd(|b| start_auth_session(b, primary, &[1; 32], &[2; POINT_LEN])), &handle_rsp(session));
    forward(g, client, &cmd(|b| policy_pcr(b, session)), &OK);
    forward(g, client, &cmd(|b| policy_auth_value(b, session)), &OK);
    forward(g, client, &cmd(|b| import(b, primary, &[0; 78], &[0; 108], &[0; 68])), &OK);
    forward(g, client, &cmd(|b| load(b, primary, &[0; 126], &[0; 78])), &handle_rsp(object));
}

fn unseal_cmd(object: u32, session: u32) -> Vec<u8> {
    cmd(|b| unseal(b, object, session, &[3; 32], 0x41, &[4; 32]))
}

#[test]
fn the_owners_whole_flow_is_forwarded_and_done_ends_it() {
    let mut g = Gate::new();
    assert_eq!(g.state(OWNER), Some(State::Fresh));
    forward(&mut g, OWNER, &cmd(pcr_read), &OK);
    setup(&mut g, OWNER, 0x8000_0000, 0x0300_0000, 0x8000_0001);
    forward(&mut g, OWNER, &unseal_cmd(0x8000_0001, 0x0300_0000), &OK);
    for h in [0x8000_0001, 0x0300_0000, 0x8000_0000] {
        forward(&mut g, OWNER, &cmd(|b| flush_context(b, h)), &OK);
    }
    assert_eq!(g.state(OWNER), Some(State::Unsealing));
    g.finish(OWNER, true).unwrap();
    assert_eq!(g.state(OWNER), Some(State::Done));
}

#[test]
fn command_codes_off_the_allowlist_are_refused_pcr_extend_included() {
    let mut g = Gate::new();
    for cc in 0x100u32..0x200 {
        if ALLOWED.contains(&cc) {
            continue;
        }
        let mut c = cmd(|b| flush_context(b, 0x8000_0000));
        c[6..10].copy_from_slice(&cc.to_be_bytes());
        assert_eq!(g.command(OWNER, &c), Err(Refusal::NotAllowed), "cc {cc:#x}");
    }
    assert_eq!(g.command(OWNER, &cmd(|b| pcr_extend(b, &[0; 32]))), Err(Refusal::NotAllowed));
    assert_eq!(g.state(OWNER), Some(State::Fresh));
}

#[test]
fn the_other_clients_handles_are_refused_for_every_command() {
    let mut g = Gate::new();
    setup(&mut g, OWNER, 0x8000_0000, 0x0300_0000, 0x8000_0001);
    let (p, s, o) = (0x8000_0000, 0x0300_0000, 0x8000_0001);
    let attempts = [
        cmd(|b| start_auth_session(b, p, &[1; 32], &[2; POINT_LEN])),
        cmd(|b| policy_pcr(b, s)),
        cmd(|b| policy_auth_value(b, s)),
        cmd(|b| import(b, p, &[0; 78], &[0; 108], &[0; 68])),
        cmd(|b| load(b, p, &[0; 126], &[0; 78])),
        unseal_cmd(o, s),
        cmd(|b| flush_context(b, p)),
        cmd(|b| flush_context(b, s)),
        cmd(|b| flush_context(b, o)),
    ];
    for (i, c) in attempts.iter().enumerate() {
        assert_eq!(g.command(OTHER, c), Err(Refusal::NotOwned), "attempt {i}");
    }
}

#[test]
fn unseal_of_an_owned_object_with_the_other_clients_session_is_refused() {
    let mut g = Gate::new();
    setup(&mut g, OWNER, 0x8000_0000, 0x0300_0000, 0x8000_0001);
    // The owner finishes without flushing: its session is still recorded.
    g.finish(OWNER, false).unwrap();
    setup(&mut g, OTHER, 0x8000_0002, 0x0300_0001, 0x8000_0003);
    assert_eq!(g.command(OTHER, &unseal_cmd(0x8000_0003, 0x0300_0000)), Err(Refusal::NotOwned));
    assert!(g.command(OTHER, &unseal_cmd(0x8000_0003, 0x0300_0001)).is_ok());
}

#[test]
fn kinds_matter_a_session_is_not_a_parent_and_an_object_is_not_a_session() {
    let mut g = Gate::new();
    setup(&mut g, OWNER, 0x8000_0000, 0x0300_0000, 0x8000_0001);
    assert_eq!(g.command(OWNER, &cmd(|b| policy_pcr(b, 0x8000_0001))), Err(Refusal::NotOwned));
    assert_eq!(g.command(OWNER, &cmd(|b| import(b, 0x0300_0000, &[0; 78], &[0; 108], &[0; 68]))), Err(Refusal::NotOwned));
    assert_eq!(g.command(OWNER, &unseal_cmd(0x8000_0000, 0x0300_0000)), Err(Refusal::NotOwned));
}

#[test]
fn a_flushed_handle_number_belongs_to_whoever_gets_it_next() {
    let mut g = Gate::new();
    forward(&mut g, OWNER, &cmd(create_primary), &handle_rsp(0x8000_0000));
    forward(&mut g, OWNER, &cmd(|b| flush_context(b, 0x8000_0000)), &OK);
    g.finish(OWNER, true).unwrap();
    forward(&mut g, OTHER, &cmd(create_primary), &handle_rsp(0x8000_0000));
    let salted = cmd(|b| start_auth_session(b, 0x8000_0000, &[1; 32], &[2; POINT_LEN]));
    // The finished owner is refused before any ownership lookup; a Fresh
    // client is refused the reused number as not its own.
    assert_eq!(g.command(OWNER, &salted), Err(Refusal::Finished));
    assert_eq!(g.command(THIRD, &salted), Err(Refusal::NotOwned));
    assert!(g.command(OTHER, &salted).is_ok());
}

#[test]
fn a_failed_flush_keeps_the_entry() {
    let mut g = Gate::new();
    forward(&mut g, OWNER, &cmd(create_primary), &handle_rsp(0x8000_0000));
    forward(&mut g, OWNER, &cmd(|b| flush_context(b, 0x8000_0000)), &hex("8001 0000000a 0000018b"));
    assert!(g.command(OWNER, &cmd(|b| flush_context(b, 0x8000_0000))).is_ok());
}

#[test]
fn one_flow_per_client_repeats_are_refused() {
    let mut g = Gate::new();
    setup(&mut g, OWNER, 0x8000_0000, 0x0300_0000, 0x8000_0001);
    forward(&mut g, OWNER, &unseal_cmd(0x8000_0001, 0x0300_0000), &OK);
    assert_eq!(g.command(OWNER, &unseal_cmd(0x8000_0001, 0x0300_0000)), Err(Refusal::Repeated));
    assert_eq!(g.command(OWNER, &cmd(create_primary)), Err(Refusal::Repeated));
    let salted = cmd(|b| start_auth_session(b, 0x8000_0000, &[1; 32], &[2; POINT_LEN]));
    assert_eq!(g.command(OWNER, &salted), Err(Refusal::Repeated));
    assert_eq!(g.command(OWNER, &cmd(|b| load(b, 0x8000_0000, &[0; 126], &[0; 78]))), Err(Refusal::Repeated));
}

#[test]
fn a_finished_client_is_refused_everything_and_cannot_finish_twice() {
    let mut g = Gate::new();
    setup(&mut g, OWNER, 0x8000_0000, 0x0300_0000, 0x8000_0001);
    g.finish(OWNER, false).unwrap();
    assert_eq!(g.state(OWNER), Some(State::Failed));
    assert_eq!(g.command(OWNER, &cmd(|b| flush_context(b, 0x8000_0000))), Err(Refusal::Finished));
    assert_eq!(g.command(OWNER, &cmd(pcr_read)), Err(Refusal::Finished));
    assert_eq!(g.finish(OWNER, true), Err(Refusal::Finished));
    assert_eq!(g.command(CLIENTS, &cmd(pcr_read)), Err(Refusal::UnknownClient));
    assert_eq!(CLIENTS, 3);
}

#[test]
fn the_cap_comes_once_after_every_client_finishes_and_then_everything_is_refused() {
    let mut g = Gate::new();
    let mut buf = [0u8; IPC_MSG_BYTES];
    setup(&mut g, OWNER, 0x8000_0000, 0x0300_0000, 0x8000_0001);
    g.finish(OWNER, true).unwrap();
    assert_eq!(g.cap(&mut buf), None);
    g.finish(OTHER, false).unwrap();
    assert_eq!(g.cap(&mut buf), None, "the third client has not finished");
    g.finish(THIRD, true).unwrap();
    let n = g.cap(&mut buf).unwrap();
    assert_eq!(buf[..n], cmd(|b| pcr_extend(b, &CAP_DIGEST))[..]);
    assert!(g.is_capped());
    assert_eq!(g.cap(&mut buf), None);
    assert_eq!(g.command(OWNER, &unseal_cmd(0x8000_0001, 0x0300_0000)), Err(Refusal::Capped));
    assert_eq!(g.command(OTHER, &cmd(create_primary)), Err(Refusal::Capped));
    assert_eq!(g.command(THIRD, &cmd(pcr_read)), Err(Refusal::Capped));
}

#[test]
fn a_returned_handle_of_the_wrong_kind_or_already_taken_fails_the_client() {
    let mut g = Gate::new();
    forward(&mut g, OWNER, &cmd(create_primary), &handle_rsp(0x0300_0000));
    assert_eq!(g.state(OWNER), Some(State::Failed));
    let mut g = Gate::new();
    forward(&mut g, OWNER, &cmd(create_primary), &handle_rsp(0x8000_0000));
    g.finish(OWNER, true).unwrap();
    forward(&mut g, OTHER, &cmd(create_primary), &handle_rsp(0x8000_0000));
    assert_eq!(g.state(OTHER), Some(State::Failed));
    assert_eq!(g.state(OWNER), Some(State::Done));
    let mut g = Gate::new();
    forward(&mut g, OWNER, &cmd(create_primary), &OK);
    assert_eq!(g.state(OWNER), Some(State::Failed));
}

/// One flow at a time (M6 plan C12): for every ordered pair of distinct
/// clients, a Fresh `b` is told Busy while `a` is Unsealing, after every
/// validity and ownership refusal, with nothing recorded; once `a` has
/// finished, `b`'s flow runs.
#[test]
fn a_fresh_client_is_busy_while_any_other_is_unsealing_for_every_ordered_pair() {
    let mut pairs = 0;
    for a in 0..CLIENTS {
        for b in (0..CLIENTS).filter(|b| *b != a) {
            pairs += 1;
            let mut g = Gate::new();
            forward(&mut g, a, &cmd(create_primary), &handle_rsp(0x8000_0000));
            let before = g.clone();
            assert_eq!(g.command(b, &cmd(create_primary)), Err(Refusal::Busy), "{a} -> {b}");
            assert_eq!(g.command(b, &cmd(pcr_read)), Err(Refusal::Busy), "{a} -> {b}");
            assert_eq!(g.command(b, &cmd(|x| flush_context(x, 0x8000_0000))), Err(Refusal::NotOwned), "{a} -> {b}");
            assert_eq!(g.command(b, &cmd(|x| pcr_extend(x, &[0; 32]))), Err(Refusal::NotAllowed), "{a} -> {b}");
            let mut bound = cmd(create_primary);
            bound[13] = 0x0C; // the platform hierarchy
            assert_eq!(g.command(b, &bound), Err(Refusal::Hierarchy), "{a} -> {b}");
            assert!(g == before, "{a} -> {b}: Busy changed the gate");
            // The started flow is never Busy.
            forward(&mut g, a, &cmd(pcr_read), &OK);
            g.finish(a, true).unwrap();
            forward(&mut g, b, &cmd(create_primary), &handle_rsp(0x8000_0001));
            assert_eq!(g.state(b), Some(State::Unsealing), "{a} -> {b}");
        }
    }
    assert_eq!(pairs, 6);
}

#[test]
fn malformed_commands_are_refused() {
    let mut g = Gate::new();
    let mut c = cmd(create_primary);
    c[5] ^= 1; // size field
    assert_eq!(g.command(OWNER, &c), Err(Refusal::Malformed));
    let mut c = cmd(create_primary);
    c[1] = 0x01; // no-sessions tag on a command with sessions
    assert_eq!(g.command(OWNER, &c), Err(Refusal::Malformed));
    let mut c = cmd(create_primary);
    c[13] = 0x0C; // the platform hierarchy
    assert_eq!(g.command(OWNER, &c), Err(Refusal::Hierarchy));
    let mut c = cmd(create_primary);
    c[17] = 0; // an empty auth area
    assert_eq!(g.command(OWNER, &c), Err(Refusal::Malformed));
    assert_eq!(g.command(OWNER, &c[..9]), Err(Refusal::Malformed));
    forward(&mut g, OWNER, &cmd(create_primary), &handle_rsp(0x8000_0000));
    let mut bound = cmd(|b| start_auth_session(b, 0x8000_0000, &[1; 32], &[2; POINT_LEN]));
    bound[17] = 0x00; // bind = the owner's primary, not TPM_RH_NULL
    assert_eq!(g.command(OWNER, &bound), Err(Refusal::Hierarchy));
}

// The bolero target: every response parser on arbitrary bytes. None may
// panic, and whatever it returns lies inside the input.
fn inside(outer: &[u8], inner: &[u8]) -> bool {
    let (o, i) = (outer.as_ptr_range(), inner.as_ptr_range());
    inner.is_empty() || (o.start <= i.start && i.end <= o.end)
}

fn fuzz_one(bytes: &[u8]) {
    if let Ok(r) = parse_create_primary(bytes) {
        assert!(inside(bytes, r.public) && inside(bytes, r.name));
        assert!(r.public.len() <= SRK_PUBLIC_LEN && r.name.len() <= NAME_LEN);
    }
    if let Ok(r) = parse_start_auth_session(bytes) {
        assert!(inside(bytes, r.nonce_tpm) && (NONCE_MIN..=NONCE_LEN).contains(&r.nonce_tpm.len()));
    }
    if let Ok(p) = parse_import(bytes) {
        assert!(inside(bytes, p) && p.len() <= MAX_PRIVATE);
    }
    if let Ok(r) = parse_load(bytes) {
        assert!(inside(bytes, r.name) && r.name.len() <= NAME_LEN);
    }
    if let Ok(u) = parse_unseal(bytes) {
        assert!(inside(bytes, u.params) && inside(u.params, u.out_data));
        assert!(inside(bytes, u.auth.nonce) && u.auth.hmac.len() == DIGEST_LEN);
    }
    let _ = parse_pcr_read(bytes);
    let _ = parse_empty(bytes);
    let _ = parse_pcr_extend(bytes);
    for client in 0..CLIENTS {
        let mut g = Gate::new();
        if let Ok(fwd) = g.command(client, bytes) {
            assert!(ALLOWED.contains(&fwd.command_code()));
            g.response(fwd, bytes);
        }
    }
}

#[test]
fn fuzz_response_parsers_never_panic_and_stay_in_bounds() {
    bolero::check!().for_each(fuzz_one);
}
