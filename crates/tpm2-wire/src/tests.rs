#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

extern crate std;

use std::vec;
use std::vec::Vec;

use super::gate::{
    ALLOWED, CAP_ATTEMPT_DEADLINE_NS, CAP_ATTEMPTS, CAP_DIGEST, CLIENTS, CapStatus, CapTransport, CapVerdict, Gate,
    POLICY_COMMANDS, PolicyPhase, PolicyRefusal, PolicyState, PolicyTransport, REFUSED, Refusal, State,
};
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
    let cases: [(Option<usize>, usize); 14] = [
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
        (slot_pcr_read(&mut buf), PCR_READ_CMD_LEN),
        (nv_read_public(&mut buf, NV_POLICY_CTR), NV_READ_PUBLIC_CMD_LEN),
        (nv_read(&mut buf, NV_POLICY_CTR), NV_READ_CMD_LEN),
        (nv_increment(&mut buf, NV_POLICY_CTR), NV_INCREMENT_CMD_LEN),
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

#[test]
fn the_policy_state_commands_are_the_documented_bytes() {
    assert_eq!(cmd(|b| nv_read_public(b, NV_POLICY_CTR)), hex("8001 0000000e 00000169 01500100"));
    // authHandle = the index (AUTHREAD), the empty password, 8 bytes at 0.
    assert_eq!(
        cmd(|b| nv_read(b, NV_POLICY_BASE)),
        hex("8002 00000023 0000014e 01500101 01500101 00000009 40000009 0000 01 0000 0008 0000")
    );
    assert_eq!(
        cmd(|b| nv_increment(b, NV_POLICY_CTR)),
        hex("8002 0000001f 00000134 01500100 01500100 00000009 40000009 0000 01 0000")
    );
    assert_eq!(cmd(slot_pcr_read), hex("8001 00000014 0000017e 00000001 000b 03 000200"));
}

#[test]
fn nv_public_is_the_marshalled_tpms_nv_public() {
    let mut out = [0u8; NV_PUBLIC_LEN];
    let attributes = NV_BASE_ATTRIBUTES | NV_WRITTEN | NV_WRITELOCKED;
    nv_public(&mut out, NV_POLICY_BASE, attributes, &[0xAB; 32], NV_DATA_SIZE).unwrap();
    assert_eq!(out[..], hex(&std::format!("01500101 000b 62042c04 0020 {} 0008", "ab".repeat(32)))[..]);
}

/// A response: `tag`, then `body`, the size filled in.
fn rsp_of(tag: &str, body: &str) -> Vec<u8> {
    let mut v = hex(&std::format!("{tag} 00000000 00000000 {body}"));
    let len = v.len() as u32;
    v[2..6].copy_from_slice(&len.to_be_bytes());
    v
}

fn nv_public_rsp(public: &[u8], name: &[u8]) -> Vec<u8> {
    let enc = |b: &[u8]| {
        let digits: std::string::String = b.iter().map(|x| std::format!("{x:02x}")).collect();
        std::format!("{:04x} {digits}", b.len())
    };
    rsp_of("8001", &std::format!("{} {}", enc(public), enc(name)))
}

fn nv_read_rsp(value: u64) -> Vec<u8> {
    rsp_of("8002", &std::format!("0000000a 0008 {value:016x} 0000 01 0000"))
}

fn pcr9_rsp(digest: &[u8; 32]) -> Vec<u8> {
    let d: std::string::String = digest.iter().map(|x| std::format!("{x:02x}")).collect();
    rsp_of("8001", &std::format!("00000007 00000001 000b 03 000200 00000001 0020 {d}"))
}

const NV_INCREMENT_OK: &str = "8002 00000013 00000000 00000000 0000 01 0000";

fn public_of(index: u32) -> [u8; NV_PUBLIC_LEN] {
    let mut out = [0u8; NV_PUBLIC_LEN];
    nv_public(&mut out, index, NV_CTR_ATTRIBUTES | NV_WRITTEN, &[0xAB; 32], NV_DATA_SIZE).unwrap();
    out
}

#[test]
fn nv_read_public_returns_the_public_area_and_the_name() {
    let public = public_of(NV_POLICY_CTR);
    let rsp = nv_public_rsp(&public, &CTR_NAME);
    let r = parse_nv_read_public(&rsp).unwrap();
    assert_eq!((r.public, r.name), (&public[..], &CTR_NAME[..]));
    assert_eq!(parse_nv_read_public(&nv_public_rsp(&public, &[0; NAME_LEN + 1])), Err(RspError::Malformed), "a long Name");
    assert_eq!(parse_nv_read_public(&nv_public_rsp(&[0; MAX_NV_PUBLIC + 1], &CTR_NAME)), Err(RspError::Malformed));
    let ok = nv_public_rsp(&public, &CTR_NAME);
    for n in 0..ok.len() {
        assert!(parse_nv_read_public(&ok[..n]).is_err(), "truncated to {n}");
    }
    let mut extra = ok.clone();
    extra.push(0);
    extra[5] += 1;
    assert_eq!(parse_nv_read_public(&extra), Err(RspError::Malformed));
}

#[test]
fn nv_read_takes_exactly_eight_bytes_from_a_password_session() {
    assert_eq!(parse_nv_read(&nv_read_rsp(0x0102_0304_0506_0708)), Ok(0x0102_0304_0506_0708));
    assert_eq!(parse_nv_read(&rsp_of("8002", "00000009 0007 01020304050607 0000 01 0000")), Err(RspError::Malformed));
    assert_eq!(parse_nv_read(&rsp_of("8002", "0000000b 0009 010203040506070809 0000 01 0000")), Err(RspError::Malformed));
    assert_eq!(parse_nv_read(&rsp_of("8002", "0000000a 0008 0102030405060708 0001 aa 01 0000")), Err(RspError::Malformed));
    assert_eq!(parse_nv_read(&hex("8001 0000000a 0000014a")), Err(RspError::Tpm(0x14A)));
}

#[test]
fn nv_increment_succeeds_only_without_parameters() {
    assert_eq!(parse_nv_increment(&hex(NV_INCREMENT_OK)), Ok(()));
    assert_eq!(parse_nv_increment(&rsp_of("8002", "00000001 00 0000 01 0000")), Err(RspError::Malformed));
    assert_eq!(parse_nv_increment(&hex("8001 0000000a 0000018b")), Err(RspError::Tpm(0x18B)));
}

#[test]
fn the_pcr9_read_requires_the_pcr9_selection() {
    assert_eq!(parse_slot_pcr_read(&pcr9_rsp(&[0x99; 32])), Ok(&[0x99; 32]));
    let pcr8 = rsp_of("8001", &std::format!("00000007 00000001 000b 03 000100 00000001 0020 {}", "99".repeat(32)));
    assert_eq!(parse_slot_pcr_read(&pcr8), Err(RspError::Malformed));
    assert_eq!(parse_pcr_read(&pcr9_rsp(&[0x99; 32])), Err(RspError::Malformed), "the cap's read refuses PCR 9");
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

/// PCR_Extend's success: a password session, no parameters.
const EXTEND_OK: &str = "8002 00000013 00000000 00000000 0000 01 0000";
/// TPM_RC_FAILURE.
const EXTEND_REFUSED: &str = "8001 0000000a 00000101";

/// A device answering each attempt as scripted (None: no response within
/// the attempt's deadline); past the script, nothing.
struct Device {
    script: Vec<Option<Vec<u8>>>,
    /// The command and budget of every attempt.
    calls: Vec<(Vec<u8>, u64)>,
    rsp: Vec<u8>,
}

impl Device {
    fn new(script: Vec<Option<Vec<u8>>>) -> Self {
        Device { script, calls: Vec::new(), rsp: Vec::new() }
    }
}

impl CapTransport for Device {
    fn attempt(&mut self, cmd: &[u8], budget_ns: u64) -> Option<&[u8]> {
        let next = self.script.get(self.calls.len()).cloned().flatten();
        self.calls.push((cmd.to_vec(), budget_ns));
        self.rsp = next?;
        Some(&self.rsp)
    }
}

fn all_finished() -> Gate {
    let mut g = Gate::new();
    for c in 0..CLIENTS {
        g.finish(c, true).unwrap();
    }
    g
}

#[test]
fn the_cap_is_confirmed_by_the_attempt_that_succeeds_after_two_failures() {
    let mut g = all_finished();
    let mut d = Device::new(vec![None, Some(hex(EXTEND_REFUSED)), Some(hex(EXTEND_OK))]);
    assert_eq!(g.run_cap(&mut d), Some(CapVerdict::Confirmed));
    let want = cmd(|b| pcr_extend(b, &CAP_DIGEST));
    assert_eq!(d.calls, vec![(want, CAP_ATTEMPT_DEADLINE_NS); 3], "three attempts, each with the attempt deadline");
    assert_eq!(g.cap_status(OWNER), Ok(CapStatus::Confirmed));
}

#[test]
fn the_cap_fails_after_cap_attempts_failures_and_tries_no_more() {
    let mut g = all_finished();
    // A success past the last attempt is never asked for.
    let mut script = vec![None; CAP_ATTEMPTS];
    script.push(Some(hex(EXTEND_OK)));
    let mut d = Device::new(script);
    assert_eq!(g.run_cap(&mut d), Some(CapVerdict::Failed));
    assert_eq!(d.calls.len(), CAP_ATTEMPTS);
    assert!(g.is_capped(), "capped whatever the device answered");
    assert_eq!(g.cap_status(OWNER), Ok(CapStatus::Failed));
}

#[test]
fn a_transport_error_a_nonzero_rc_and_a_short_response_each_fail_an_attempt() {
    let ok = hex(EXTEND_OK);
    let failures = [None, Some(hex(EXTEND_REFUSED)), Some(ok[..ok.len() - 1].to_vec())];
    for (i, f) in failures.iter().enumerate() {
        let mut g = all_finished();
        assert_eq!(g.run_cap(&mut Device::new(vec![f.clone(); CAP_ATTEMPTS])), Some(CapVerdict::Failed), "failure {i}");
        let mut g = all_finished();
        let mut d = Device::new(vec![f.clone(), Some(ok.clone())]);
        assert_eq!(g.run_cap(&mut d), Some(CapVerdict::Confirmed), "failure {i}, then success");
        assert_eq!(d.calls.len(), 2, "failure {i}");
    }
}

#[test]
fn a_cap_not_due_gives_no_verdict_and_calls_no_device() {
    let mut g = Gate::new();
    g.finish(OWNER, true).unwrap();
    let mut d = Device::new(vec![Some(hex(EXTEND_OK))]);
    assert_eq!(g.run_cap(&mut d), None);
    assert!(d.calls.is_empty() && !g.is_capped());
    assert_eq!(g.cap_status(OWNER), Ok(CapStatus::Pending));
    // Once run, the cap is not due again.
    let mut g = all_finished();
    assert_eq!(g.run_cap(&mut Device::new(vec![None; CAP_ATTEMPTS])), Some(CapVerdict::Failed));
    let mut d = Device::new(vec![Some(hex(EXTEND_OK))]);
    assert_eq!(g.run_cap(&mut d), None);
    assert!(d.calls.is_empty());
    assert_eq!(g.cap_status(OWNER), Ok(CapStatus::Failed), "the first verdict stays");
}

#[test]
fn cap_status_answers_done_clients_only_and_changes_nothing() {
    let mut g = Gate::new();
    forward(&mut g, 1, &cmd(create_primary), &handle_rsp(0x8000_0000));
    g.finish(2, false).unwrap();
    g.finish(OWNER, true).unwrap();
    let before = g.clone();
    assert_eq!(g.cap_status(OWNER), Ok(CapStatus::Pending));
    assert_eq!(g.cap_status(1), Err(Refusal::NotDone), "Unsealing");
    assert_eq!(g.cap_status(2), Err(Refusal::NotDone), "Failed");
    assert_eq!(g.cap_status(CLIENTS), Err(Refusal::UnknownClient));
    assert!(g == before, "cap_status changed the gate");
    assert_eq!(Gate::new().cap_status(OWNER), Err(Refusal::NotDone), "Fresh");
    // A gate capped without a device has no verdict: Pending stays.
    let mut g = all_finished();
    let mut out = [0u8; PCR_EXTEND_CMD_LEN];
    assert!(g.cap(&mut out).is_some());
    assert_eq!(g.cap_status(OWNER), Ok(CapStatus::Pending));
}

// The policy client (M8 plan C3).

const CTR_NAME: [u8; NAME_LEN] = name_of(0x11);
const BASE_NAME: [u8; NAME_LEN] = name_of(0x22);

const fn name_of(fill: u8) -> [u8; NAME_LEN] {
    let mut n = [fill; NAME_LEN];
    n[0] = 0x00;
    n[1] = 0x0B;
    n
}

fn policy_gate() -> Gate {
    Gate::with_policy(true, CTR_NAME, BASE_NAME)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// No response.
    Silent,
    /// TPM_RC_FAILURE.
    Error,
    /// The right response less its last byte.
    Short,
}

/// The two indices and PCR 9 on a device that answers every command of
/// `POLICY_COMMANDS` as a TPM would, and records what it was sent.
struct Nv {
    counter: u64,
    base: u64,
    names: [[u8; NAME_LEN]; 2],
    pcr9: [u8; 32],
    /// The command code and first handle of every command sent.
    seen: Vec<(u32, u32)>,
    /// The call (by its index in `seen`) that fails, and how.
    fault: Option<(usize, Fault)>,
    rsp: Vec<u8>,
}

impl Nv {
    fn new(counter: u64, base: u64) -> Self {
        let names = [CTR_NAME, BASE_NAME];
        Nv { counter, base, names, pcr9: [0x99; 32], seen: Vec::new(), fault: None, rsp: Vec::new() }
    }

    fn increments(&self) -> usize {
        self.seen.iter().filter(|(cc, _)| *cc == CC_NV_INCREMENT).count()
    }
}

impl PolicyTransport for Nv {
    fn transact(&mut self, sent: &[u8]) -> Option<&[u8]> {
        let cc = u32::from_be_bytes(sent[6..10].try_into().unwrap());
        let handle = u32::from_be_bytes(sent[10..14].try_into().unwrap());
        assert!(POLICY_COMMANDS.contains(&cc), "a command outside the policy set: {cc:#x}");
        self.seen.push((cc, handle));
        let slot = |h: u32| {
            [NV_POLICY_CTR, NV_POLICY_BASE]
                .iter()
                .position(|i| *i == h)
                .unwrap_or_else(|| panic!("an NV handle off the two indices: {h:#x}"))
        };
        let mut rsp = match cc {
            CC_NV_READ_PUBLIC => nv_public_rsp(&public_of(handle), &self.names[slot(handle)]),
            CC_NV_READ => nv_read_rsp(if slot(handle) == 0 { self.counter } else { self.base }),
            CC_NV_INCREMENT => {
                assert_eq!(slot(handle), 0, "an increment of the base");
                self.counter += 1;
                hex(NV_INCREMENT_OK)
            }
            _ => {
                assert_eq!(sent, &cmd(slot_pcr_read)[..], "a PCR read other than PCR 9's");
                pcr9_rsp(&self.pcr9)
            }
        };
        match self.fault {
            Some((at, f)) if at == self.seen.len() - 1 => match f {
                Fault::Silent => return None,
                Fault::Error => rsp = hex("8001 0000000a 00000101"),
                Fault::Short => {
                    rsp.pop();
                }
            },
            _ => {}
        }
        self.rsp = rsp;
        Some(&self.rsp)
    }
}

/// What State sends, in order.
const STATE_SEQUENCE: [(u32, u32); 5] = [
    (CC_NV_READ_PUBLIC, NV_POLICY_CTR),
    (CC_NV_READ_PUBLIC, NV_POLICY_BASE),
    (CC_NV_READ, NV_POLICY_CTR),
    (CC_NV_READ, NV_POLICY_BASE),
    (CC_PCR_READ, 0x0000_0001),
];

#[test]
fn a_gate_without_policy_refuses_every_policy_operation_and_caps_as_before() {
    for mut g in [Gate::new(), Gate::with_policy(false, CTR_NAME, BASE_NAME)] {
        let mut nv = Nv::new(7, 0);
        assert_eq!(g.policy_state(&mut nv), Err(PolicyRefusal::Absent));
        assert_eq!(g.policy_advance(0, &mut nv), Err(PolicyRefusal::Absent));
        assert_eq!(g.policy_finish(), Err(PolicyRefusal::Absent));
        assert!(nv.seen.is_empty());
        let mut buf = [0u8; PCR_EXTEND_CMD_LEN];
        for c in 0..CLIENTS {
            assert_eq!(g.cap(&mut buf), None);
            g.finish(c, true).unwrap();
        }
        assert!(g.cap(&mut buf).is_some(), "the M7 cap: every raw client finished");
        assert_eq!(g.policy_state(&mut nv), Err(PolicyRefusal::Absent));
    }
}

#[test]
fn state_checks_both_names_reads_both_values_and_pcr9() {
    let mut g = policy_gate();
    let mut nv = Nv::new(1007, 1000);
    assert_eq!(g.policy_state(&mut nv), Ok(PolicyState { current: 7, pcr9: [0x99; 32] }));
    assert_eq!(nv.seen, STATE_SEQUENCE);
    assert_eq!(g.policy_phase(), PolicyPhase::Stated);
}

#[test]
fn a_wrong_name_of_either_index_refuses_state_before_any_read() {
    for which in 0..2 {
        let mut g = policy_gate();
        let mut nv = Nv::new(7, 0);
        nv.names[which][NAME_LEN - 1] ^= 1;
        assert_eq!(g.policy_state(&mut nv), Err(PolicyRefusal::Name), "index {which}");
        assert_eq!(nv.seen, STATE_SEQUENCE[..=which], "index {which}");
        assert_eq!(g.policy_phase(), PolicyPhase::Spent);
    }
}

#[test]
fn an_all_zero_expected_name_refuses_without_asking_the_device() {
    for (ctr, base) in [([0; NAME_LEN], BASE_NAME), (CTR_NAME, [0; NAME_LEN])] {
        let mut g = Gate::with_policy(true, ctr, base);
        let mut nv = Nv::new(7, 0);
        nv.names = [ctr, base];
        assert_eq!(g.policy_state(&mut nv), Err(PolicyRefusal::Name));
        assert!(nv.seen.len() <= 1, "the zero Name was looked up");
    }
}

#[test]
fn the_version_is_the_wrapping_difference_and_one_above_u32_max_is_refused() {
    // Provisioning sets base = counter - v0, wrapping (M8 plan D2).
    let mut g = policy_gate();
    assert_eq!(g.policy_state(&mut Nv::new(3, 3u64.wrapping_sub(9))).map(|s| s.current), Ok(9));
    let mut g = policy_gate();
    assert_eq!(g.policy_state(&mut Nv::new(u64::from(u32::MAX) + 5, 5)).map(|s| s.current), Ok(u32::MAX));
    let mut g = policy_gate();
    assert_eq!(g.policy_state(&mut Nv::new(u64::from(u32::MAX) + 6, 5)), Err(PolicyRefusal::Range));
    let mut g = policy_gate();
    assert_eq!(g.policy_state(&mut Nv::new(4, 5)), Err(PolicyRefusal::Range), "a counter below its base");
}

#[test]
fn every_device_failure_refuses_state_and_spends_it() {
    for at in 0..STATE_SEQUENCE.len() {
        for f in [Fault::Silent, Fault::Error, Fault::Short] {
            let mut g = policy_gate();
            let mut nv = Nv::new(7, 0);
            nv.fault = Some((at, f));
            assert_eq!(g.policy_state(&mut nv), Err(PolicyRefusal::Device), "{at} {f:?}");
            assert_eq!(nv.seen.len(), at + 1, "{at} {f:?}: asked on after a failure");
            assert_eq!(g.policy_advance(7, &mut nv), Err(PolicyRefusal::Order), "{at} {f:?}");
            assert_eq!(nv.increments(), 0);
            assert_eq!(g.policy_finish(), Ok(()));
        }
    }
}

#[test]
fn advance_increments_once_when_the_version_is_the_expected_one() {
    let mut g = policy_gate();
    let mut nv = Nv::new(1007, 1000);
    g.policy_state(&mut nv).unwrap();
    nv.seen.clear();
    assert_eq!(g.policy_advance(7, &mut nv), Ok(8));
    assert_eq!(nv.increments(), 1);
    assert_eq!(nv.seen[4], (CC_NV_INCREMENT, NV_POLICY_CTR));
    assert_eq!(nv.seen.len(), 9, "re-read, increment, re-read");
    assert_eq!((nv.counter, nv.base), (1008, 1000));
    assert_eq!(g.policy_phase(), PolicyPhase::Spent);
}

#[test]
fn a_stale_advance_is_refused_without_an_increment() {
    for expected in [6, 8, u32::MAX] {
        let mut g = policy_gate();
        let mut nv = Nv::new(7, 0);
        g.policy_state(&mut nv).unwrap();
        assert_eq!(g.policy_advance(expected, &mut nv), Err(PolicyRefusal::Stale), "{expected}");
        assert_eq!(nv.increments(), 0);
        assert_eq!(g.policy_advance(7, &mut nv), Err(PolicyRefusal::Order), "a stale Advance is spent");
    }
}

#[test]
fn a_second_state_a_second_advance_and_an_advance_before_state_are_refused() {
    let mut g = policy_gate();
    let mut nv = Nv::new(7, 0);
    assert_eq!(g.policy_advance(7, &mut nv), Err(PolicyRefusal::Order), "before State");
    assert!(nv.seen.is_empty());
    g.policy_state(&mut nv).unwrap();
    assert_eq!(g.policy_state(&mut nv), Err(PolicyRefusal::Order));
    assert_eq!(g.policy_advance(7, &mut nv), Ok(8));
    let sent = nv.seen.len();
    assert_eq!(g.policy_advance(8, &mut nv), Err(PolicyRefusal::Order));
    assert_eq!(g.policy_state(&mut nv), Err(PolicyRefusal::Order));
    assert_eq!((nv.seen.len(), nv.increments()), (sent, 1), "one increment per boot");
}

#[test]
fn every_device_failure_refuses_advance_with_at_most_its_one_increment() {
    for at in 0..9 {
        for f in [Fault::Silent, Fault::Error, Fault::Short] {
            let mut g = policy_gate();
            let mut nv = Nv::new(7, 0);
            g.policy_state(&mut nv).unwrap();
            nv.seen.clear();
            nv.fault = Some((at, f));
            assert_eq!(g.policy_advance(7, &mut nv), Err(PolicyRefusal::Device), "{at} {f:?}");
            assert_eq!(nv.increments(), usize::from(at >= 4), "{at} {f:?}");
            assert_eq!(g.policy_advance(7, &mut nv), Err(PolicyRefusal::Order));
        }
    }
}

#[test]
fn done_or_failed_ends_the_policy_client() {
    for stated in [false, true] {
        let mut g = policy_gate();
        let mut nv = Nv::new(7, 0);
        if stated {
            g.policy_state(&mut nv).unwrap();
        }
        assert_eq!(g.policy_finish(), Ok(()));
        assert_eq!(g.policy_phase(), PolicyPhase::Finished);
        let sent = nv.seen.len();
        assert_eq!(g.policy_state(&mut nv), Err(PolicyRefusal::Finished));
        assert_eq!(g.policy_advance(7, &mut nv), Err(PolicyRefusal::Finished));
        assert_eq!(g.policy_finish(), Err(PolicyRefusal::Finished));
        assert_eq!(nv.seen.len(), sent);
    }
}

#[test]
fn the_cap_waits_for_the_policy_client_when_it_is_present_and_then_refuses_it() {
    let mut g = policy_gate();
    let mut buf = [0u8; PCR_EXTEND_CMD_LEN];
    for c in 0..CLIENTS {
        g.finish(c, true).unwrap();
    }
    assert_eq!(g.cap(&mut buf), None, "the policy client has not finished");
    let mut nv = Nv::new(7, 0);
    g.policy_state(&mut nv).unwrap();
    assert_eq!(g.cap(&mut buf), None);
    g.policy_finish().unwrap();
    assert!(g.cap(&mut buf).is_some());
    let sent = nv.seen.len();
    assert_eq!(g.policy_state(&mut nv), Err(PolicyRefusal::Capped));
    assert_eq!(g.policy_advance(7, &mut nv), Err(PolicyRefusal::Capped));
    assert_eq!(g.policy_finish(), Err(PolicyRefusal::Capped));
    assert_eq!(nv.seen.len(), sent);
    // The policy client finishing first: the raw clients still hold the cap.
    let mut g = policy_gate();
    g.policy_finish().unwrap();
    assert_eq!(g.cap(&mut buf), None);
}

#[test]
fn policy_operations_interleave_with_a_raw_flow() {
    let mut g = policy_gate();
    setup(&mut g, OWNER, 0x8000_0000, 0x0300_0000, 0x8000_0001);
    let mut nv = Nv::new(7, 0);
    assert!(g.policy_state(&mut nv).is_ok());
    assert_eq!(g.state(OWNER), Some(State::Unsealing));
    forward(&mut g, OWNER, &unseal_cmd(0x8000_0001, 0x0300_0000), &OK);
    assert!(g.policy_advance(7, &mut nv).is_ok());
}

/// I3.2: every command of the refused set, on the policy indices or any
/// other handle, is refused for every raw client and changes nothing.
#[test]
fn the_refused_set_is_refused_for_every_raw_client() {
    for cc in REFUSED {
        assert!(!ALLOWED.contains(&cc), "{cc:#x}");
        for handle in [NV_POLICY_CTR, NV_POLICY_BASE, 0x4000_000C] {
            let mut c = cmd(|b| nv_increment(b, handle));
            c[6..10].copy_from_slice(&cc.to_be_bytes());
            for client in 0..CLIENTS {
                let mut g = Gate::new();
                assert_eq!(g.command(client, &c), Err(Refusal::NotAllowed), "{cc:#x} {handle:#x} {client}");
                assert!(g == Gate::new());
            }
        }
    }
    let named = [
        CC_NV_INCREMENT,
        CC_NV_READ,
        CC_NV_UNDEFINE_SPACE,
        CC_NV_UNDEFINE_SPACE_SPECIAL,
        CC_NV_WRITE,
        CC_NV_WRITE_LOCK,
        CC_NV_DEFINE_SPACE,
        CC_CLEAR,
        CC_HIERARCHY_CHANGE_AUTH,
    ];
    assert!(named.iter().all(|cc| REFUSED.contains(cc)));
    // The policy client's own commands are refused to raw clients too.
    let mut g = Gate::new();
    assert_eq!(g.command(OWNER, &cmd(|b| nv_read_public(b, NV_POLICY_CTR))), Err(Refusal::NotAllowed));
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
    if let Ok(r) = parse_nv_read_public(bytes) {
        assert!(inside(bytes, r.public) && inside(bytes, r.name));
        assert!(r.public.len() <= MAX_NV_PUBLIC && r.name.len() <= NAME_LEN);
    }
    let _ = parse_nv_read(bytes);
    let _ = parse_nv_increment(bytes);
    let _ = parse_slot_pcr_read(bytes);
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
