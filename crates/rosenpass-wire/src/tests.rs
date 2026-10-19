#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

extern crate std;

use super::*;

/// Messages captured from upstream rosenpass 9e72f1eb (tools/rp-vectors).
const CORPUS: &str = "src/__fuzz__/tests__parsers_never_panic_and_round_trip/corpus";
const UPSTREAM_INIT_HELLO: &[u8] =
    include_bytes!("__fuzz__/tests__parsers_never_panic_and_round_trip/corpus/seed-init-hello");
const UPSTREAM_RESP_HELLO: &[u8] =
    include_bytes!("__fuzz__/tests__parsers_never_panic_and_round_trip/corpus/seed-resp-hello");
const UPSTREAM_INIT_CONF: &[u8] =
    include_bytes!("__fuzz__/tests__parsers_never_panic_and_round_trip/corpus/seed-init-conf");
const UPSTREAM_EMPTY_DATA: &[u8] =
    include_bytes!("__fuzz__/tests__parsers_never_panic_and_round_trip/corpus/seed-empty-data");

fn init_hello() -> InitHello {
    InitHello {
        sidi: [1, 2, 3, 4],
        epki: [0x11; EPK_LEN],
        sctr: [0x22; SCT_LEN],
        pidi_ct: [0x33; PIDI_CT_LEN],
        auth: [0x44; TAG_LEN],
        mac: [0x55; MAC_LEN],
        cookie: [0x66; COOKIE_LEN],
    }
}

fn resp_hello() -> RespHello {
    RespHello {
        sidr: [5, 6, 7, 8],
        sidi: [1, 2, 3, 4],
        ecti: [0x11; ECT_LEN],
        scti: [0x22; SCT_LEN],
        auth: [0x33; TAG_LEN],
        biscuit_ct: [0x44; BISCUIT_CT_LEN],
        mac: [0x55; MAC_LEN],
        cookie: [0x66; COOKIE_LEN],
    }
}

fn init_conf() -> InitConf {
    InitConf {
        sidi: [1, 2, 3, 4],
        sidr: [5, 6, 7, 8],
        biscuit_ct: [0x11; BISCUIT_CT_LEN],
        auth: [0x22; TAG_LEN],
        mac: [0x33; MAC_LEN],
        cookie: [0x44; COOKIE_LEN],
    }
}

fn empty_data() -> EmptyData {
    EmptyData {
        sid: [1, 2, 3, 4],
        ctr: [9, 0, 0, 0, 0, 0, 0, 0],
        auth: [0x11; TAG_LEN],
        mac: [0x22; MAC_LEN],
        cookie: [0x33; COOKIE_LEN],
    }
}

#[test]
fn init_hello_layout_matches_upstream_msgs_rs() {
    let mut b = [0u8; INIT_HELLO_LEN];
    assert_eq!(init_hello().emit(&mut b), Ok(INIT_HELLO_LEN));
    assert_eq!(&b[..8], &[0x81, 0, 0, 0, 1, 2, 3, 4]);
    assert_eq!(&b[8..808], &[0x11; EPK_LEN]);
    assert_eq!(&b[808..996], &[0x22; SCT_LEN]);
    assert_eq!(&b[996..1044], &[0x33; PIDI_CT_LEN]);
    assert_eq!(&b[1044..1060], &[0x44; TAG_LEN]);
    assert_eq!(&b[mac_offset(INIT_HELLO_LEN)..1076], &[0x55; MAC_LEN]);
    assert_eq!(&b[cookie_offset(INIT_HELLO_LEN)..], &[0x66; COOKIE_LEN]);
    assert_eq!(InitHello::parse(&b), Ok(init_hello()));
}

#[test]
fn resp_hello_layout_matches_upstream_msgs_rs() {
    let mut b = [0u8; RESP_HELLO_LEN];
    assert_eq!(resp_hello().emit(&mut b), Ok(RESP_HELLO_LEN));
    assert_eq!(&b[..12], &[0x82, 0, 0, 0, 5, 6, 7, 8, 1, 2, 3, 4]);
    assert_eq!(&b[12..780], &[0x11; ECT_LEN]);
    assert_eq!(&b[780..968], &[0x22; SCT_LEN]);
    assert_eq!(&b[968..984], &[0x33; TAG_LEN]);
    assert_eq!(&b[984..1100], &[0x44; BISCUIT_CT_LEN]);
    assert_eq!(&b[mac_offset(RESP_HELLO_LEN)..1116], &[0x55; MAC_LEN]);
    assert_eq!(&b[cookie_offset(RESP_HELLO_LEN)..], &[0x66; COOKIE_LEN]);
    assert_eq!(RespHello::parse(&b), Ok(resp_hello()));
}

#[test]
fn init_conf_layout_matches_upstream_msgs_rs() {
    let mut b = [0u8; INIT_CONF_LEN];
    assert_eq!(init_conf().emit(&mut b), Ok(INIT_CONF_LEN));
    assert_eq!(&b[..12], &[0x83, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&b[12..128], &[0x11; BISCUIT_CT_LEN]);
    assert_eq!(&b[128..144], &[0x22; TAG_LEN]);
    assert_eq!(&b[mac_offset(INIT_CONF_LEN)..160], &[0x33; MAC_LEN]);
    assert_eq!(&b[cookie_offset(INIT_CONF_LEN)..], &[0x44; COOKIE_LEN]);
    assert_eq!(InitConf::parse(&b), Ok(init_conf()));
}

#[test]
fn empty_data_layout_matches_upstream_msgs_rs() {
    let mut b = [0u8; EMPTY_DATA_LEN];
    assert_eq!(empty_data().emit(&mut b), Ok(EMPTY_DATA_LEN));
    assert_eq!(&b[..16], &[0x84, 0, 0, 0, 1, 2, 3, 4, 9, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&b[16..32], &[0x11; TAG_LEN]);
    assert_eq!(&b[mac_offset(EMPTY_DATA_LEN)..48], &[0x22; MAC_LEN]);
    assert_eq!(&b[cookie_offset(EMPTY_DATA_LEN)..], &[0x33; COOKIE_LEN]);
    assert_eq!(EmptyData::parse(&b), Ok(empty_data()));
}

#[test]
fn upstream_captures_parse_and_re_emit_identically() {
    let mut out = [0u8; RESP_HELLO_LEN];
    let n = InitHello::parse(UPSTREAM_INIT_HELLO).unwrap().emit(&mut out).unwrap();
    assert_eq!(&out[..n], UPSTREAM_INIT_HELLO);
    let n = RespHello::parse(UPSTREAM_RESP_HELLO).unwrap().emit(&mut out).unwrap();
    assert_eq!(&out[..n], UPSTREAM_RESP_HELLO);
    let n = InitConf::parse(UPSTREAM_INIT_CONF).unwrap().emit(&mut out).unwrap();
    assert_eq!(&out[..n], UPSTREAM_INIT_CONF);
    let n = EmptyData::parse(UPSTREAM_EMPTY_DATA).unwrap().emit(&mut out).unwrap();
    assert_eq!(&out[..n], UPSTREAM_EMPTY_DATA);
}

#[test]
fn upstream_captures_carry_the_ids_they_exchange() {
    let ih = InitHello::parse(UPSTREAM_INIT_HELLO).unwrap();
    let rh = RespHello::parse(UPSTREAM_RESP_HELLO).unwrap();
    let ic = InitConf::parse(UPSTREAM_INIT_CONF).unwrap();
    let ed = EmptyData::parse(UPSTREAM_EMPTY_DATA).unwrap();
    assert_eq!(rh.sidi, ih.sidi);
    assert_eq!((ic.sidi, ic.sidr), (ih.sidi, rh.sidr));
    assert_eq!(ic.biscuit_ct, rh.biscuit_ct);
    assert_eq!(ed.sid, ih.sidi);
    // A responder never holds a cookie value from its peer, so upstream
    // leaves the cookie field zero.
    assert_eq!(rh.cookie, [0; COOKIE_LEN]);
    assert_eq!(ed.cookie, [0; COOKIE_LEN]);
}

/// Each parser accepts only its own type, so a datagram is never decoded as
/// two different messages.
#[test]
fn each_parser_accepts_only_its_own_type() {
    for ty in 0..=u8::MAX {
        let mut ih = UPSTREAM_INIT_HELLO.to_vec();
        ih[0] = ty;
        assert_eq!(InitHello::parse(&ih).is_ok(), ty == MSG_INIT_HELLO, "type {ty:#x}");
        let mut rh = UPSTREAM_RESP_HELLO.to_vec();
        rh[0] = ty;
        assert_eq!(RespHello::parse(&rh).is_ok(), ty == MSG_RESP_HELLO, "type {ty:#x}");
        let mut ic = UPSTREAM_INIT_CONF.to_vec();
        ic[0] = ty;
        assert_eq!(InitConf::parse(&ic).is_ok(), ty == MSG_INIT_CONF, "type {ty:#x}");
        let mut ed = UPSTREAM_EMPTY_DATA.to_vec();
        ed[0] = ty;
        assert_eq!(EmptyData::parse(&ed).is_ok(), ty == MSG_EMPTY_DATA, "type {ty:#x}");
    }
}

#[test]
fn parsers_reject_every_wrong_length() {
    let mut big = std::vec![0u8; RESP_HELLO_LEN + 1];
    for len in 0..big.len() {
        for (ty, want) in [
            (MSG_INIT_HELLO, INIT_HELLO_LEN),
            (MSG_RESP_HELLO, RESP_HELLO_LEN),
            (MSG_INIT_CONF, INIT_CONF_LEN),
            (MSG_EMPTY_DATA, EMPTY_DATA_LEN),
        ] {
            big[0] = ty;
            let ok = match ty {
                MSG_INIT_HELLO => InitHello::parse(&big[..len]).map(|_| ()),
                MSG_RESP_HELLO => RespHello::parse(&big[..len]).map(|_| ()),
                MSG_INIT_CONF => InitConf::parse(&big[..len]).map(|_| ()),
                _ => EmptyData::parse(&big[..len]).map(|_| ()),
            };
            if len == want {
                assert_eq!(ok, Ok(()), "type {ty:#x} len {len}");
            } else {
                assert_eq!(ok, Err(WireError::WrongLength), "type {ty:#x} len {len}");
            }
        }
    }
}

#[test]
fn reserved_bytes_must_be_zero() {
    for i in 1..4 {
        let mut m = UPSTREAM_INIT_CONF.to_vec();
        m[i] = 0x80;
        assert_eq!(InitConf::parse(&m), Err(WireError::ReservedNonZero), "byte {i}");
        let mut m = UPSTREAM_INIT_HELLO.to_vec();
        m[i] = 1;
        assert_eq!(InitHello::parse(&m), Err(WireError::ReservedNonZero), "byte {i}");
        let mut m = UPSTREAM_RESP_HELLO.to_vec();
        m[i] = 1;
        assert_eq!(RespHello::parse(&m), Err(WireError::ReservedNonZero), "byte {i}");
        let mut m = UPSTREAM_EMPTY_DATA.to_vec();
        m[i] = 1;
        assert_eq!(EmptyData::parse(&m), Err(WireError::ReservedNonZero), "byte {i}");
    }
}

#[test]
fn emitters_refuse_short_buffers() {
    assert_eq!(init_hello().emit(&mut [0u8; INIT_HELLO_LEN - 1]), Err(WireError::BufferTooSmall));
    assert_eq!(resp_hello().emit(&mut [0u8; RESP_HELLO_LEN - 1]), Err(WireError::BufferTooSmall));
    assert_eq!(init_conf().emit(&mut [0u8; INIT_CONF_LEN - 1]), Err(WireError::BufferTooSmall));
    assert_eq!(empty_data().emit(&mut [0u8; EMPTY_DATA_LEN - 1]), Err(WireError::BufferTooSmall));
}

#[test]
fn peek_type_reads_the_first_byte_only() {
    assert_eq!(peek_type(&[]), Err(WireError::TooShort));
    assert_eq!(peek_type(&[MSG_COOKIE_REPLY]), Ok(MSG_COOKIE_REPLY));
    assert_eq!(peek_type(UPSTREAM_INIT_CONF), Ok(MSG_INIT_CONF));
}

#[test]
fn committed_seeds_are_the_upstream_captures() {
    // The fuzz target's seeds double as the upstream oracle; a hand edit
    // that changed their length would silently weaken both.
    for (name, len) in [
        ("seed-init-hello", INIT_HELLO_LEN),
        ("seed-resp-hello", RESP_HELLO_LEN),
        ("seed-init-conf", INIT_CONF_LEN),
        ("seed-empty-data", EMPTY_DATA_LEN),
    ] {
        let p = std::format!("{}/{CORPUS}/{name}", env!("CARGO_MANIFEST_DIR"));
        assert_eq!(std::fs::read(&p).unwrap().len(), len, "{p}");
    }
}

/// Every parser is total and whatever parses re-emits to the same bytes.
/// Beyond Kani's bound: inputs of any length.
fn fuzz_one(bytes: &[u8]) {
    let mut out = [0u8; RESP_HELLO_LEN];
    if let Ok(m) = InitHello::parse(bytes) {
        let n = m.emit(&mut out).unwrap();
        assert_eq!(&out[..n], bytes);
    }
    if let Ok(m) = RespHello::parse(bytes) {
        let n = m.emit(&mut out).unwrap();
        assert_eq!(&out[..n], bytes);
    }
    if let Ok(m) = InitConf::parse(bytes) {
        let n = m.emit(&mut out).unwrap();
        assert_eq!(&out[..n], bytes);
    }
    if let Ok(m) = EmptyData::parse(bytes) {
        let n = m.emit(&mut out).unwrap();
        assert_eq!(&out[..n], bytes);
    }
    assert_eq!(peek_type(bytes).ok(), bytes.first().copied());
}

#[test]
fn fuzz_parsers_never_panic_and_round_trip() {
    bolero::check!().for_each(fuzz_one);
}
