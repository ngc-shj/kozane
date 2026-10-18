#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

use super::*;

const EP: Endpoint = Endpoint { ip: [10, 0, 2, 2], port: 40000 };

#[test]
fn initiation_round_trips_and_rejects_other_sizes() {
    let msg = [7u8; INITIATION_LEN];
    let mut out = [0u8; 256];
    let n = Initiation { src: EP, msg: &msg }.encode(&mut out).unwrap();
    assert_eq!(n, INITIATION_MSG_LEN);
    assert_eq!(Initiation::decode(&out[..n]), Ok(Initiation { src: EP, msg: &msg }));
    assert_eq!(Initiation::decode(&out[..n - 1]), Err(Malformed));
    assert_eq!(Initiation::decode(&out[..n + 1]), Err(Malformed));
}

#[test]
fn response_round_trips_and_rejects_other_sizes() {
    let msg = [9u8; RESPONSE_LEN];
    let mut out = [0u8; 256];
    let n = Response { dst: EP, msg: &msg }.encode(&mut out).unwrap();
    assert_eq!(Response::decode(&out[..n]), Ok(Response { dst: EP, msg: &msg }));
    assert_eq!(Response::decode(&out[..n + 1]), Err(Malformed));
}

#[test]
fn install_round_trips_every_field() {
    let (send, recv) = ([1u8; 32], [2u8; 32]);
    let m = Install { peer: 3, local_index: 0xdead_beef, remote_index: 7, created_ns: 1 << 40, send: &send, recv: &recv };
    let mut out = [0u8; 128];
    let n = m.encode(&mut out).unwrap();
    assert_eq!(n, INSTALL_LEN);
    assert_eq!(Install::decode(&out[..n]), Ok(m));
    assert_eq!(Install::decode(&out[..n - 1]), Err(Malformed));
}

#[test]
fn transport_keeps_the_whole_message() {
    let mut out = [0u8; 64];
    let n = Transport { src: EP, msg: b"0123456789abcdef0123456789abcdef" }.encode(&mut out).unwrap();
    assert_eq!(Transport::decode(&out[..n]).unwrap().msg, b"0123456789abcdef0123456789abcdef");
    assert_eq!(Transport::decode(&out[..5]), Err(Malformed));
}

#[test]
fn to_ingress_variants_round_trip_and_unknown_tags_fail() {
    let mut out = [0u8; 64];
    for m in [ToIngress::Outbound { peer: 1, msg: b"sealed" }, ToIngress::EndpointUpdate { peer: 2, endpoint: EP }] {
        let n = m.encode(&mut out).unwrap();
        assert_eq!(ToIngress::decode(&out[..n]), Ok(m));
    }
    assert_eq!(ToIngress::decode(&[3, 0, 0]), Err(Malformed));
    let n = ToIngress::EndpointUpdate { peer: 2, endpoint: EP }.encode(&mut out).unwrap();
    assert_eq!(ToIngress::decode(&out[..n + 1]), Err(Malformed));
}

#[test]
fn encode_reports_a_small_buffer() {
    let msg = [0u8; INITIATION_LEN];
    assert_eq!(Initiation { src: EP, msg: &msg }.encode(&mut [0u8; 100]), None);
}
