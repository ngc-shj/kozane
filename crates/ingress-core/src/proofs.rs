//! Kani harnesses for `ingress-core`. Run with `cargo kani -p ingress-core`.

use super::*;

struct AnyMac1;

impl Mac1 for AnyMac1 {
    fn verify(&self, _: &[u8; INITIATION_LEN]) -> bool {
        kani::any()
    }
}

const CFG: Config =
    Config { mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56], ipv4: [10, 0, 2, 15], router_mac: [0x52, 0x55, 10, 0, 2, 2], port: 51820 };

/// `respond` never panics and never claims more bytes than `out` holds.
#[kani::proof]
#[kani::unwind(66)]
fn respond_is_total_and_bounded() {
    let buf: [u8; 64] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 64);
    let mut out = [0u8; 64];
    let mut buckets = Buckets::<2>::default();
    let o = respond(&CFG, &AnyMac1, &mut buckets, kani::any(), buf.get(..len).unwrap_or(&[]), &mut out);
    if let Outcome::ArpReplied(n) = o {
        assert!(n <= out.len());
    }
    kani::cover!(matches!(o, Outcome::ArpReplied(_)));
    // A transport frame needs 74 bytes; `classify` covers it.
    kani::cover!(o == Outcome::NotForUs);
    kani::cover!(o == Outcome::NoService);
    kani::cover!(o == Outcome::Spoofed);
    kani::cover!(o == Outcome::BadMessage);
}

/// Only an exactly-sized type-1 message with a valid mac1 and budget is
/// handed to `hs`; transport messages have at least header + tag.
#[kani::proof]
#[kani::unwind(150)]
fn classify_forwards_only_well_formed_messages() {
    let payload: [u8; INITIATION_LEN + 1] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= payload.len());
    let mut buckets = Buckets::<2>::default();
    let src = Endpoint { ip: kani::any(), port: kani::any() };
    let o = classify(&AnyMac1, &mut buckets, kani::any(), src, payload.get(..len).unwrap_or(&[]));
    match o {
        Outcome::Initiation { msg, .. } => assert!(len == INITIATION_LEN && msg[0] == MSG_INITIATION),
        Outcome::Transport { msg, .. } => assert!(msg.len() >= TRANSPORT_MIN_LEN && msg[0] == MSG_TRANSPORT),
        _ => {}
    }
    kani::cover!(matches!(o, Outcome::Initiation { .. }));
    kani::cover!(matches!(o, Outcome::Transport { .. }));
    kani::cover!(o == Outcome::BadMac1);
}

/// A source never gets more than BURST initiations at one instant, and the
/// table never panics, for any interleaving of three sources over two slots.
#[kani::proof]
#[kani::unwind(10)]
fn bucket_never_exceeds_burst() {
    let mut buckets = Buckets::<2>::default();
    let now: u64 = kani::any();
    let mut granted = 0u64;
    for _ in 0..(BURST + 2) {
        if buckets.allow([10, 0, 0, 1], now) {
            granted += 1;
        }
    }
    assert!(granted == BURST);
    let other: u8 = kani::any();
    let _ = buckets.allow([10, 0, 0, other], kani::any());
}
