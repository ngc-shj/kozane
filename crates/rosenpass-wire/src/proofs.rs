//! Kani harnesses for the codecs. Run with `cargo kani -p rosenpass-wire`.
//!
//! Each message gets two harnesses: totality over every length up to one
//! byte past the message (anything longer fails the same length check), and
//! the round trip over every byte string of exactly the message's length.
//! Splitting them keeps the copies concrete-sized; one harness doing both
//! over a 1136-byte symbolic buffer ran for tens of minutes.

use super::*;

macro_rules! harnesses {
    ($total:ident, $round:ident, $msg:ty, $len:expr, $unwind:literal) => {
        #[kani::proof]
        #[kani::unwind(2)]
        fn $total() {
            let buf: [u8; $len + 1] = kani::any();
            let len: usize = kani::any();
            kani::assume(len <= buf.len());
            let r = <$msg>::parse(buf.get(..len).unwrap_or(&[]));
            kani::cover!(r.is_ok());
            kani::cover!(r.as_ref().err() == Some(&WireError::WrongLength));
            kani::cover!(r.as_ref().err() == Some(&WireError::WrongType));
            kani::cover!(r.as_ref().err() == Some(&WireError::ReservedNonZero));
            assert!(r.is_err() || len == $len);
        }

        #[kani::proof]
        #[kani::unwind($unwind)]
        fn $round() {
            let bytes: [u8; $len] = kani::any();
            let r = <$msg>::parse(&bytes);
            kani::cover!(r.is_ok());
            if let Ok(m) = r {
                let mut out = [0u8; $len];
                assert_eq!(m.emit(&mut out), Ok($len));
                assert!(out == bytes);
            }
        }
    };
}

harnesses!(init_hello_parse_is_total, init_hello_round_trips, InitHello, INIT_HELLO_LEN, 1094);
harnesses!(resp_hello_parse_is_total, resp_hello_round_trips, RespHello, RESP_HELLO_LEN, 1134);
harnesses!(init_conf_parse_is_total, init_conf_round_trips, InitConf, INIT_CONF_LEN, 178);
harnesses!(empty_data_parse_is_total, empty_data_round_trips, EmptyData, EMPTY_DATA_LEN, 66);

/// Emitting into any buffer either fits exactly the message or reports
/// `BufferTooSmall`, never panics.
#[kani::proof]
#[kani::unwind(2)]
fn init_conf_emit_is_total() {
    let m = InitConf {
        sidi: kani::any(),
        sidr: kani::any(),
        biscuit_ct: kani::any(),
        auth: kani::any(),
        mac: kani::any(),
        cookie: kani::any(),
    };
    let mut buf = [0u8; INIT_CONF_LEN + 4];
    let len: usize = kani::any();
    kani::assume(len <= buf.len());
    let r = m.emit(buf.get_mut(..len).unwrap_or(&mut []));
    kani::cover!(r.is_ok());
    kani::cover!(r == Err(WireError::BufferTooSmall));
    assert_eq!(r.is_ok(), len >= INIT_CONF_LEN);
}

#[kani::proof]
fn peek_type_is_total() {
    let buf: [u8; 2] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 2);
    let r = peek_type(buf.get(..len).unwrap_or(&[]));
    kani::cover!(r.is_ok());
    kani::cover!(r == Err(WireError::TooShort));
}
