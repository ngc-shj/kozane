use kozane_client::Secret;

use crate::ipc::{INSTALL_LEN, RECORD_MAX, Request, TAG_INSTALL, TAG_SCRUB, admit, decode, encode_install};

#[test]
fn decodes_scrub_and_install() {
    let mut psk = Secret::zero();
    let mut buf = [0u8; RECORD_MAX];
    buf[0] = TAG_SCRUB;
    assert_eq!(decode(&buf, 1, &mut psk), Some(Request::Scrub));
    let mut rec = [0u8; INSTALL_LEN];
    encode_install(&Secret::copy_from(&[7; 32]), &mut rec);
    assert_eq!(rec[0], TAG_INSTALL);
    buf[..INSTALL_LEN].copy_from_slice(&rec);
    assert_eq!(decode(&buf, INSTALL_LEN, &mut psk), Some(Request::Install));
    assert_eq!(psk.expose(), &[7; 32]);
}

#[test]
fn refuses_any_other_record() {
    let mut psk = Secret::zero();
    let mut buf = [0u8; RECORD_MAX];
    buf[0] = TAG_SCRUB;
    assert_eq!(decode(&buf, 2, &mut psk), None, "a scrub with a payload");
    buf[0] = TAG_INSTALL;
    assert_eq!(decode(&buf, 32, &mut psk), None, "a short install");
    assert_eq!(decode(&buf, 34, &mut psk), None, "a long install");
    assert_eq!(decode(&buf, RECORD_MAX + 1, &mut psk), None, "a truncated record");
    buf[0] = 3;
    assert_eq!(decode(&buf, 1, &mut psk), None, "an unknown tag");
    assert_eq!(decode(&buf, 0, &mut psk), None);
    assert!(psk.is_zero());
}

#[test]
fn admits_only_kozane_net() {
    assert!(admit(990, 990));
    assert!(!admit(991, 990), "kzc-psk: foreign peer accepted");
    assert!(!admit(0, 990), "kzc-psk: foreign peer accepted");
}
