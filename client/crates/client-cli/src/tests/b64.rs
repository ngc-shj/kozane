use crate::b64::{decode32, encode};

#[test]
fn encodes_rfc4648_vectors() {
    for (i, o) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foobar", "Zm9vYmFy")] {
        assert_eq!(encode(i.as_bytes()), o);
    }
}

#[test]
fn decodes_a_key_it_encoded() {
    let key: [u8; 32] = core::array::from_fn(|i| (i * 37 + 5) as u8);
    assert_eq!(decode32(&encode(&key)), Some(key));
    assert_eq!(encode(&[0; 32]), format!("{}=", "A".repeat(43)));
}

#[test]
fn refuses_non_canonical_or_misshapen_keys() {
    let good = encode(&[0xff; 32]);
    assert!(decode32(&good).is_some());
    // The last digit carries two unused bits; setting them is another text.
    let mut loose = good.clone().into_bytes();
    loose[42] = b'/';
    assert_eq!(decode32(std::str::from_utf8(&loose).unwrap()), None);
    assert_eq!(decode32(&good[..43]), None);
    assert_eq!(decode32(&format!("{}==", &good[..42])), None);
    assert_eq!(decode32(&good.replace('/', "_")), None);
}
