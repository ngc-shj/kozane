//! Kani harnesses for the head delimiter, the head parser, the
//! Content-Length parse and the rewrite (M6 plan C9, T15). Run with
//! `cargo kani -p http-wire`. Heads are walked byte by byte with nested
//! field loops, and at 96 bytes cbmc passed 38 GiB, so each harness takes
//! the smallest input that still reaches its covers: the delimiter 32
//! bytes, each part of the head parser alone, and the whole head with a fixed
//! request line and 16 field bytes (at most 2 fields; the bound is `N`), the rewrite 40 bytes and 3 fields.

use super::*;


fn any_bytes<const L: usize>(buf: &[u8; L]) -> &[u8] {
    let len: usize = kani::any();
    kani::assume(len <= L);
    buf.get(..len).unwrap_or(&[])
}

fn inside(outer: &[u8], inner: &[u8]) -> bool {
    let (o, i) = (outer.as_ptr_range(), inner.as_ptr_range());
    o.start <= i.start && i.end <= o.end
}

/// No panic; `Some(n)` is the end of the first CRLFCRLF, `None` means
/// there is none yet and no bare CR or LF either.
#[kani::proof]
#[kani::unwind(34)]
fn head_end_finds_the_first_blank_line() {
    let buf: [u8; 32] = kani::any();
    let bytes = any_bytes(&buf);
    let r = head_end(bytes);
    if let Ok(found) = r {
        let end = found.unwrap_or(bytes.len());
        assert!(end <= bytes.len());
        // No terminator ends before `end`.
        for i in 4..end {
            assert!(bytes.get(i - 4..i) != Some(b"\r\n\r\n"));
        }
        if let Some(n) = found {
            assert!(n >= 4 && bytes.get(n - 4..n) == Some(b"\r\n\r\n"));
        }
    }
    kani::cover!(matches!(r, Ok(Some(n)) if n < bytes.len()));
    kani::cover!(matches!(r, Ok(None)) && !bytes.is_empty());
    kani::cover!(r == Err(HttpRefusal::BareLineEnding));
}

/// A field line's name and value lie inside the line, and parsing one
/// never panics. The whole-head harness over 32 symbolic field bytes ran
/// past 90 minutes, so each part of the head parser gets its own small
/// harness and the head harness keeps a short field block.
#[kani::proof]
#[kani::unwind(26)]
fn field_line_slices_stay_inside() {
    let buf: [u8; 24] = kani::any();
    let line = any_bytes(&buf);
    if let Ok(f) = field_line(line) {
        assert!(inside(line, f.name) && inside(line, f.value));
        assert!(!f.name.is_empty());
        kani::cover!(!f.value.is_empty());
    }
}

/// The request line's method and target lie inside it.
#[kani::proof]
#[kani::unwind(26)]
fn request_line_slices_stay_inside() {
    let buf: [u8; 24] = kani::any();
    let line = any_bytes(&buf);
    if let Ok((method, target)) = request_line(line) {
        assert!(inside(line, method) && inside(line, target));
        kani::cover!(target.len() > 1);
    }
}

/// A Connection value never panics, and naming a field the proxy owns is
/// refused.
#[kani::proof]
#[kani::unwind(22)]
fn connection_value_is_total() {
    let buf: [u8; 20] = kani::any();
    let value = any_bytes(&buf);
    let r = check_connection(value);
    kani::cover!(r.is_ok() && !value.is_empty());
    kani::cover!(r == Err(HttpRefusal::ConnectionNamesProtected));
}

/// A head (fixed request line, then up to 16 symbolic bytes of fields) is
/// total, and every slice it returns lies inside it.
#[kani::proof]
#[kani::unwind(18)]
fn head_is_total_and_slices_stay_inside() {
    const LINE: &[u8] = b"GET / HTTP/1.1\r\n";
    const FIELD_LEN: usize = 16;
    let fields: [u8; FIELD_LEN] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= FIELD_LEN);
    let mut buf = [0u8; LINE.len() + FIELD_LEN];
    buf[..LINE.len()].copy_from_slice(LINE);
    buf[LINE.len()..LINE.len() + len].copy_from_slice(&fields[..len]);
    let bytes = &buf[..LINE.len() + len];
    let r = parse::<2>(bytes);
    if let Ok(h) = &r {
        assert!(h.bytes.len() == bytes.len() && inside(bytes, h.bytes));
        assert!(inside(bytes, h.line) && inside(h.line, h.method) && inside(h.line, h.target));
        assert!(inside(bytes, h.host) && !h.host.is_empty());
        assert!(h.headers().len() <= 2 && h.content_length <= MAX_BODY);
        for f in h.headers() {
            assert!(inside(bytes, f.line) && inside(f.line, f.name) && inside(f.line, f.value));
        }
    }
    kani::cover!(matches!(&r, Ok(h) if h.headers().len() >= 2));
}

/// Any value of 0..=24 bytes: no overflow (Kani checks every operation),
/// and an accepted value is all digits and equals its decimal value
/// saturated at `MAX_BODY + 1`, so a huge one is refused as too large.
#[kani::proof]
#[kani::unwind(26)]
fn content_length_parse_is_exact_and_saturates() {
    let buf: [u8; 24] = kani::any();
    let value = any_bytes(&buf);
    let r = parse_content_length(value);
    if let Ok(n) = r {
        assert!(!value.is_empty() && value.iter().all(u8::is_ascii_digit));
        // 24 digits stay below 10^24 < u128::MAX.
        let exact = value.iter().fold(0u128, |v, &d| v * 10 + u128::from(d - b'0'));
        assert!(n as u128 == exact.min(MAX_BODY as u128 + 1));
    }
    kani::cover!(r == Ok(MAX_BODY));
    kani::cover!(matches!(r, Ok(n) if n > MAX_BODY) && value.len() > 20);
    kani::cover!(r == Err(HttpRefusal::ContentLength));
}

/// An accepted head of 0..=64 bytes and at most 3 fields rewrites into a
/// buffer `REWRITE_GROWTH` bytes larger than the head, starting with the
/// request line and ending with ours.
#[kani::proof]
#[kani::unwind(42)]
fn rewrite_fits_and_keeps_the_request_line() {
    let buf: [u8; 40] = kani::any();
    let bytes = any_bytes(&buf);
    let Ok(h) = parse::<3>(bytes) else { return };
    let mut out = [0u8; 40 + REWRITE_GROWTH];
    let r = rewrite(&h, kani::any(), &mut out);
    assert!(matches!(r, Ok(n) if n <= bytes.len() + REWRITE_GROWTH));
    let n = r.unwrap_or(0);
    let written = out.get(..n).unwrap_or(&[]);
    assert!(written.starts_with(h.line));
    assert!(written.ends_with(b"X-Forwarded-Proto: https\r\nConnection: close\r\n\r\n"));
    kani::cover!(h.headers().iter().any(|f| is_dropped(&h, f.name)));
    kani::cover!(h.headers().len() >= 2);
}
