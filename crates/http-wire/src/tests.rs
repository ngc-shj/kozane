#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

use std::string::String;
use std::vec::Vec;

use super::*;

const CORPUS: &str = "src/__fuzz__/tests__parse_never_panics_and_rewrite_reparses/corpus";

fn seed(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS).join(name)).unwrap()
}

/// A GET with Host first, then `fields` (each with its CRLF), then the
/// blank line.
fn req(fields: &str) -> Vec<u8> {
    std::format!("GET / HTTP/1.1\r\nHost: example.com\r\n{fields}\r\n").into_bytes()
}

fn refusal(bytes: &[u8]) -> HttpRefusal {
    request_head(bytes).unwrap_err()
}

/// A head of exactly `len` bytes: Host and one `X-Pad` field filling the rest.
fn head_of_len(len: usize) -> Vec<u8> {
    let fixed = req("X-Pad: \r\n").len();
    req(&std::format!("X-Pad: {}\r\n", "a".repeat(len - fixed)))
}

/// `n` fields in all: Host and `n - 1` distinct custom ones.
fn head_with_fields(n: usize) -> Vec<u8> {
    let fields: String = (1..n).map(|i| std::format!("X-F{i}: v\r\n")).collect();
    req(&fields)
}

fn rewritten(bytes: &[u8], ip: [u8; 4]) -> Vec<u8> {
    let head = request_head(bytes).unwrap();
    let mut out = [0u8; MAX_REWRITE];
    let n = rewrite(&head, ip, &mut out).unwrap();
    out[..n].to_vec()
}

// --- constants and the status table ---

#[test]
fn limits_are_the_plans() {
    assert_eq!((MAX_HEAD, MAX_HEADERS, MAX_BODY), (8192, 32, 1_048_576));
    assert_eq!(REWRITE_GROWTH, b"X-Forwarded-For: 255.255.255.255\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n".len());
}

#[test]
fn refusals_map_to_the_c10_statuses() {
    use HttpRefusal::*;
    let table: &[(HttpRefusal, u16)] = &[
        (BareLineEnding, 400),
        (Unterminated, 400),
        (TrailingBytes, 400),
        (RequestLine, 400),
        (Target, 400),
        (Version, 400),
        (ObsFold, 400),
        (HeaderLine, 400),
        (FieldName, 400),
        (UnderscoreName, 400),
        (FieldValue, 400),
        (ContentLength, 400),
        (DuplicateContentLength, 400),
        (MissingHost, 400),
        (DuplicateHost, 400),
        (Host, 400),
        (ConnectionOption, 400),
        (ConnectionNamesProtected, 400),
        (BodyTooLarge, 413),
        (Expect, 417),
        (HeadTooLarge, 431),
        (TooManyHeaders, 431),
        (RewriteTooLarge, 431),
        (Connect, 501),
        (AbsoluteForm, 501),
        (AsteriskForm, 501),
        (TransferEncoding, 501),
        (Upgrade, 501),
    ];
    for &(r, code) in table {
        assert_eq!(r.status().code(), code, "{r:?}");
    }
}

#[test]
fn status_indices_follow_the_audit_order() {
    let indices: Vec<u16> = Status::ALL.iter().map(|s| s.index()).collect();
    assert_eq!(indices, [0, 1, 2, 3, 4]);
}

/// `Status::ALL` lists every variant once: `position` is exhaustive, so a
/// new variant does not compile until it is given the next position, and
/// the positions must be exactly ALL's indices up to its last.
#[test]
fn status_all_lists_every_variant_once() {
    fn position(s: Status) -> usize {
        match s {
            Status::BadRequest => 0,
            Status::ContentTooLarge => 1,
            Status::ExpectationFailed => 2,
            Status::HeaderFieldsTooLarge => 3,
            Status::NotImplemented => 4,
        }
    }
    for (i, s) in Status::ALL.iter().enumerate() {
        assert_eq!(position(*s), i, "{s:?}");
    }
    assert_eq!(position(Status::NotImplemented) + 1, Status::ALL.len());
}

#[test]
fn refusal_responses_are_complete_and_close() {
    for status in Status::ALL {
        let text = std::str::from_utf8(refusal_response(status)).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with(&std::format!("HTTP/1.1 {} ", status.code())), "{text}");
        assert!(head.split("\r\n").any(|l| l == "Connection: close"), "{text}");
        assert!(head.split("\r\n").any(|l| l == std::format!("Content-Length: {}", body.len())), "{text}");
    }
}

// --- head_end and the 8 KiB bound ---

#[test]
fn head_end_finds_the_blank_line_before_the_body() {
    let mut bytes = req("Content-Length: 5\r\n");
    let n = bytes.len();
    bytes.extend_from_slice(b"hello");
    assert_eq!(head_end(&bytes), Ok(Some(n)));
}

#[test]
fn head_end_waits_for_an_unfinished_head() {
    let bytes = req("");
    assert_eq!(head_end(&bytes[..bytes.len() - 1]), Ok(None));
    assert_eq!(head_end(b""), Ok(None));
}

#[test]
fn head_end_refuses_a_bare_lf_at_once() {
    assert_eq!(head_end(b"GET / HTTP/1.1\nHost: a\n"), Err(HttpRefusal::BareLineEnding));
}

#[test]
fn head_end_refuses_a_bare_cr_at_once() {
    assert_eq!(head_end(b"GET / HTTP/1.1\rHost"), Err(HttpRefusal::BareLineEnding));
}

#[test]
fn head_of_8192_bytes_is_accepted() {
    let bytes = head_of_len(MAX_HEAD);
    assert_eq!(bytes.len(), 8192);
    assert_eq!(head_end(&bytes), Ok(Some(8192)));
    assert!(request_head(&bytes).is_ok());
}

#[test]
fn head_of_8193_bytes_is_refused_with_431() {
    let bytes = head_of_len(MAX_HEAD + 1);
    assert_eq!(bytes.len(), 8193);
    assert_eq!(head_end(&bytes), Err(HttpRefusal::HeadTooLarge));
    assert_eq!(refusal(&bytes), HttpRefusal::HeadTooLarge);
    assert_eq!(HttpRefusal::HeadTooLarge.status(), Status::HeaderFieldsTooLarge);
}

#[test]
fn head_end_waits_up_to_8191_unterminated_bytes() {
    let bytes = std::vec![b'a'; MAX_HEAD - 1];
    assert_eq!(head_end(&bytes), Ok(None));
}

#[test]
fn head_end_refuses_8192_unterminated_bytes() {
    let bytes = std::vec![b'a'; MAX_HEAD];
    assert_eq!(head_end(&bytes), Err(HttpRefusal::HeadTooLarge));
}

#[test]
fn request_head_refuses_bytes_after_the_blank_line() {
    let mut bytes = req("");
    bytes.push(b'x');
    assert_eq!(refusal(&bytes), HttpRefusal::TrailingBytes);
}

#[test]
fn request_head_refuses_a_head_without_blank_line() {
    assert_eq!(refusal(b"GET / HTTP/1.1\r\nHost: a\r\n"), HttpRefusal::Unterminated);
}

// --- the field count ---

#[test]
fn thirty_two_fields_are_accepted() {
    let head_bytes = head_with_fields(MAX_HEADERS);
    assert_eq!(request_head(&head_bytes).unwrap().headers().len(), 32);
}

#[test]
fn thirty_three_fields_are_refused_with_431() {
    assert_eq!(refusal(&head_with_fields(MAX_HEADERS + 1)), HttpRefusal::TooManyHeaders);
}

#[test]
fn the_field_bound_is_the_parsers_parameter() {
    // The Kani harnesses parse with N = 4.
    assert!(parse::<4>(&head_with_fields(4)).is_ok());
    assert_eq!(parse::<4>(&head_with_fields(5)).unwrap_err(), HttpRefusal::TooManyHeaders);
}

// --- request line ---

#[test]
fn accepted_head_exposes_its_parts() {
    let bytes = b"POST /a/b?c=d HTTP/1.1\r\nHost: example.com\r\nContent-Length: 7\r\nAccept:  */* \r\n\r\n";
    let h = request_head(bytes).unwrap();
    assert_eq!((h.method, h.target, h.host, h.content_length), (&b"POST"[..], &b"/a/b?c=d"[..], &b"example.com"[..], 7));
    assert_eq!(h.line, b"POST /a/b?c=d HTTP/1.1");
    let accept = h.headers()[2];
    assert_eq!((accept.name, accept.value, accept.line), (&b"Accept"[..], &b"*/*"[..], &b"Accept:  */* "[..]));
}

#[test]
fn origin_form_targets_are_accepted() {
    for target in ["/", "/a/b/", "/%2Fx", "/a:b@c", "/?", "/p?q=/x?y&z=%41", "//double", "/!$&'()*+,;=-._~"] {
        let bytes = std::format!("GET {target} HTTP/1.1\r\nHost: a\r\n\r\n");
        assert!(request_head(bytes.as_bytes()).is_ok(), "{target}");
    }
}

#[test]
fn malformed_targets_are_refused_with_400() {
    for target in ["", "a", "/a%zz", "/a%4", "/#frag", "/a\"b", "/a<b", "/\x7f", "/a\\b", "/{}"] {
        let bytes = std::format!("GET {target} HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(refusal(bytes.as_bytes()), HttpRefusal::Target, "{target:?}");
    }
}

#[test]
fn absolute_form_is_refused_with_501() {
    assert_eq!(refusal(&seed("seed-absolute-form")), HttpRefusal::AbsoluteForm);
}

#[test]
fn authority_form_is_refused_with_501() {
    assert_eq!(refusal(b"GET example.com:443 HTTP/1.1\r\nHost: a\r\n\r\n"), HttpRefusal::AbsoluteForm);
}

#[test]
fn asterisk_form_is_refused_with_501() {
    assert_eq!(refusal(b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n"), HttpRefusal::AsteriskForm);
}

#[test]
fn connect_is_refused_with_501_in_any_case() {
    for method in ["CONNECT", "connect", "Connect"] {
        let bytes = std::format!("{method} example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
        assert_eq!(refusal(bytes.as_bytes()), HttpRefusal::Connect, "{method}");
    }
}

#[test]
fn other_versions_are_refused() {
    for line in ["GET / HTTP/1.0", "GET / HTTP/2", "GET / http/1.1", "GET / HTTP/1.1 ", "GET /"] {
        let bytes = std::format!("{line}\r\nHost: a\r\n\r\n");
        let r = refusal(bytes.as_bytes());
        assert!(matches!(r, HttpRefusal::Version | HttpRefusal::RequestLine), "{line}: {r:?}");
    }
}

#[test]
fn extra_spaces_in_the_request_line_are_refused() {
    assert_eq!(refusal(b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n"), HttpRefusal::Version);
    assert_eq!(refusal(b" GET / HTTP/1.1\r\nHost: a\r\n\r\n"), HttpRefusal::RequestLine);
}

#[test]
fn a_method_that_is_no_token_is_refused() {
    assert_eq!(refusal(b"GE(T / HTTP/1.1\r\nHost: a\r\n\r\n"), HttpRefusal::RequestLine);
}

// --- field lines ---

#[test]
fn obs_fold_is_refused() {
    assert_eq!(refusal(&req("X-A: a\r\n b\r\n")), HttpRefusal::ObsFold);
    assert_eq!(refusal(&req("X-A: a\r\n\tb\r\n")), HttpRefusal::ObsFold);
}

#[test]
fn a_bare_lf_in_the_head_is_refused() {
    assert_eq!(refusal(b"GET / HTTP/1.1\r\nHost: a\nX: b\r\n\r\n"), HttpRefusal::BareLineEnding);
}

#[test]
fn whitespace_before_the_colon_is_refused() {
    assert_eq!(refusal(&req("X-A : b\r\n")), HttpRefusal::FieldName);
    assert_eq!(refusal(&req("X-A\t: b\r\n")), HttpRefusal::FieldName);
}

#[test]
fn underscore_names_are_refused() {
    assert_eq!(refusal(&req("X_Custom: b\r\n")), HttpRefusal::UnderscoreName);
    assert_eq!(refusal(&req("Content_Length: 5\r\n")), HttpRefusal::UnderscoreName);
}

#[test]
fn names_that_are_no_tokens_are_refused() {
    assert_eq!(refusal(&req(": b\r\n")), HttpRefusal::FieldName);
    assert_eq!(refusal(&req("X(A): b\r\n")), HttpRefusal::FieldName);
    assert_eq!(refusal(&req("X-\x01: b\r\n")), HttpRefusal::FieldName);
}

#[test]
fn a_field_line_without_colon_is_refused() {
    assert_eq!(refusal(&req("X-A b\r\n")), HttpRefusal::HeaderLine);
}

#[test]
fn ctls_in_values_are_refused() {
    for ctl in [0x00u8, 0x01, 0x0b, 0x0c, b'\r', 0x1f, 0x7f] {
        let mut bytes = b"GET / HTTP/1.1\r\nHost: a\r\nX-A: a".to_vec();
        bytes.push(ctl);
        bytes.extend_from_slice(b"b\r\n\r\n");
        assert_eq!(refusal(&bytes), HttpRefusal::FieldValue, "{ctl:#x}");
    }
}

#[test]
fn htab_and_obs_text_in_values_are_accepted() {
    let mut bytes = b"GET / HTTP/1.1\r\nHost: a\r\nX-A: a\tb ".to_vec();
    bytes.extend_from_slice(&[0x80, 0xff]);
    bytes.extend_from_slice(b"\r\n\r\n");
    assert!(request_head(&bytes).is_ok());
}

#[test]
fn names_are_matched_ignoring_case() {
    assert_eq!(refusal(&req("tRaNsFeR-eNcOdInG: chunked\r\n")), HttpRefusal::TransferEncoding);
    assert_eq!(refusal(b"GET / HTTP/1.1\r\nhost: a\r\nHOST: a\r\n\r\n"), HttpRefusal::DuplicateHost);
}

// --- Transfer-Encoding, Upgrade, Expect ---

#[test]
fn cl_te_is_refused_with_501() {
    assert_eq!(refusal(&req("Content-Length: 6\r\nTransfer-Encoding: chunked\r\n")), HttpRefusal::TransferEncoding);
}

#[test]
fn te_cl_is_refused_with_501() {
    assert_eq!(refusal(&req("Transfer-Encoding: chunked\r\nContent-Length: 3\r\n")), HttpRefusal::TransferEncoding);
}

#[test]
fn te_te_is_refused_with_501() {
    assert_eq!(refusal(&req("Transfer-Encoding: chunked\r\nTransfer-Encoding: cow\r\n")), HttpRefusal::TransferEncoding);
}

#[test]
fn any_transfer_encoding_is_refused() {
    for v in ["identity", "", "chunked, gzip"] {
        assert_eq!(refusal(&req(&std::format!("Transfer-Encoding: {v}\r\n"))), HttpRefusal::TransferEncoding, "{v}");
    }
}

#[test]
fn upgrade_is_refused_with_501() {
    assert_eq!(refusal(&req("Upgrade: websocket\r\n")), HttpRefusal::Upgrade);
}

#[test]
fn expect_is_refused_with_417() {
    let r = refusal(&req("Expect: 100-continue\r\n"));
    assert_eq!((r, r.status()), (HttpRefusal::Expect, Status::ExpectationFailed));
}

#[test]
fn syntax_faults_win_over_expect() {
    assert_eq!(refusal(b"GET / HTTP/1.1\r\nExpect: 100-continue\r\n\r\n"), HttpRefusal::MissingHost);
    assert_eq!(refusal(&req("Expect: 100-continue\r\nX_A: b\r\n")), HttpRefusal::UnderscoreName);
}

// --- Content-Length ---

#[test]
fn content_length_of_max_body_is_accepted() {
    assert_eq!(request_head(&req("Content-Length: 1048576\r\n")).unwrap().content_length, MAX_BODY);
}

#[test]
fn content_length_above_max_body_is_refused_with_413() {
    let r = refusal(&req("Content-Length: 1048577\r\n"));
    assert_eq!((r, r.status()), (HttpRefusal::BodyTooLarge, Status::ContentTooLarge));
}

#[test]
fn content_length_beyond_u64_is_refused_with_413() {
    for v in ["18446744073709551616", "99999999999999999999999999999999999999999999"] {
        assert_eq!(refusal(&req(&std::format!("Content-Length: {v}\r\n"))), HttpRefusal::BodyTooLarge, "{v}");
    }
}

#[test]
fn content_length_is_one_decimal_number() {
    for v in ["", "+5", "-1", "1 0", "0x10", "5,5", "1.0", "01", "00", "five", "5\t5"] {
        assert_eq!(refusal(&req(&std::format!("Content-Length: {v}\r\n"))), HttpRefusal::ContentLength, "{v:?}");
    }
}

#[test]
fn content_length_takes_surrounding_whitespace_and_zero() {
    assert_eq!(request_head(&req("Content-Length: \t 5 \r\n")).unwrap().content_length, 5);
    assert_eq!(request_head(&req("Content-Length: 0\r\n")).unwrap().content_length, 0);
    assert_eq!(request_head(&req("")).unwrap().content_length, 0);
}

#[test]
fn duplicate_content_length_is_refused_even_when_equal() {
    assert_eq!(refusal(&req("Content-Length: 5\r\nContent-Length: 5\r\n")), HttpRefusal::DuplicateContentLength);
}

// --- Host ---

#[test]
fn missing_host_is_refused() {
    assert_eq!(refusal(b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"), HttpRefusal::MissingHost);
}

#[test]
fn duplicate_host_is_refused() {
    assert_eq!(refusal(&req("Host: example.com\r\n")), HttpRefusal::DuplicateHost);
}

#[test]
fn authority_hosts_are_accepted() {
    for host in [
        "example.com",
        "example.com:8443",
        "10.0.0.1",
        "10.0.0.1:0",
        "a:65535",
        "a%41b",
        "[::1]",
        "[::1]:443",
        "[::]",
        "[2001:db8::1]",
        "[1:2:3:4:5:6:7:8]",
        "[1:2:3:4:5:6:7::]",
        "[::ffff:10.0.0.1]",
        "[1:2:3:4:5:6:10.0.0.1]",
    ] {
        let bytes = std::format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        assert_eq!(request_head(bytes.as_bytes()).map(|h| h.host), Ok(host.as_bytes()), "{host}");
    }
}

#[test]
fn non_authority_hosts_are_refused() {
    for host in [
        "",
        "a b",
        "a/b",
        "user@a",
        "a:",
        "a:x",
        "a:65536",
        "a:123456",
        ":80",
        "a%4",
        "[::1",
        "[::1]x",
        "[::1]:",
        "[zz::1]",
        "[1:2]",
        "[1:2:3:4:5:6:7:8:9]",
        "[1::2::3]",
        "[1:2:3:4:5:6:7:8::]",
        "[::1.2.3.256]",
        "[::01.2.3.4]",
        "[12345::]",
        "[v1.x]",
        "a,b:1:2",
    ] {
        let bytes = std::format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        assert_eq!(refusal(bytes.as_bytes()), HttpRefusal::Host, "{host:?}");
    }
}

/// Pins `is_ipv6` across its piece step (M6 plan Re-plan R3): elision at
/// either end or inside, once only; an IPv4 tail worth two pieces; exactly
/// eight pieces without elision, at most seven with it.
#[test]
fn ipv6_literals_follow_rfc_3986() {
    let table: &[(&str, bool)] = &[
        ("::", true),
        ("::1", true),
        ("1::", true),
        ("1::8", true),
        ("fe80::1:2", true),
        ("1:2:3:4:5:6:7:8", true),
        ("1:2:3:4:5:6:7::", true),
        ("::2:3:4:5:6:7:8", true),
        ("ABCD:ef01::", true),
        ("::ffff:1.2.3.4", true),
        ("1:2:3:4:5:6:1.2.3.4", true),
        ("1::1.2.3.4", true),
        ("", false),
        (":", false),
        (":::", false),
        (":1", false),
        ("1:", false),
        ("1:::2", false),
        ("1::2::3", false),
        ("::1::", false),
        ("::1:2:3:4:5:6:7:8", false),
        ("1:2:3:4:5:6:7", false),
        ("1:2:3:4:5:6:7:8:9", false),
        ("1:2:3:4:5:6:7:8::", false),
        ("1:2:3:4:5:6:7:1.2.3.4", false),
        ("1:2:3:4:5:6:7::1.2.3.4", false),
        ("1.2.3.4", false),
        ("::1.2.3", false),
        ("::1.2.3.4:5", false),
        ("::01.2.3.4", false),
        ("12345::", false),
        ("g::", false),
        ("1:2::", true),
        (":1:2", false),
    ];
    for &(addr, valid) in table {
        assert_eq!(is_ipv6(addr.as_bytes()), valid, "{addr:?}");
    }
}

/// `is_ipv4` as it was, over `split` and `is_dec_octet`: the single pass
/// replaced it (M6 plan Re-plan R3) so that its Kani harness stays
/// single-level, and must agree with it on every input.
fn reference_ipv4(s: &[u8]) -> bool {
    fn dec_octet(p: &[u8]) -> bool {
        match p {
            [b'0'] => true,
            [b'1'..=b'9', ..] => p.len() <= 3 && p.iter().all(u8::is_ascii_digit) && std::str::from_utf8(p).unwrap().parse::<u16>().unwrap() <= 255,
            _ => false,
        }
    }
    let mut parts = s.split(|&b| b == b'.');
    (0..4).all(|_| parts.next().is_some_and(dec_octet)) && parts.next().is_none()
}

#[test]
fn ipv4_agrees_with_the_reference_on_every_short_string() {
    // Every string of up to 7 bytes over an alphabet that reaches each
    // branch: zero, small and large digits, the dot, a non-digit.
    const ALPHABET: &[u8] = b"0125.9x";
    let mut strings: Vec<Vec<u8>> = std::vec![Vec::new()];
    let mut last = strings.clone();
    for _ in 0..7 {
        last = last.iter().flat_map(|s| ALPHABET.iter().map(move |&b| [s.as_slice(), &[b]].concat())).collect();
        strings.extend(last.iter().cloned());
    }
    for s in &strings {
        assert_eq!(is_ipv4(s), reference_ipv4(s), "{:?}", std::str::from_utf8(s));
    }
    for s in ["255.255.255.255", "256.0.0.0", "0.0.0.0", "199.200.249.250", "1.2.3.4.5", "1..2.3", "300.1.1.1", "10.0.0.010", "1.2.3.25x"] {
        assert_eq!(is_ipv4(s.as_bytes()), reference_ipv4(s.as_bytes()), "{s}");
    }
}

// --- Connection ---

#[test]
fn connection_naming_a_protected_field_is_refused() {
    for name in ["content-length", "Transfer-Encoding", "HOST", "X-Forwarded-For", "x-forwarded-proto", "connection"] {
        let bytes = req(&std::format!("Connection: keep-alive, {name}\r\n"));
        assert_eq!(refusal(&bytes), HttpRefusal::ConnectionNamesProtected, "{name}");
    }
}

#[test]
fn connection_naming_ordinary_fields_is_accepted() {
    assert!(request_head(&req("Connection: keep-alive, , X-Custom\r\nConnection: close\r\n")).is_ok());
}

#[test]
fn connection_elements_must_be_tokens() {
    assert_eq!(refusal(&req("Connection: a b\r\n")), HttpRefusal::ConnectionOption);
}

// --- rewrite ---

#[test]
fn rewrite_drops_hop_by_hop_and_forwarding_fields_exactly() {
    let bytes = b"POST /api?x=1 HTTP/1.1\r\n\
Host: example.com\r\n\
Connection: keep-alive, X-Secret\r\n\
X-Secret: s\r\n\
Keep-Alive: timeout=5\r\n\
Proxy-Authorization: Basic Zm9v\r\n\
proxy-connection: keep-alive\r\n\
Proxy: http://evil.example:8080\r\n\
TE: trailers\r\n\
Trailer: X-T\r\n\
Forwarded: for=127.0.0.1\r\n\
X-Real-IP: 127.0.0.1\r\n\
X-Forwarded-For: 127.0.0.1\r\n\
x-forwarded-proto: http\r\n\
X-Forwarded-Host: evil\r\n\
Accept: */*\r\n\
Content-Length: 2\r\n\
\r\n";
    let expected = b"POST /api?x=1 HTTP/1.1\r\n\
Host: example.com\r\n\
Accept: */*\r\n\
Content-Length: 2\r\n\
X-Forwarded-For: 192.0.2.7\r\n\
X-Forwarded-Proto: https\r\n\
Connection: close\r\n\
\r\n";
    assert_eq!(rewritten(bytes, [192, 0, 2, 7]), expected);
}

/// The client-address fields a CDN or proxy sets (S4): each one dropped, so
/// the head with it rewrites byte for byte as the head without it.
const CLIENT_ADDRESS_FIELDS: [&str; 7] = [
    "True-Client-IP",
    "X-Client-IP",
    "X-Cluster-Client-IP",
    "CF-Connecting-IP",
    "Fastly-Client-IP",
    "X-Original-Forwarded-For",
    "Client-IP",
];

#[test]
fn rewrite_drops_each_client_address_field() {
    let plain = rewritten(&req("Accept: */*\r\n"), [192, 0, 2, 7]);
    for field in CLIENT_ADDRESS_FIELDS {
        let with = req(&std::format!("{field}: 127.0.0.1\r\nAccept: */*\r\n"));
        assert_eq!(rewritten(&with, [192, 0, 2, 7]), plain, "{field}");
        let lower = req(&std::format!("{}: 127.0.0.1\r\nAccept: */*\r\n", field.to_ascii_lowercase()));
        assert_eq!(rewritten(&lower, [192, 0, 2, 7]), plain, "{field} in lower case");
    }
}

/// The allow side: a custom field whose name only extends one of them
/// passes unchanged, in its place.
#[test]
fn rewrite_keeps_a_custom_field_that_only_resembles_a_client_address_field() {
    let fields = "X-Client-IP-Hint: 127.0.0.1\r\nAccept: */*\r\n";
    let expected = std::format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\n{fields}X-Forwarded-For: 192.0.2.7\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n"
    );
    assert_eq!(rewritten(&req(fields), [192, 0, 2, 7]), expected.as_bytes());
}

/// Envoy's fields (external review E1): X-Envoy-External-Address is
/// dropped, and the ordinary custom field beside it passes byte for byte.
#[test]
fn rewrite_drops_an_x_envoy_field_and_keeps_a_custom_field() {
    let kept = "X-Custom: value\r\n";
    let with = req(&std::format!("X-Envoy-External-Address: 127.0.0.1\r\n{kept}"));
    let expected = std::format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\n{kept}X-Forwarded-For: 192.0.2.7\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n"
    );
    assert_eq!(rewritten(&with, [192, 0, 2, 7]), expected.as_bytes());
}

#[test]
fn rewrite_passes_ordinary_fields_unchanged() {
    let fields = "User-Agent: curl/8.11.1\r\nX-Custom:\tvalue  \r\nCookie: a=b; c=d\r\nX-Forwarded: kept\r\nProxyish: kept\r\n";
    let bytes = req(fields);
    let expected = std::format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\n{fields}X-Forwarded-For: 10.0.0.1\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n"
    );
    assert_eq!(rewritten(&bytes, [10, 0, 0, 1]), expected.as_bytes());
}

#[test]
fn rewrite_writes_every_address_in_decimal() {
    let out = rewritten(&req(""), [255, 0, 10, 100]);
    assert!(out.windows(30).any(|w| w == b"X-Forwarded-For: 255.0.10.100\r"));
}

#[test]
fn rewrite_refuses_a_buffer_one_byte_short_with_431() {
    let bytes = req("Accept: */*\r\n");
    let full = rewritten(&bytes, [192, 0, 2, 1]);
    let head = request_head(&bytes).unwrap();
    let mut out = std::vec![0u8; full.len() - 1];
    let r = rewrite(&head, [192, 0, 2, 1], &mut out).unwrap_err();
    assert_eq!((r, r.status()), (HttpRefusal::RewriteTooLarge, Status::HeaderFieldsTooLarge));
    let mut out = std::vec![0u8; full.len()];
    assert_eq!(rewrite(&head, [192, 0, 2, 1], &mut out), Ok(full.len()));
}

#[test]
fn rewrite_of_the_largest_head_fits_max_rewrite() {
    let bytes = head_of_len(MAX_HEAD);
    assert_eq!(rewritten(&bytes, [255; 4]).len(), MAX_HEAD + REWRITE_GROWTH);
}

// --- the Connection list step ---

/// The splitter `next_option` replaced (M6 plan Re-plan R3): `is_dropped`
/// decides by it which fields reach the backend, so the step must agree
/// with it on every input.
fn reference_options(value: &[u8]) -> Vec<&[u8]> {
    value.split(|&b| b == b',').map(trim_ows).filter(|o| !o.is_empty()).collect()
}

fn stepped_options(value: &[u8]) -> Vec<&[u8]> {
    let mut rest = value;
    let options: Vec<&[u8]> = core::iter::from_fn(|| next_option(&mut rest)).collect();
    assert!(rest.is_empty());
    options
}

#[test]
fn next_option_agrees_with_the_reference_splitter_on_list_edges() {
    let table: &[(&[u8], &[&[u8]])] = &[
        (b"", &[]),
        (b",,,", &[]),
        (b"a,,,b", &[b"a", b"b"]),
        (b",,a,,", &[b"a"]),
        (b"   ", &[]),
        (b" \t a \t , \t b \t ", &[b"a", b"b"]),
        (b"a, b c ,d", &[b"a", b"b c", b"d"]),
        (b"keep-alive,", &[b"keep-alive"]),
        (b"a,\t,b", &[b"a", b"b"]),
        (b"\t", &[]),
    ];
    for (value, expected) in table {
        assert_eq!(reference_options(value), *expected, "reference {value:?}");
        assert_eq!(stepped_options(value), *expected, "next_option {value:?}");
    }
}

// --- seeds and the fuzz target ---

#[test]
fn seeds_meet_their_expected_outcome() {
    use HttpRefusal::*;
    let table: &[(&str, Result<(), HttpRefusal>)] = &[
        ("seed-get-valid", Ok(())),
        ("seed-post-valid", Ok(())),
        ("seed-forwarding-spoof", Ok(())),
        ("seed-cl-te", Err(TransferEncoding)),
        ("seed-te-cl", Err(TransferEncoding)),
        ("seed-te-te", Err(TransferEncoding)),
        ("seed-te-space-before-colon", Err(FieldName)),
        ("seed-duplicate-cl", Err(DuplicateContentLength)),
        ("seed-signed-cl", Err(ContentLength)),
        ("seed-spaced-cl", Err(ContentLength)),
        ("seed-obs-fold", Err(ObsFold)),
        ("seed-bare-lf", Err(BareLineEnding)),
        ("seed-connection-content-length", Err(ConnectionNamesProtected)),
        ("seed-underscore-name", Err(UnderscoreName)),
        ("seed-expect", Err(Expect)),
        ("seed-upgrade", Err(Upgrade)),
        ("seed-absolute-form", Err(AbsoluteForm)),
    ];
    let mut names: Vec<String> = std::fs::read_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("seed-"))
        .collect();
    names.sort();
    let mut listed: Vec<&str> = table.iter().map(|(n, _)| *n).collect();
    listed.sort();
    assert_eq!(names, listed, "every committed seed has an expected outcome");
    for (name, expected) in table {
        let bytes = seed(name);
        // As the PD does: delimit the head, then parse exactly it.
        let outcome = head_end(&bytes).and_then(|end| request_head(&bytes[..end.unwrap()]).map(|_| ()));
        assert_eq!(outcome, *expected, "{name}");
        fuzz_one(&bytes);
    }
}

#[test]
fn spoofed_forwarding_seed_reaches_the_backend_with_ours_only() {
    let bytes = seed("seed-forwarding-spoof");
    let out = rewritten(&bytes, [198, 51, 100, 9]);
    let text = std::str::from_utf8(&out).unwrap();
    assert_eq!(
        text,
        "GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 198.51.100.9\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n"
    );
}

fn inside(outer: &[u8], inner: &[u8]) -> bool {
    let (o, i) = (outer.as_ptr_range(), inner.as_ptr_range());
    o.start <= i.start && i.end <= o.end
}

/// What the fuzz target checks for any input: the PD's delimit-then-parse
/// never panics; an accepted head borrows only from itself, is what
/// `head_end` delimits, carries no refused field, and its rewrite fits the
/// stated bound and parses again to the same request with only our
/// forwarding fields and `Connection: close`.
fn fuzz_one(bytes: &[u8]) {
    let head = match head_end(bytes) {
        Ok(Some(n)) => &bytes[..n],
        _ => bytes,
    };
    let Ok(h) = request_head(head) else { return };
    assert_eq!(head_end(head), Ok(Some(head.len())));
    assert!(inside(head, h.line) && inside(h.line, h.method) && inside(h.line, h.target) && inside(head, h.host));
    assert!(h.content_length <= MAX_BODY && h.headers().len() <= MAX_HEADERS);
    for f in h.headers() {
        assert!(inside(head, f.line) && inside(f.line, f.name) && inside(f.line, f.value));
        for refused in [&b"transfer-encoding"[..], b"upgrade", b"expect"] {
            assert!(!f.name.eq_ignore_ascii_case(refused));
        }
    }
    let count = |head: &Head<'_, { MAX_HEADERS + 3 }>, name: &[u8]| {
        head.headers().iter().filter(|f| f.name.eq_ignore_ascii_case(name)).count()
    };
    let mut out = std::vec![0u8; MAX_REWRITE];
    let n = rewrite(&h, [192, 0, 2, 1], &mut out).unwrap();
    assert!(n <= head.len() + REWRITE_GROWTH);
    if n > MAX_HEAD {
        return;
    }
    let again = parse::<{ MAX_HEADERS + 3 }>(&out[..n]).unwrap();
    assert_eq!((again.method, again.target, again.host, again.content_length), (h.method, h.target, h.host, h.content_length));
    assert_eq!(count(&again, b"content-length"), h.headers().iter().filter(|f| f.name.eq_ignore_ascii_case(b"content-length")).count());
    for name in [&b"x-forwarded-for"[..], b"x-forwarded-proto", b"connection"] {
        assert_eq!(count(&again, name), 1);
    }
    for f in again.headers() {
        for dropped in [&b"keep-alive"[..], b"te", b"trailer", b"forwarded", b"x-real-ip", b"true-client-ip", b"client-ip"] {
            assert!(!f.name.eq_ignore_ascii_case(dropped));
        }
    }
    let tail = &again.headers()[again.headers().len() - 3..];
    assert_eq!(tail[0].line, b"X-Forwarded-For: 192.0.2.1");
    assert_eq!(tail[1].line, b"X-Forwarded-Proto: https");
    assert_eq!(tail[2].line, b"Connection: close");
}

#[test]
fn fuzz_parse_never_panics_and_rewrite_reparses() {
    bolero::check!().for_each(fuzz_one);
}

/// `next_option` collected over any bytes equals the reference splitter.
fn options_match(bytes: &[u8]) {
    assert_eq!(stepped_options(bytes), reference_options(bytes));
}

#[test]
fn fuzz_next_option_matches_the_reference_splitter() {
    bolero::check!().for_each(options_match);
}

#[test]
fn connection_values_longer_than_max_connection_value_are_refused() {
    let at = [b'a'; MAX_CONNECTION_VALUE];
    assert_eq!(check_connection(&at), Ok(()));
    let over = [b'a'; MAX_CONNECTION_VALUE + 1];
    assert_eq!(check_connection(&over), Err(HttpRefusal::ConnectionOption));
}

#[test]
fn request_head_refuses_a_connection_value_over_max_connection_value() {
    let at = req(&std::format!("Connection: {}\r\n", "a".repeat(MAX_CONNECTION_VALUE)));
    assert!(request_head(&at).is_ok());
    let over = req(&std::format!("Connection: {}\r\n", "a".repeat(MAX_CONNECTION_VALUE + 1)));
    assert_eq!(refusal(&over), HttpRefusal::ConnectionOption);
}
