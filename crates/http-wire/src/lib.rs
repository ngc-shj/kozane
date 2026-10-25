//! HTTP/1.1 request head parsing and rewriting for the `tls` PD (M6 plan
//! C9): one request per connection, smuggling-prone forms refused.
//!
//! The PD buffers the client's bytes and asks [`head_end`] where the head
//! ends; [`request_head`] parses exactly those bytes, and [`rewrite`] writes
//! what the backend sees: the request line verbatim, the client's field
//! lines minus hop-by-hop and forwarding ones, then ours. No
//! Transfer-Encoding is ever accepted, so the body is exactly
//! [`Head::content_length`] bytes and this parser and the backend cannot
//! disagree on where the request ends.
//!
//! The head is the request line through the blank line, its final CRLF
//! included; [`MAX_HEAD`] bounds that whole span (a head of exactly 8192
//! bytes is accepted, 8193 is refused with 431).
//!
//! Every refusal is an [`HttpRefusal`]; [`HttpRefusal::status`] names the
//! response and [`refusal_response`] its fixed bytes. Faults within a line
//! are found line by line, the first one wins; a missing Host (400),
//! `Expect` (417) and the body bound (413) are decided, in that order, once
//! every line has passed.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

#[cfg(test)]
extern crate std;

/// Largest request head, request line through the blank line's CRLF.
pub const MAX_HEAD: usize = 8 * 1024;
/// Most header fields in a request head.
pub const MAX_HEADERS: usize = 32;
/// Largest request body; a larger `Content-Length` is refused at head time.
pub const MAX_BODY: usize = 1 << 20;
/// Most bytes `rewrite`'s output exceeds its head by: our three field lines
/// with the longest address, less nothing (every other line is copied or
/// dropped, never grown).
pub const REWRITE_GROWTH: usize = XFF_LONGEST.len() + XFP_AND_CLOSE.len() - CRLF.len();
/// A buffer this large holds the rewrite of any accepted head.
pub const MAX_REWRITE: usize = MAX_HEAD + REWRITE_GROWTH;

const CRLF: &[u8] = b"\r\n";
const XFF: &[u8] = b"X-Forwarded-For: ";
const XFF_LONGEST: &[u8] = b"X-Forwarded-For: 255.255.255.255\r\n";
// Ends with the head's blank line.
const XFP_AND_CLOSE: &[u8] = b"X-Forwarded-Proto: https\r\nConnection: close\r\n\r\n";

/// `Connection` may not name these: the framing fields, Host, and the
/// fields `rewrite` sets (M6 plan S5).
const PROTECTED: [&[u8]; 6] = [
    b"content-length",
    b"transfer-encoding",
    b"host",
    b"connection",
    b"x-forwarded-for",
    b"x-forwarded-proto",
];
/// Dropped by `rewrite` besides the fields `Connection` names. `Proxy`
/// is not hop-by-hop, but CGI-style backends read it as `HTTP_PROXY`
/// (httpoxy, CVE-2016-5385), so it goes with `Proxy-*`. The client-address
/// fields CDNs and proxies set (from `Forwarded` on, and Envoy's
/// `X-Envoy-*`) go too: a backend that trusts any of them would take the
/// client's word for its address (M6 code review S4).
///
/// The trust contract: the backend may trust only the `X-Forwarded-For`
/// this proxy generates for the client address. These lists are defence in
/// depth against a backend that reads another field, not the boundary; a
/// field no list names still reaches the backend.
const DROPPED: [&[u8]; 15] = [
    b"proxy",
    b"connection",
    b"keep-alive",
    b"te",
    b"trailer",
    b"upgrade",
    b"forwarded",
    b"x-real-ip",
    b"true-client-ip",
    b"x-client-ip",
    b"x-cluster-client-ip",
    b"cf-connecting-ip",
    b"fastly-client-ip",
    b"x-original-forwarded-for",
    b"client-ip",
];
const DROPPED_PREFIXES: [&[u8]; 3] = [b"proxy-", b"x-forwarded-", b"x-envoy-"];

/// The responses `tls` generates itself (M6 plan C10's audit order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    BadRequest,
    ContentTooLarge,
    ExpectationFailed,
    HeaderFieldsTooLarge,
    NotImplemented,
}

impl Status {
    /// Every variant, in index order (`tls` checks audit-event's table
    /// against it).
    pub const ALL: [Status; 5] = [
        Status::BadRequest,
        Status::ContentTooLarge,
        Status::ExpectationFailed,
        Status::HeaderFieldsTooLarge,
        Status::NotImplemented,
    ];

    pub const fn code(self) -> u16 {
        match self {
            Status::BadRequest => 400,
            Status::ContentTooLarge => 413,
            Status::ExpectationFailed => 417,
            Status::HeaderFieldsTooLarge => 431,
            Status::NotImplemented => 501,
        }
    }

    /// The offset in C10's `HTTP_REFUSED_BASE + status index` audit codes.
    pub const fn index(self) -> u16 {
        match self {
            Status::BadRequest => 0,
            Status::ContentTooLarge => 1,
            Status::ExpectationFailed => 2,
            Status::HeaderFieldsTooLarge => 3,
            Status::NotImplemented => 4,
        }
    }
}

/// The complete response for `status`: fixed text body, `Connection:
/// close` (the connection ends after it, C10).
pub const fn refusal_response(status: Status) -> &'static [u8] {
    match status {
        Status::BadRequest => {
            b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 12\r\nConnection: close\r\n\r\nBad Request\n"
        }
        Status::ContentTooLarge => {
            b"HTTP/1.1 413 Content Too Large\r\nContent-Type: text/plain\r\nContent-Length: 18\r\nConnection: close\r\n\r\nContent Too Large\n"
        }
        Status::ExpectationFailed => {
            b"HTTP/1.1 417 Expectation Failed\r\nContent-Type: text/plain\r\nContent-Length: 19\r\nConnection: close\r\n\r\nExpectation Failed\n"
        }
        Status::HeaderFieldsTooLarge => {
            b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: text/plain\r\nContent-Length: 32\r\nConnection: close\r\n\r\nRequest Header Fields Too Large\n"
        }
        Status::NotImplemented => {
            b"HTTP/1.1 501 Not Implemented\r\nContent-Type: text/plain\r\nContent-Length: 16\r\nConnection: close\r\n\r\nNot Implemented\n"
        }
    }
}

/// Why a request was refused. 400 is any syntax fault; 501 is a method,
/// target form or feature this proxy does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpRefusal {
    /// A LF without the CR before it, or a CR the PD saw without its LF.
    BareLineEnding,
    /// No blank line ends the head.
    Unterminated,
    /// Bytes after the blank line given to `request_head`.
    TrailingBytes,
    /// Not `method SP target SP version`, or the method is not a token.
    RequestLine,
    /// A target that is no origin-form (RFC 9112 section 3.2.1).
    Target,
    /// Anything but `HTTP/1.1`.
    Version,
    /// A field line starting with whitespace (obsolete line folding).
    ObsFold,
    /// A field line without a colon.
    HeaderLine,
    /// A field name that is not a token, whitespace before the colon among
    /// them.
    FieldName,
    /// A field name with `_` (M6 plan S5: proxies may fold it into `-`).
    UnderscoreName,
    /// A field value with a CTL other than HTAB (NUL, CR, DEL, ...).
    FieldValue,
    /// `Content-Length` that is not one decimal number without sign or
    /// leading zero.
    ContentLength,
    DuplicateContentLength,
    MissingHost,
    DuplicateHost,
    /// A Host value that is not `host [":" port]` (RFC 3986 authority, no
    /// userinfo).
    Host,
    /// A `Connection` element that is not a token.
    ConnectionOption,
    /// `Connection` names Content-Length, Transfer-Encoding, Host or a
    /// field `rewrite` sets.
    ConnectionNamesProtected,
    /// `Content-Length` above `MAX_BODY`.
    BodyTooLarge,
    /// Any `Expect` field.
    Expect,
    /// The head exceeds `MAX_HEAD`.
    HeadTooLarge,
    /// More than `MAX_HEADERS` fields.
    TooManyHeaders,
    /// `rewrite`'s output does not fit its buffer.
    RewriteTooLarge,
    /// `CONNECT`, in any letter case.
    Connect,
    /// A target with a scheme, or authority-form outside CONNECT.
    AbsoluteForm,
    AsteriskForm,
    /// Any `Transfer-Encoding` field: bodies are `Content-Length` only.
    TransferEncoding,
    /// Any `Upgrade` field.
    Upgrade,
}

impl HttpRefusal {
    pub const fn status(self) -> Status {
        match self {
            HttpRefusal::BareLineEnding
            | HttpRefusal::Unterminated
            | HttpRefusal::TrailingBytes
            | HttpRefusal::RequestLine
            | HttpRefusal::Target
            | HttpRefusal::Version
            | HttpRefusal::ObsFold
            | HttpRefusal::HeaderLine
            | HttpRefusal::FieldName
            | HttpRefusal::UnderscoreName
            | HttpRefusal::FieldValue
            | HttpRefusal::ContentLength
            | HttpRefusal::DuplicateContentLength
            | HttpRefusal::MissingHost
            | HttpRefusal::DuplicateHost
            | HttpRefusal::Host
            | HttpRefusal::ConnectionOption
            | HttpRefusal::ConnectionNamesProtected => Status::BadRequest,
            HttpRefusal::BodyTooLarge => Status::ContentTooLarge,
            HttpRefusal::Expect => Status::ExpectationFailed,
            HttpRefusal::HeadTooLarge | HttpRefusal::TooManyHeaders | HttpRefusal::RewriteTooLarge => {
                Status::HeaderFieldsTooLarge
            }
            HttpRefusal::Connect
            | HttpRefusal::AbsoluteForm
            | HttpRefusal::AsteriskForm
            | HttpRefusal::TransferEncoding
            | HttpRefusal::Upgrade => Status::NotImplemented,
        }
    }
}

/// One field line; every slice borrows from the head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Header<'a> {
    pub name: &'a [u8],
    /// Without the whitespace around it.
    pub value: &'a [u8],
    /// The whole line without its CRLF, forwarded as received.
    pub line: &'a [u8],
}

/// An accepted request head. `N` bounds the fields (`MAX_HEADERS`; the Kani
/// harnesses use fewer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head<'a, const N: usize = MAX_HEADERS> {
    /// The whole head, blank line included.
    pub bytes: &'a [u8],
    /// The request line without its CRLF.
    pub line: &'a [u8],
    pub method: &'a [u8],
    pub target: &'a [u8],
    /// The one Host field's value.
    pub host: &'a [u8],
    /// The body length, 0 without `Content-Length`; at most `MAX_BODY`.
    pub content_length: usize,
    headers: [Header<'a>; N],
    count: usize,
}

impl<'a, const N: usize> Head<'a, N> {
    pub fn headers(&self) -> &[Header<'a>] {
        self.headers.get(..self.count).unwrap_or(&[])
    }
}

/// Where the head in `bytes` ends: `Some(n)` when its first `n` bytes are a
/// head (blank line included), `None` while it may still end within
/// `MAX_HEAD`. A bare CR or LF refuses at once rather than waiting for a
/// CRLFCRLF that a bare-LF client never sends.
pub fn head_end(bytes: &[u8]) -> Result<Option<usize>, HttpRefusal> {
    let window = bytes.get(..MAX_HEAD).unwrap_or(bytes);
    let mut prev = 0u8;
    for (i, &b) in window.iter().enumerate() {
        if b == b'\n' {
            if prev != b'\r' {
                return Err(HttpRefusal::BareLineEnding);
            }
            if i.checked_sub(3).and_then(|start| window.get(start..i)) == Some(b"\r\n\r") {
                return Ok(Some(i.wrapping_add(1)));
            }
        } else if prev == b'\r' {
            return Err(HttpRefusal::BareLineEnding);
        }
        prev = b;
    }
    if window.len() >= MAX_HEAD { Err(HttpRefusal::HeadTooLarge) } else { Ok(None) }
}

/// Parses `bytes`, which must be exactly one head (as `head_end` delimits
/// it): request line, at most `MAX_HEADERS` field lines, blank line.
pub fn request_head(bytes: &[u8]) -> Result<Head<'_>, HttpRefusal> {
    parse::<MAX_HEADERS>(bytes)
}

fn parse<const N: usize>(bytes: &[u8]) -> Result<Head<'_, N>, HttpRefusal> {
    if bytes.len() > MAX_HEAD {
        return Err(HttpRefusal::HeadTooLarge);
    }
    let mut rest = bytes;
    let line = next_line(&mut rest)?;
    let (method, target) = request_line(line)?;
    let mut head = Head {
        bytes,
        line,
        method,
        target,
        host: &[],
        content_length: 0,
        headers: [Header::default(); N],
        count: 0,
    };
    let mut host = None;
    let mut content_length = None;
    let mut expect = false;
    // One pass more than N: the blank line ends the head, a field line
    // there is one too many.
    for _ in 0..=N {
        let line = next_line(&mut rest)?;
        if line.is_empty() {
            if !rest.is_empty() {
                return Err(HttpRefusal::TrailingBytes);
            }
            head.host = host.ok_or(HttpRefusal::MissingHost)?;
            if expect {
                return Err(HttpRefusal::Expect);
            }
            head.content_length = content_length.unwrap_or(0);
            if head.content_length > MAX_BODY {
                return Err(HttpRefusal::BodyTooLarge);
            }
            return Ok(head);
        }
        let h = field_line(line)?;
        *head.headers.get_mut(head.count).ok_or(HttpRefusal::TooManyHeaders)? = h;
        head.count = head.count.wrapping_add(1);
        let name = h.name;
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(HttpRefusal::TransferEncoding);
        } else if name.eq_ignore_ascii_case(b"upgrade") {
            return Err(HttpRefusal::Upgrade);
        } else if name.eq_ignore_ascii_case(b"content-length") {
            if content_length.is_some() {
                return Err(HttpRefusal::DuplicateContentLength);
            }
            content_length = Some(parse_content_length(h.value)?);
        } else if name.eq_ignore_ascii_case(b"host") {
            if host.is_some() {
                return Err(HttpRefusal::DuplicateHost);
            }
            if !is_authority(h.value) {
                return Err(HttpRefusal::Host);
            }
            host = Some(h.value);
        } else if name.eq_ignore_ascii_case(b"expect") {
            expect = true;
        } else if name.eq_ignore_ascii_case(b"connection") {
            check_connection(h.value)?;
        }
    }
    Err(HttpRefusal::TooManyHeaders)
}

/// Takes the next line off `rest`, without its CRLF.
fn next_line<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8], HttpRefusal> {
    let at = rest.iter().position(|&b| b == b'\n').ok_or(HttpRefusal::Unterminated)?;
    let (line, tail) = rest.split_at_checked(at).ok_or(HttpRefusal::Unterminated)?;
    *rest = tail.get(1..).unwrap_or(&[]);
    // A CR elsewhere in the line fails the line's own character rules.
    line.strip_suffix(b"\r").ok_or(HttpRefusal::BareLineEnding)
}

/// `method SP origin-form SP HTTP/1.1` (RFC 9112 section 3), single spaces.
fn request_line(line: &[u8]) -> Result<(&[u8], &[u8]), HttpRefusal> {
    let mut parts = line.splitn(3, |&b| b == b' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(HttpRefusal::RequestLine);
    };
    if !is_token(method) {
        return Err(HttpRefusal::RequestLine);
    }
    if version != b"HTTP/1.1" {
        return Err(HttpRefusal::Version);
    }
    // Methods are case-sensitive, but a backend that folds case must not
    // see a tunnel request either.
    if method.eq_ignore_ascii_case(b"CONNECT") {
        return Err(HttpRefusal::Connect);
    }
    match target.first() {
        Some(b'/') => {}
        Some(b'*') if target.len() == 1 => return Err(HttpRefusal::AsteriskForm),
        _ if has_scheme(target) => return Err(HttpRefusal::AbsoluteForm),
        _ => return Err(HttpRefusal::Target),
    }
    // absolute-path [ "?" query ]: segments are pchars, the query adds "/"
    // and "?", and the path ends at the first "?", so one pass over the
    // query's set checks both (RFC 3986 section 3.3, 3.4).
    if !uri_chars(target, b":@/?") {
        return Err(HttpRefusal::Target);
    }
    Ok((method, target))
}

/// `scheme ":"` at the start (RFC 3986 section 3.1); also catches
/// authority-form `host:port`, which only CONNECT may use.
fn has_scheme(target: &[u8]) -> bool {
    let Some(colon) = target.iter().position(|&b| b == b':') else {
        return false;
    };
    let scheme = target.get(..colon).unwrap_or(&[]);
    scheme.first().is_some_and(u8::is_ascii_alphabetic)
        && scheme.iter().all(|&b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
}

/// `field-name ":" OWS field-value OWS` (RFC 9112 section 5).
fn field_line(line: &[u8]) -> Result<Header<'_>, HttpRefusal> {
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return Err(HttpRefusal::ObsFold);
    }
    let colon = line.iter().position(|&b| b == b':').ok_or(HttpRefusal::HeaderLine)?;
    let (name, rest) = line.split_at_checked(colon).ok_or(HttpRefusal::HeaderLine)?;
    if name.contains(&b'_') {
        return Err(HttpRefusal::UnderscoreName);
    }
    if !is_token(name) {
        return Err(HttpRefusal::FieldName);
    }
    let raw = rest.get(1..).unwrap_or(&[]);
    // VCHAR, obs-text, SP and HTAB; no other CTL (M6 plan S15).
    if raw.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Err(HttpRefusal::FieldValue);
    }
    Ok(Header { name, value: trim_ows(raw), line })
}

/// One decimal number, no sign, no inner whitespace, no leading zero (a
/// parser down the line reading it as octal would disagree). The value
/// saturates just above `MAX_BODY`, so any length of digits is overflow-free
/// and still refused as too large.
fn parse_content_length(value: &[u8]) -> Result<usize, HttpRefusal> {
    let leading_zero = value.len() > 1 && value.first() == Some(&b'0');
    if value.is_empty() || leading_zero || !value.iter().all(u8::is_ascii_digit) {
        return Err(HttpRefusal::ContentLength);
    }
    Ok(value.iter().fold(0usize, |n, &d| {
        n.saturating_mul(10).saturating_add(usize::from(d.wrapping_sub(b'0'))).min(MAX_BODY.saturating_add(1))
    }))
}

/// Every element a token, none of them `PROTECTED` (RFC 9110 section 7.6.1
/// lists may hold empty elements).
fn check_connection(value: &[u8]) -> Result<(), HttpRefusal> {
    for option in options(value) {
        if !is_token(option) {
            return Err(HttpRefusal::ConnectionOption);
        }
        if PROTECTED.iter().any(|p| option.eq_ignore_ascii_case(p)) {
            return Err(HttpRefusal::ConnectionNamesProtected);
        }
    }
    Ok(())
}

fn options(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    value.split(|&b| b == b',').map(trim_ows).filter(|o| !o.is_empty())
}

/// `host [":" port]` with host an IP-literal (IPv6 only, no IPvFuture) or a
/// non-empty reg-name (which covers IPv4address); port 0..=65535.
fn is_authority(value: &[u8]) -> bool {
    let (host_ok, port) = match value.strip_prefix(b"[") {
        Some(inner) => {
            let Some(close) = inner.iter().position(|&b| b == b']') else {
                return false;
            };
            let (addr, after) = inner.split_at_checked(close).unwrap_or_default();
            (is_ipv6(addr), after.get(1..).unwrap_or(&[]))
        }
        None => {
            let end = value.iter().position(|&b| b == b':').unwrap_or(value.len());
            let (name, after) = value.split_at_checked(end).unwrap_or_default();
            (!name.is_empty() && uri_chars(name, b""), after)
        }
    };
    host_ok
        && match port {
            [] => true,
            [b':', digits @ ..] => is_port(digits),
            _ => false,
        }
}

fn is_port(digits: &[u8]) -> bool {
    !digits.is_empty()
        && digits.len() <= 5
        && digits.iter().all(u8::is_ascii_digit)
        && digits.iter().fold(0u32, |n, &d| n.wrapping_mul(10).wrapping_add(u32::from(d.wrapping_sub(b'0')))) <= 65535
}

/// RFC 3986 section 3.2.2 IPv6address: eight 16-bit pieces, or fewer with
/// one `::` standing for at least one; the last two may be a dotted IPv4.
fn is_ipv6(addr: &[u8]) -> bool {
    let mut rest = addr;
    let mut groups = 0usize;
    let mut elided = false;
    if let Some(r) = rest.strip_prefix(b"::") {
        elided = true;
        rest = r;
        if rest.is_empty() {
            return true;
        }
    }
    // Each pass takes one piece; a ninth is never valid.
    for _ in 0..8 {
        let end = rest.iter().position(|&b| b == b':').unwrap_or(rest.len());
        let (piece, after) = rest.split_at_checked(end).unwrap_or_default();
        if after.is_empty() {
            let worth = if piece.contains(&b'.') {
                if !is_ipv4(piece) {
                    return false;
                }
                2
            } else {
                if !is_h16(piece) {
                    return false;
                }
                1
            };
            groups = groups.wrapping_add(worth);
            return if elided { groups <= 7 } else { groups == 8 };
        }
        if !is_h16(piece) {
            return false;
        }
        groups = groups.wrapping_add(1);
        rest = after.get(1..).unwrap_or(&[]);
        if let Some(r) = rest.strip_prefix(b":") {
            if elided {
                return false;
            }
            elided = true;
            rest = r;
            if rest.is_empty() {
                return groups <= 7;
            }
        } else if rest.is_empty() {
            return false;
        }
    }
    false
}

fn is_h16(piece: &[u8]) -> bool {
    (1..=4).contains(&piece.len()) && piece.iter().all(u8::is_ascii_hexdigit)
}

fn is_ipv4(s: &[u8]) -> bool {
    let mut parts = s.split(|&b| b == b'.');
    (0..4).all(|_| parts.next().is_some_and(is_dec_octet)) && parts.next().is_none()
}

fn is_dec_octet(p: &[u8]) -> bool {
    match p {
        [b'0'] => true,
        [b'1'..=b'9', ..] => {
            p.len() <= 3
                && p.iter().all(u8::is_ascii_digit)
                && p.iter().fold(0u16, |n, &d| n.wrapping_mul(10).wrapping_add(u16::from(d.wrapping_sub(b'0')))) <= 255
        }
        _ => false,
    }
}

/// unreserved / sub-delims / pct-encoded / `extra` (RFC 3986 section 2).
fn uri_chars(s: &[u8], extra: &[u8]) -> bool {
    let mut bytes = s.iter();
    while let Some(&b) = bytes.next() {
        let ok = if b == b'%' {
            matches!((bytes.next(), bytes.next()), (Some(h), Some(l)) if h.is_ascii_hexdigit() && l.is_ascii_hexdigit())
        } else {
            b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&b) || extra.contains(&b)
        };
        if !ok {
            return false;
        }
    }
    true
}

/// `1*tchar` (RFC 9110 section 5.6.2).
fn is_token(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|&b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn trim_ows(s: &[u8]) -> &[u8] {
    let ows = |b: &u8| *b == b' ' || *b == b'\t';
    let start = s.iter().position(|b| !ows(b)).unwrap_or(s.len());
    let end = s.iter().rposition(|b| !ows(b)).map_or(start, |e| e.wrapping_add(1));
    s.get(start..end).unwrap_or(&[])
}

/// Writes the head the backend sees into `out`: the request line verbatim;
/// the field lines verbatim minus `Connection` and the fields it names,
/// `Keep-Alive`, `Proxy` and `Proxy-*`, `TE`, `Trailer`, `Upgrade`, `Forwarded`,
/// `X-Real-IP`, the other client-address fields of `DROPPED`,
/// `X-Forwarded-*` and `X-Envoy-*`; then `X-Forwarded-For: <client_ip>`,
/// `X-Forwarded-Proto: https`, `Connection: close` and the blank line.
/// Returns the length written; `MAX_REWRITE` bytes always suffice.
pub fn rewrite<const N: usize>(head: &Head<'_, N>, client_ip: [u8; 4], out: &mut [u8]) -> Result<usize, HttpRefusal> {
    let mut w = Writer { out, len: 0 };
    w.put(head.line)?;
    w.put(CRLF)?;
    for h in head.headers() {
        if !is_dropped(head, h.name) {
            w.put(h.line)?;
            w.put(CRLF)?;
        }
    }
    w.put(XFF)?;
    for (i, &octet) in client_ip.iter().enumerate() {
        if i > 0 {
            w.put(b".")?;
        }
        w.put_decimal(octet)?;
    }
    w.put(CRLF)?;
    w.put(XFP_AND_CLOSE)?;
    Ok(w.len)
}

fn is_dropped<const N: usize>(head: &Head<'_, N>, name: &[u8]) -> bool {
    DROPPED.iter().any(|d| name.eq_ignore_ascii_case(d))
        || DROPPED_PREFIXES.iter().any(|p| name.get(..p.len()).is_some_and(|s| s.eq_ignore_ascii_case(p)))
        || head
            .headers()
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(b"connection"))
            .any(|h| options(h.value).any(|o| o.eq_ignore_ascii_case(name)))
}

struct Writer<'o> {
    out: &'o mut [u8],
    len: usize,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), HttpRefusal> {
        let end = self.len.checked_add(bytes.len()).ok_or(HttpRefusal::RewriteTooLarge)?;
        self.out.get_mut(self.len..end).ok_or(HttpRefusal::RewriteTooLarge)?.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    fn put_decimal(&mut self, v: u8) -> Result<(), HttpRefusal> {
        let digits = [b'0'.wrapping_add(v / 100), b'0'.wrapping_add(v / 10 % 10), b'0'.wrapping_add(v % 10)];
        let skip = match v {
            100.. => 0,
            10..=99 => 1,
            _ => 2,
        };
        self.put(digits.get(skip..).unwrap_or(&[]))
    }
}

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests;
