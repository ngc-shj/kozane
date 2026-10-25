//! Kani harnesses for http-wire (M6 plan C9, T15, Re-plan R3). Run with
//! `cargo kani -p http-wire`.
//!
//! Whole-head harnesses never finished: cbmc re-unrolls the slice
//! iterators' inner loops on every pass of the enclosing loop, so the
//! unrolling multiplies with nesting depth. Kani therefore proves each
//! loop's *step* and each per-line function, single-level, over its bound;
//! the composition below is argued, resting on the code's loop structure
//! and Rust's semantics (no unsafe, no aliasing in these functions).
//!
//! # The composition
//!
//! **`parse` is total and every slice it returns lies inside
//! `bytes`.** Step: `next_line` (`next_line_step`, `next_line_step_tail`,
//! `next_line_unterminated`).
//! On `Ok(line)` there is a `k` with `line` equal to `old[..k]` (same
//! pointer, same length), `old[k..k + 2] == b"\r\n"` and the new `rest`
//! equal to `old[k + 2..]`; every `Err` is reached without a panic. By
//! induction over the lines, every line lies inside `bytes`, the lines are
//! disjoint and each is followed by its CRLF. The per-line work is
//! `request_line` and `field_line` (slices inside the line, total; the
//! field harness also pins `f.line` as the line itself),
//! `parse_content_length`, `is_authority` (below), the name comparisons and
//! the Connection check (below). The field loop runs at most `N + 1` times
//! by its own range. `host` and every header's slices are sub-slices of
//! lines, so they lie inside `bytes`; `content_length <= MAX_BODY` is
//! checked before the return.
//!
//! **`is_authority` is total.** It is `authority_parts`
//! (`authority_parts_split`, over any value within a field line's
//! `B_PART`), which splits off the host and the rest, then by branch:
//! `is_ipv6` on a bracketed address or `uri_chars` (`uri_chars_is_total`)
//! on a name, and `is_port` (`is_port_is_total`) on what follows the `:`.
//! `is_ipv6` is the `::` prefix (`strip_prefix`, no loop) and then at most
//! eight passes of the step `ipv6_piece` (`ipv6_piece_step`,
//! `ipv6_piece_step_tail`): `None` takes one piece, its `:` and any second
//! `:` off `rest`, which becomes a strictly shorter suffix, and adds one to
//! `groups`, so `groups <= 7` holds on entry to every pass; `Some` is the
//! answer. The step's tail piece goes through `is_h16` or `is_ipv4`
//! (`is_ipv4_is_total`), both single passes.
//!
//! **`check_connection` is total and returns `Ok`, `ConnectionOption` or
//! `ConnectionNamesProtected`.** Step: `next_option` (`next_option_step`,
//! `next_option_step_tail`, `next_option_none`; values over
//! `MAX_CONNECTION_VALUE` are refused before the loop). `Some(o)`: `o` lies
//! inside the old `rest`, is non-empty, holds no comma and no leading or
//! trailing OWS, and the new `rest` is a strictly shorter suffix. `None`:
//! the old `rest` held only commas and OWS, and the new `rest` is empty.
//! `check_connection` is `while let Some(o) = next_option(..) {
//! check_option(o)? }`, so by induction over the options (the suffix
//! shrinks, so the loop ends) it returns `Ok` or the first `Err` of
//! `check_option`, whose three results `connection_option_is_total` proves.
//! `is_dropped`'s Connection scan uses the same step.
//!
//! **`rewrite` is total; its output fits in `bytes.len() +
//! REWRITE_GROWTH`, starts with the request line and ends with
//! `XFP_AND_CLOSE`.** Step: `Writer::put` (`writer_put_step`, every byte
//! symbolic, an output of up to `B_WOUT` and a put of up to `B_WPUT`; larger
//! outputs are argued, below): `Ok` exactly when
//! `len + bytes.len() <= out.len()`, and then `out[len..len']` is `bytes`,
//! `len' == len + bytes.len()` and `out` outside `[len, len')` is unchanged;
//! on `Err` neither `out` nor `len` changes. `put_decimal` writes 1 to 3
//! bytes (`put_decimal_writes_one_to_three`). `is_dropped` is total, being
//! built from the steps above. The output is the request line, CRLF, each
//! kept header line and its CRLF, `X-Forwarded-For: ` and the address (at
//! most 15 bytes), CRLF, then `XFP_AND_CLOSE`. In `bytes` the request line
//! and every header line are disjoint ranges each followed by its CRLF, and
//! the head ends with a blank CRLF (the `next_line` step, by induction), so
//! the output is at most `bytes.len() - 2 + XFF_LONGEST.len() +
//! XFP_AND_CLOSE.len()`, which is `bytes.len() + REWRITE_GROWTH`. The puts
//! are sequential, so the first writes the request line and the last
//! `XFP_AND_CLOSE`.
//!
//! # Bounds
//!
//! One row per harness; the time each took, alone and on which host, is in
//! the deviation log.
//!
//! | Harness | Bound | Unwind |
//! |---|---|---|
//! | `head_end_finds_the_first_blank_line` | 32 bytes | 34 |
//! | `next_line_step` | LF within `B_LINE` = 32; remainder up to `MAX_HEAD`, bytes past `B_LINE` fixed | 33 |
//! | `next_line_step_tail` | LF within `B_LINE`; remainder up to `B_LINE + 8`, all symbolic | 33 |
//! | `next_line_unterminated` | rest up to `B_LINE` | 33 |
//! | `request_line_slices_stay_inside` | line up to `B_PART` = 48 | 50 |
//! | `field_line_slices_stay_inside` | line up to `B_PART` | 50 |
//! | `content_length_parse_is_exact_and_saturates` | 24 bytes | 26 |
//! | `connection_option_is_total` | 12 bytes | 18 |
//! | `next_option_step` | element ends within `B_OPT` = 16; remainder up to `MAX_CONNECTION_VALUE`, bytes past `B_OPT` fixed | 17 |
//! | `next_option_step_tail` | as `next_option_step`; remainder up to `B_OPT + 8`, all symbolic | 17 |
//! | `next_option_none` | rest up to `B_OPT` | 17 |
//! | `ipv6_piece_step` | piece's `:` or end within `B_PIECE` = 16; remainder up to `B_IPV6` = 48, bytes past `B_PIECE + 1` fixed | 18 |
//! | `ipv6_piece_step_tail` | as `ipv6_piece_step`; remainder up to `B_PIECE + 8`, all symbolic | 18 |
//! | `is_ipv4_is_total` | 15 bytes | 17 |
//! | `uri_chars_is_total` | `B_URI` = 32 bytes, both callers' `extra` | 34 |
//! | `is_port_is_total` | 8 bytes | 10 |
//! | `writer_put_step` | out up to `B_WOUT` = 64, put up to `B_WPUT` = 56, all symbolic | 4 |
//! | `put_decimal_writes_one_to_three` | any `u8` | 5 |
//!
//! The `*_step` harnesses fix the bytes past the delimiter so that the
//! remainder's length can range over its whole bound; the `*_step_tail`
//! harnesses let those bytes vary over a short remainder. The step reads
//! no byte past the delimiter (`ipv6_piece`: past the byte after its `:`),
//! since `position` stops there and `split_at_checked` and `get` only
//! compute pointers; that joins the two. `writer_put_step` asserts its
//! universally quantified properties at one nondeterministic index, so it
//! has no loop to unwind.
//!
//! # The composed statement
//!
//! For every head of at most `MAX_HEAD` bytes in which
//! - the request line and every field line is within min(`B_LINE`,
//!   `B_PART`) bytes (`B_LINE` counting the CRLF),
//! - every Connection element is within 12 bytes, and its leading commas
//!   and OWS together with the element end within `B_OPT` bytes,
//! - a trailing run of only commas and OWS in a Connection value is within
//!   `B_OPT` bytes,
//! - an unterminated remainder (no LF) is within `B_LINE` bytes,
//! - the Host value is a reg-name within `B_URI` bytes or an IPv6 literal
//!   within `B_IPV6` bytes whose every piece ends within `B_PIECE` bytes
//!   (an IPv4 tail within 15), with a port part within 8 bytes,
//!
//! `parse` is total and its slices lie inside the head, and the rewrite
//! properties hold. Longer elements rest on the same code without a Kani
//! argument; the unit tests and bolero cover them.
//!
//! # What Kani does not prove here (argued)
//!
//! Three links of the composition are arguments, not Kani proofs (owner's
//! decision, Re-plan R3; recorded as a residual):
//! 1. **The induction.** That the loops (`parse`'s lines, `check_connection`'s
//!    and `is_dropped`'s options, `is_ipv6`'s pieces) inherit their steps'
//!    properties over every iteration. Kani checks each step; carrying the
//!    invariant across iterations would need Kani's unstable loop contracts.
//! 2. **Long scans without a delimiter.** An unterminated remainder longer
//!    than `B_LINE`, and a separator-only run longer than `B_OPT`: `position`
//!    over bytes containing no LF (only separators) returns `None` whatever
//!    their length. A fully symbolic remainder of `MAX_HEAD` bytes is beyond
//!    cbmc.
//! 3. **`Writer::put` into outputs larger than `B_WOUT`.** `rewrite` writes
//!    into an output of at least `MAX_REWRITE` bytes; cbmc ran out of memory
//!    at 1 KiB. `put` is loop-free: a `checked_add`, the bounds check of
//!    `get_mut(len..end)` and a `copy_from_slice` between slices of equal
//!    length, none of which depends on the output's size beyond those
//!    checks.

use super::*;

/// Bytes to the LF in the `next_line` harnesses.
const B_LINE: usize = 32;
/// Bytes to the comma (or the end) in the `next_option` harnesses.
const B_OPT: usize = 16;
/// The request line and field line harnesses' line.
const B_PART: usize = 48;
/// Bytes to the `:` (or the end) in the `ipv6_piece` harnesses.
const B_PIECE: usize = 16;
/// The `ipv6_piece` step harness's remainder: the longest IPv6 literal is 45
/// bytes.
const B_IPV6: usize = 48;
/// The `uri_chars` harness's input.
const B_URI: usize = 32;
/// The `Writer::put` harness's output buffer.
const B_WOUT: usize = 64;
/// The `Writer::put` harnesses' put: every put `rewrite` makes for a head
/// within the line bound (`XFP_AND_CLOSE`, 49 bytes, is the longest).
const B_WPUT: usize = 56;

fn any_bytes<const L: usize>(buf: &[u8; L]) -> &[u8] {
    let len: usize = kani::any();
    kani::assume(len <= L);
    buf.get(..len).unwrap_or(&[])
}

fn inside(outer: &[u8], inner: &[u8]) -> bool {
    let (o, i) = (outer.as_ptr_range(), inner.as_ptr_range());
    o.start <= i.start && i.end <= o.end
}

fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
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

/// `next_line`'s step, for any remainder up to `MAX_HEAD` bytes whose
/// first LF is within `B_LINE`: on `Ok(line)` the remainder splits exactly
/// into the line, its CRLF and the new remainder; the only refusal is a
/// bare LF. The bytes past `B_LINE` are fixed here (zero) so the remainder's
/// length can range over all of `MAX_HEAD`; `next_line_step_tail` lets them
/// vary. The step reads no byte past the first LF (`position` stops there;
/// `split_at_checked` and `get` only compute pointers), which is what joins
/// the two harnesses.
#[kani::proof]
#[kani::unwind(33)]
fn next_line_step() {
    let head: [u8; B_LINE] = kani::any();
    let mut buf = [0u8; MAX_HEAD];
    buf[..B_LINE].copy_from_slice(&head);
    let len: usize = kani::any();
    kani::assume(len <= MAX_HEAD);
    let r = next_line_split_exactly(&buf[..len]);
    kani::cover!(r && len > B_LINE);
}

/// `next_line_step` with the bytes after the LF symbolic too, over a
/// remainder up to `B_LINE + 8` bytes.
#[kani::proof]
#[kani::unwind(33)]
fn next_line_step_tail() {
    let buf: [u8; B_LINE + 8] = kani::any();
    let r = next_line_split_exactly(any_bytes(&buf));
    kani::cover!(r);
}

/// The step's property for one remainder whose first LF is within
/// `B_LINE`; returns whether a line was taken.
fn next_line_split_exactly(old: &[u8]) -> bool {
    let lf: usize = kani::any();
    kani::assume(lf < B_LINE && lf < old.len() && old[lf] == b'\n');
    let mut rest = old;
    match next_line(&mut rest) {
        Ok(line) => {
            let k = line.len();
            assert!(line.as_ptr() == old.as_ptr());
            assert!(k + 2 <= old.len() && old[k..k + 2] == *b"\r\n");
            assert!(rest.as_ptr() == old[k + 2..].as_ptr() && rest.len() == old.len() - k - 2);
            true
        }
        Err(e) => {
            assert!(e == HttpRefusal::BareLineEnding);
            false
        }
    }
}

/// A remainder of at most `B_LINE` bytes without a LF is `Unterminated`.
#[kani::proof]
#[kani::unwind(33)]
fn next_line_unterminated() {
    let buf: [u8; B_LINE] = kani::any();
    let old = any_bytes(&buf);
    kani::assume(!old.contains(&b'\n'));
    let mut rest = old;
    let r = next_line(&mut rest);
    assert!(r == Err(HttpRefusal::Unterminated));
    kani::cover!(old.len() == B_LINE);
}

/// A field line's name and value lie inside the line, `f.line` is the line
/// itself (the rewrite's length arithmetic needs it), and parsing one never
/// panics.
#[kani::proof]
#[kani::unwind(50)]
fn field_line_slices_stay_inside() {
    let buf: [u8; B_PART] = kani::any();
    let line = any_bytes(&buf);
    if let Ok(f) = field_line(line) {
        assert!(inside(line, f.name) && inside(line, f.value));
        assert!(f.line.as_ptr() == line.as_ptr() && f.line.len() == line.len());
        assert!(!f.name.is_empty());
        kani::cover!(!f.value.is_empty());
    }
}

/// The request line's method and target lie inside it.
#[kani::proof]
#[kani::unwind(50)]
fn request_line_slices_stay_inside() {
    let buf: [u8; B_PART] = kani::any();
    let line = any_bytes(&buf);
    if let Ok((method, target)) = request_line(line) {
        assert!(inside(line, method) && inside(line, target));
        kani::cover!(target.len() > 1);
    }
}

/// One Connection element never panics and its result is one of exactly
/// three; of the protected names, the two that fit in 12 bytes (`host`,
/// `connection`) are refused in any letter case. The longer ones are the
/// unit test `connection_naming_a_protected_field_is_refused`'s. The unwind
/// covers `is_token`'s 15-byte delimiter set as well as the 12-byte option.
#[kani::proof]
#[kani::unwind(18)]
fn connection_option_is_total() {
    let buf: [u8; 12] = kani::any();
    let option = any_bytes(&buf);
    let r = check_option(option);
    assert!(matches!(
        r,
        Ok(()) | Err(HttpRefusal::ConnectionOption) | Err(HttpRefusal::ConnectionNamesProtected)
    ));
    if option.eq_ignore_ascii_case(b"host") || option.eq_ignore_ascii_case(b"connection") {
        assert!(r == Err(HttpRefusal::ConnectionNamesProtected));
    }
    kani::cover!(r.is_ok() && !option.is_empty());
    kani::cover!(r == Err(HttpRefusal::ConnectionNamesProtected));
}

/// `next_option`'s step, for any remainder up to `MAX_CONNECTION_VALUE`
/// bytes (longer values are refused before the loop) whose first element
/// ends within `B_OPT`: `Some(o)` lies inside the old remainder, is
/// non-empty, holds no comma and no OWS at either end, and the new remainder
/// is a strictly shorter suffix. As in `next_line_step`, the bytes past
/// `B_OPT` are fixed here and vary in `next_option_step_tail`; the step
/// reads no byte past the comma that ends the element.
#[kani::proof]
#[kani::unwind(17)]
fn next_option_step() {
    let head: [u8; B_OPT] = kani::any();
    let mut buf = [0u8; MAX_CONNECTION_VALUE];
    buf[..B_OPT].copy_from_slice(&head);
    let len: usize = kani::any();
    kani::assume(len <= MAX_CONNECTION_VALUE);
    let r = next_option_step_holds(&buf[..len]);
    kani::cover!(r && len > B_OPT);
}

/// `next_option_step` with the bytes after the element symbolic too, over a
/// remainder up to `B_OPT + 8` bytes.
#[kani::proof]
#[kani::unwind(17)]
fn next_option_step_tail() {
    let buf: [u8; B_OPT + 8] = kani::any();
    let r = next_option_step_holds(any_bytes(&buf));
    kani::cover!(r);
}

/// The step's property for one remainder; past `B_OPT` bytes a comma within
/// `B_OPT` ends an element that starts before it. Returns whether an
/// element was taken.
fn next_option_step_holds(old: &[u8]) -> bool {
    if old.len() > B_OPT {
        let comma: usize = kani::any();
        kani::assume(comma < B_OPT && old[comma] == b',');
        kani::assume(old[..comma].iter().any(|&b| b != b',' && !is_ows(b)));
    }
    let mut rest = old;
    let r = next_option(&mut rest);
    if let Some(o) = r {
        assert!(inside(old, o) && !o.is_empty() && !o.contains(&b','));
        assert!(!is_ows(o[0]) && !is_ows(o[o.len() - 1]));
        assert!(rest.len() < old.len() && rest.as_ptr() == old[old.len() - rest.len()..].as_ptr());
    }
    r.is_some()
}

/// A remainder of at most `B_OPT` bytes yields `None` only when it held
/// commas and OWS alone, and is then empty.
#[kani::proof]
#[kani::unwind(17)]
fn next_option_none() {
    let buf: [u8; B_OPT] = kani::any();
    let old = any_bytes(&buf);
    let mut rest = old;
    let r = next_option(&mut rest);
    if r.is_none() {
        assert!(old.iter().all(|&b| b == b',' || is_ows(b)));
        assert!(rest.is_empty());
    }
    kani::cover!(r.is_none() && !old.is_empty());
    kani::cover!(r.is_some());
}

/// `ipv6_piece`'s step, for a remainder up to `B_IPV6` bytes whose piece
/// ends (at its `:` or at the end) within `B_PIECE`, entered with
/// `groups <= 7` as in every pass of `is_ipv6`: no panic; `None` leaves a
/// non-empty, strictly shorter suffix and one more group; `Some` leaves at
/// most nine groups, and `Some(true)` at most eight. The bytes past
/// `B_PIECE + 1` are fixed here (the step reads the byte after the `:`, for
/// `::`) and vary in `ipv6_piece_step_tail`.
#[kani::proof]
#[kani::unwind(18)]
fn ipv6_piece_step() {
    let head: [u8; B_PIECE + 1] = kani::any();
    let mut buf = [0u8; B_IPV6];
    buf[..B_PIECE + 1].copy_from_slice(&head);
    let len: usize = kani::any();
    kani::assume(len <= B_IPV6);
    let r = ipv6_piece_holds(&buf[..len]);
    kani::cover!(r.is_none() && len > B_PIECE + 1);
    kani::cover!(r == Some(true));
    kani::cover!(r == Some(false));
}

/// `ipv6_piece_step` with every byte symbolic, over a remainder up to
/// `B_PIECE + 8` bytes.
#[kani::proof]
#[kani::unwind(18)]
fn ipv6_piece_step_tail() {
    let buf: [u8; B_PIECE + 8] = kani::any();
    let old = any_bytes(&buf);
    let r = ipv6_piece_holds(old);
    kani::cover!(r.is_none());
    kani::cover!(r == Some(true) && old.contains(&b'.'));
}

/// The step's property for one remainder; returns the step's result.
fn ipv6_piece_holds(old: &[u8]) -> Option<bool> {
    if old.len() > B_PIECE {
        let colon: usize = kani::any();
        kani::assume(colon < B_PIECE && old[colon] == b':');
    }
    let groups_in: usize = kani::any();
    kani::assume(groups_in <= 7);
    let elided_in: bool = kani::any();
    let (mut rest, mut groups, mut elided) = (old, groups_in, elided_in);
    let r = ipv6_piece(&mut rest, &mut groups, &mut elided);
    match r {
        None => {
            assert!(!rest.is_empty() && rest.len() < old.len());
            assert!(rest.as_ptr() == old[old.len() - rest.len()..].as_ptr());
            assert!(groups == groups_in + 1 && (elided || !elided_in));
        }
        Some(valid) => {
            assert!(groups <= groups_in + 2);
            assert!(!valid || groups <= 8);
        }
    }
    r
}

/// `is_ipv4` over any 15 bytes (the longest dotted quad) never panics; an
/// accepted one holds exactly three dots and digits otherwise.
#[kani::proof]
#[kani::unwind(17)]
fn is_ipv4_is_total() {
    let buf: [u8; 15] = kani::any();
    let s = any_bytes(&buf);
    let r = is_ipv4(s);
    if r {
        assert!(s.len() >= 7 && s.iter().all(|&b| b == b'.' || b.is_ascii_digit()));
        assert!(s.iter().filter(|&&b| b == b'.').count() == 3);
    }
    kani::cover!(r && s.len() == 15);
    kani::cover!(!r && s.len() == 15 && s.iter().all(|&b| b == b'.' || b.is_ascii_digit()));
}

/// `authority_parts` over any Host value within a field line's bound
/// (`B_PART`): no panic; the host and the rest lie inside the value, the
/// rest is empty or starts with `:` for a name, and for a bracketed literal
/// the address is what lies between `[` and the first `]`. With the piece
/// harnesses below, `is_authority`'s totality is Kani-proven: it is this
/// split, then `is_ipv6` (8 passes of `ipv6_piece`), `uri_chars` and
/// `is_port`, each proven total.
#[kani::proof]
#[kani::unwind(50)]
fn authority_parts_split() {
    let buf: [u8; B_PART] = kani::any();
    let value = any_bytes(&buf);
    let r = authority_parts(value);
    match r {
        Some((AuthorityHost::Ipv6(addr), rest)) => {
            assert!(value.first() == Some(&b'['));
            assert!(inside(value, addr) && inside(value, rest));
            assert!(!addr.contains(&b']'));
            assert!(value.get(addr.len() + 1) == Some(&b']'));
        }
        Some((AuthorityHost::Name(name), rest)) => {
            assert!(value.first() != Some(&b'['));
            assert!(inside(value, name) && inside(value, rest));
            assert!(!name.contains(&b':'));
            assert!(rest.is_empty() || rest.first() == Some(&b':'));
            assert!(name.len() + rest.len() == value.len());
        }
        None => assert!(value.first() == Some(&b'[') && !value.contains(&b']')),
    }
    kani::cover!(matches!(r, Some((AuthorityHost::Ipv6(_), r)) if !r.is_empty()));
    kani::cover!(matches!(r, Some((AuthorityHost::Name(_), r)) if !r.is_empty()));
    kani::cover!(r.is_none());
}

/// `uri_chars` over any `B_URI` bytes, with either caller's extra set, never
/// panics (the `%` lookahead included).
#[kani::proof]
#[kani::unwind(34)]
fn uri_chars_is_total() {
    let buf: [u8; B_URI] = kani::any();
    let s = any_bytes(&buf);
    let extra: &[u8] = if kani::any() { b":@/?" } else { b"" };
    let r = uri_chars(s, extra);
    if r {
        assert!(!s.iter().any(|&b| b == b' ' || b == b'#' || b == b'[' || b >= 0x7f));
    }
    kani::cover!(r && s.contains(&b'%'));
    kani::cover!(!r && !s.is_empty());
}

/// `is_port` over any 8 bytes never panics, and accepts exactly 1 to 5
/// digits of value at most 65535.
#[kani::proof]
#[kani::unwind(10)]
fn is_port_is_total() {
    let buf: [u8; 8] = kani::any();
    let digits = any_bytes(&buf);
    let r = is_port(digits);
    let in_shape = (1..=5).contains(&digits.len()) && digits.iter().all(u8::is_ascii_digit);
    let value = digits.iter().fold(0u64, |n, &d| n * 10 + u64::from(d.wrapping_sub(b'0')));
    assert!(r == (in_shape && value <= 65535));
    kani::cover!(r && digits.len() == 5);
    kani::cover!(!r && in_shape && digits.len() == 5);
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

/// `Writer::put`'s step with every byte symbolic: an output of up to
/// `B_WOUT` bytes and a put of up to `B_WPUT` (`XFP_AND_CLOSE`, the longest
/// put of a head within the line bound, is 49). Larger outputs exhausted
/// cbmc (30 GiB at 1 KiB): the copy of a symbolic length at a symbolic
/// offset grows with the array; see the header for the argument above it.
#[kani::proof]
#[kani::unwind(4)]
fn writer_put_step() {
    let out: [u8; B_WOUT] = kani::any();
    let input: [u8; B_WPUT] = kani::any();
    let bytes = any_bytes(&input);
    let ok = writer_put_holds(out, bytes);
    kani::cover!(ok && bytes.len() == B_WPUT);
    kani::cover!(!ok && !bytes.is_empty());
}

/// The step's property for one buffer and put: `Ok` exactly when the bytes
/// fit; then they land at `[len, len')`, `len'` is `len + bytes.len()` and
/// nothing else in `out` changes. On `Err` neither `out` nor `len` changes.
/// "For every index" is one nondeterministic index, so nothing loops.
/// Returns whether the put succeeded.
fn writer_put_holds<const L: usize>(mut buf: [u8; L], bytes: &[u8]) -> bool {
    let before = buf;
    let out_len: usize = kani::any();
    let len: usize = kani::any();
    kani::assume(out_len <= L && len <= out_len);
    let mut w = Writer { out: &mut buf[..out_len], len };
    let r = w.put(bytes);
    let new_len = w.len;
    assert!(r.is_ok() == (len + bytes.len() <= out_len));
    let i: usize = kani::any();
    kani::assume(i < L);
    if r.is_ok() {
        assert!(new_len == len + bytes.len());
        if i < len || i >= new_len {
            assert!(buf[i] == before[i]);
        }
        let j: usize = kani::any();
        if j < bytes.len() {
            assert!(buf[len + j] == bytes[j]);
        }
        kani::cover!(len > 0 && !bytes.is_empty() && new_len < out_len);
    } else {
        assert!(r == Err(HttpRefusal::RewriteTooLarge) && new_len == len);
        assert!(buf[i] == before[i]);
        kani::cover!(len > 0);
    }
    r.is_ok()
}

/// `put_decimal` writes `v` in 1 to 3 decimal digits, without a leading
/// zero.
#[kani::proof]
#[kani::unwind(5)]
fn put_decimal_writes_one_to_three() {
    let v: u8 = kani::any();
    let mut buf = [0u8; 3];
    let mut w = Writer { out: &mut buf, len: 0 };
    let r = w.put_decimal(v);
    let n = w.len;
    assert!(r.is_ok());
    assert!(n == if v >= 100 { 3 } else if v >= 10 { 2 } else { 1 });
    let written = &buf[..n];
    assert!(n == 1 || written[0] != b'0');
    assert!(written.iter().all(u8::is_ascii_digit));
    assert!(written.iter().fold(0u32, |a, &d| a * 10 + u32::from(d - b'0')) == u32::from(v));
    kani::cover!(n == 3);
}
