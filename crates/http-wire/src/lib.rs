//! HTTP/1.1 request head parsing and rewriting for the `tls` PD (M6 plan
//! C9): one request per connection, smuggling-prone forms refused. The
//! parser lands with the proxy flow; this is the crate's fixed frame.

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

/// Largest request head, request line through the blank line.
pub const MAX_HEAD: usize = 8 * 1024;
/// Most header fields in a request head.
pub const MAX_HEADERS: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_limits_are_the_plans() {
        assert_eq!((MAX_HEAD, MAX_HEADERS), (8192, 32));
    }
}
