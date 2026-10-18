//! Integer and boolean parsing matching the Microkit tool's own SDF number
//! syntax: an optional `0x`/`0X` hex prefix, `_` digit separators anywhere,
//! decimal otherwise. Getting this wrong would let a `.system` value parse
//! differently here than it does for `microkit` itself.

use core::fmt;

#[derive(Debug)]
pub struct NumberError(String);

impl fmt::Display for NumberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid number '{}'", self.0)
    }
}

pub fn parse_u64(raw: &str) -> Result<u64, NumberError> {
    let cleaned: String = raw.chars().filter(|c| *c != '_').collect();
    let (digits, radix) = match cleaned.strip_prefix("0x").or_else(|| cleaned.strip_prefix("0X")) {
        Some(hex) => (hex, 16),
        None => (cleaned.as_str(), 10),
    };
    if digits.is_empty() {
        return Err(NumberError(raw.to_string()));
    }
    u64::from_str_radix(digits, radix).map_err(|_| NumberError(raw.to_string()))
}

pub fn parse_bool(raw: &str) -> Result<bool, NumberError> {
    match raw {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(NumberError(raw.to_string())),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parses_decimal() {
        assert_eq!(parse_u64("1000").unwrap(), 1000);
    }

    #[test]
    fn parses_hex_with_separators() {
        assert_eq!(parse_u64("0x10_000").unwrap(), 0x10000);
        assert_eq!(parse_u64("0x1_000_000_000").unwrap(), 0x1_000_000_000);
    }

    #[test]
    fn parses_decimal_with_separators() {
        assert_eq!(parse_u64("1_000_000").unwrap(), 1_000_000);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_u64("").is_err());
        assert!(parse_u64("0xzz").is_err());
        assert!(parse_u64("ten").is_err());
    }

    #[test]
    fn parses_bool() {
        assert!(parse_bool("true").unwrap());
        assert!(!parse_bool("false").unwrap());
        assert!(parse_bool("yes").is_err());
    }
}
