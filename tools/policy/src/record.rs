//! Canonical `key=value` records (M8 plan C2): the same shape as
//! `tools/release`'s manifest — one `key=value` per line, keys sorted and
//! each present exactly once, LF line ends, nothing else — generalised
//! over the required key set, since approval and restore-approval records
//! each have their own.

#[derive(Debug, PartialEq, Eq)]
pub enum RecordError {
    NotUtf8,
    NoFinalNewline,
    EmptyLine(usize),
    NoEquals(usize),
    BadKey(usize),
    BadValue(usize),
    Unknown(String),
    Duplicate(String),
    Unsorted(String),
    Missing(String),
}

impl core::fmt::Display for RecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotUtf8 => write!(f, "record is not UTF-8"),
            Self::NoFinalNewline => write!(f, "record does not end with LF"),
            Self::EmptyLine(n) => write!(f, "record line {n} is empty"),
            Self::NoEquals(n) => write!(f, "record line {n} has no `=`"),
            Self::BadKey(n) => write!(f, "record line {n}: key is not [a-z0-9_]+"),
            Self::BadValue(n) => write!(f, "record line {n}: value is empty or not printable ASCII"),
            Self::Unknown(k) => write!(f, "record key {k} is unknown"),
            Self::Duplicate(k) => write!(f, "record key {k} appears twice"),
            Self::Unsorted(k) => write!(f, "record key {k} is out of order"),
            Self::Missing(k) => write!(f, "record key {k} is missing"),
        }
    }
}

/// Parses `text` as a canonical record whose keys are exactly `keys`
/// (order-independent in the check, but the text itself must be sorted).
pub fn parse(bytes: &[u8], keys: &[&str]) -> Result<Vec<(String, String)>, RecordError> {
    let text = core::str::from_utf8(bytes).map_err(|_| RecordError::NotUtf8)?;
    let body = text.strip_suffix('\n').ok_or(RecordError::NoFinalNewline)?;
    let mut fields: Vec<(String, String)> = Vec::new();
    for (i, line) in body.split('\n').enumerate() {
        let n = i + 1;
        if line.is_empty() {
            return Err(RecordError::EmptyLine(n));
        }
        let (key, value) = line.split_once('=').ok_or(RecordError::NoEquals(n))?;
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            return Err(RecordError::BadKey(n));
        }
        if value.is_empty() || !value.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return Err(RecordError::BadValue(n));
        }
        if !keys.contains(&key) {
            return Err(RecordError::Unknown(key.to_string()));
        }
        if let Some((last, _)) = fields.last() {
            if last.as_str() == key {
                return Err(RecordError::Duplicate(key.to_string()));
            }
            if last.as_str() > key {
                return Err(if fields.iter().any(|(k, _)| k == key) {
                    RecordError::Duplicate(key.to_string())
                } else {
                    RecordError::Unsorted(key.to_string())
                });
            }
        }
        fields.push((key.to_string(), value.to_string()));
    }
    for key in keys {
        if !fields.iter().any(|(k, _)| k == key) {
            return Err(RecordError::Missing(key.to_string()));
        }
    }
    Ok(fields)
}

/// The canonical bytes for these fields (each key once; any order in,
/// sorted order out).
pub fn render(fields: &[(&str, &str)], keys: &[&str]) -> Vec<u8> {
    let mut sorted: Vec<&(&str, &str)> = fields.iter().collect();
    sorted.sort_by_key(|(k, _)| *k);
    let mut out = Vec::new();
    for (k, v) in sorted {
        out.extend_from_slice(k.as_bytes());
        out.push(b'=');
        out.extend_from_slice(v.as_bytes());
        out.push(b'\n');
    }
    debug_assert!(parse(&out, keys).is_ok());
    out
}

/// Looks up one field's value by key (the caller already parsed with
/// [`parse`], so the key is known present).
pub fn get<'a>(fields: &'a [(String, String)], key: &str) -> Option<&'a str> {
    fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}
