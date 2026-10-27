//! The release manifest (M5 plan C13): canonical text, one `key=value` per
//! line, keys sorted and each present exactly once, LF line ends, nothing
//! else. Parsing refuses every other byte sequence, so the bytes signed and
//! the fields read from them cannot disagree.

/// Every key a manifest carries, in its required (sorted) order.
/// `firmware_sha256` is flash.bin's, and `pcrs` the PCRs 0-8 the envelopes
/// are sealed to, comma-separated (M7 plan C4).
pub const KEYS: [&str; 10] = [
    "boot_desc_sha256",
    "cargo_lock_sha256",
    "commit",
    "dev_image",
    "firmware_sha256",
    "kani",
    "loader_img_sha256",
    "pcrs",
    "verus",
    "version",
];

#[derive(Debug, PartialEq, Eq)]
pub enum ManifestError {
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

impl core::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotUtf8 => write!(f, "manifest is not UTF-8"),
            Self::NoFinalNewline => write!(f, "manifest does not end with LF"),
            Self::EmptyLine(n) => write!(f, "manifest line {n} is empty"),
            Self::NoEquals(n) => write!(f, "manifest line {n} has no `=`"),
            Self::BadKey(n) => write!(f, "manifest line {n}: key is not [a-z0-9_]+"),
            Self::BadValue(n) => write!(f, "manifest line {n}: value is empty or not printable ASCII"),
            Self::Unknown(k) => write!(f, "manifest key {k} is unknown"),
            Self::Duplicate(k) => write!(f, "manifest key {k} appears twice"),
            Self::Unsorted(k) => write!(f, "manifest key {k} is out of order"),
            Self::Missing(k) => write!(f, "manifest key {k} is missing"),
        }
    }
}

/// The fields of a canonical manifest, in `KEYS` order.
pub fn parse(bytes: &[u8]) -> Result<Vec<(String, String)>, ManifestError> {
    let text = core::str::from_utf8(bytes).map_err(|_| ManifestError::NotUtf8)?;
    let body = text.strip_suffix('\n').ok_or(ManifestError::NoFinalNewline)?;
    let mut fields: Vec<(String, String)> = Vec::new();
    for (i, line) in body.split('\n').enumerate() {
        let n = i + 1;
        if line.is_empty() {
            return Err(ManifestError::EmptyLine(n));
        }
        let (key, value) = line.split_once('=').ok_or(ManifestError::NoEquals(n))?;
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            return Err(ManifestError::BadKey(n));
        }
        // Printable ASCII only: no CR, tab or other control character can hide
        // in a value.
        if value.is_empty() || !value.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return Err(ManifestError::BadValue(n));
        }
        if !KEYS.contains(&key) {
            return Err(ManifestError::Unknown(key.to_string()));
        }
        if let Some((last, _)) = fields.last() {
            if last.as_str() == key {
                return Err(ManifestError::Duplicate(key.to_string()));
            }
            if last.as_str() > key {
                return Err(if fields.iter().any(|(k, _)| k == key) {
                    ManifestError::Duplicate(key.to_string())
                } else {
                    ManifestError::Unsorted(key.to_string())
                });
            }
        }
        fields.push((key.to_string(), value.to_string()));
    }
    for key in KEYS {
        if !fields.iter().any(|(k, _)| k == key) {
            return Err(ManifestError::Missing(key.to_string()));
        }
    }
    Ok(fields)
}

/// The canonical bytes for these fields (each key once; any order in).
pub fn render(fields: &[(&str, &str)]) -> Result<Vec<u8>, ManifestError> {
    let mut sorted: Vec<&(&str, &str)> = fields.iter().collect();
    sorted.sort_by_key(|(k, _)| *k);
    let mut out = Vec::new();
    for (k, v) in sorted {
        out.extend_from_slice(k.as_bytes());
        out.push(b'=');
        out.extend_from_slice(v.as_bytes());
        out.push(b'\n');
    }
    // What was rendered must be what parse accepts.
    parse(&out)?;
    Ok(out)
}
