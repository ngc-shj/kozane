//! The launcher's own files, `/etc/kozane/vm.conf` and
//! `/etc/kozane/firmware.pin`: canonical `key=value` text in the release
//! manifest's shape. One pair per LF-ended line, the keys exactly the given
//! set in sorted order, each once; values printable ASCII without spaces.
//! Anything else is refused, so one file has one reading.

/// The values of `keys` (which must be sorted), in that order.
pub fn parse<'a>(text: &'a str, keys: &[&str]) -> Result<Vec<&'a str>, String> {
    let body = text.strip_suffix('\n').ok_or("does not end with LF")?;
    let lines: Vec<&str> = body.split('\n').collect();
    if lines.len() != keys.len() {
        return Err(format!("{} lines, expected exactly {}: {}", lines.len(), keys.len(), keys.join(", ")));
    }
    let mut values = Vec::with_capacity(keys.len());
    for (n, (line, key)) in lines.iter().zip(keys).enumerate() {
        let (k, v) = line.split_once('=').ok_or(format!("line {} has no `=`", n + 1))?;
        if k != *key {
            return Err(format!("line {}: key `{k}`, expected `{key}`", n + 1));
        }
        if v.is_empty() || !v.bytes().all(|b| (0x21..0x7f).contains(&b)) {
            return Err(format!("line {}: value is empty or not printable ASCII", n + 1));
        }
        values.push(v);
    }
    Ok(values)
}

/// The canonical text for `pairs`, which must already be sorted by key.
pub fn render(pairs: &[(&str, &str)]) -> String {
    pairs.iter().map(|(k, v)| format!("{k}={v}\n")).collect()
}

/// 64 lowercase hex digits.
pub fn is_sha256_hex(v: &str) -> bool {
    v.len() == 64 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A `u32` in canonical decimal, as the release manifest spells
/// `release_seq`: no sign, no leading zero but `0` itself.
pub fn parse_seq(v: &str) -> Option<u32> {
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) || (v.len() > 1 && v.starts_with('0')) {
        return None;
    }
    v.parse().ok()
}

/// The firmware pin: u-boot.bin's digest and the `RELEASE_SEQ` of the
/// release it was taken from (M9 plan C4).
#[derive(Debug, PartialEq, Eq)]
pub struct Pin {
    pub firmware_sha256: String,
    pub release_seq: u32,
}

pub const PIN_KEYS: [&str; 2] = ["firmware_sha256", "release_seq"];

impl Pin {
    pub fn parse(text: &str) -> Result<Self, String> {
        let v = parse(text, &PIN_KEYS)?;
        let (hash, seq) = match v.as_slice() {
            [hash, seq] => (*hash, *seq),
            _ => return Err("pin: wrong shape".into()),
        };
        if !is_sha256_hex(hash) {
            return Err("firmware_sha256 is not 64 lowercase hex digits".into());
        }
        let release_seq = parse_seq(seq).ok_or("release_seq is not a canonical u32")?;
        Ok(Self { firmware_sha256: hash.to_string(), release_seq })
    }

    pub fn render(&self) -> String {
        render(&[("firmware_sha256", &self.firmware_sha256), ("release_seq", &self.release_seq.to_string())])
    }
}

/// `/etc/kozane/vm.conf`: the two bridges the taps join, and the QEMU and
/// swtpm programs.
#[derive(Debug, PartialEq, Eq)]
pub struct VmConf {
    pub inside_bridge: String,
    pub outside_bridge: String,
    pub qemu: String,
    pub swtpm: String,
}

pub const CONF_KEYS: [&str; 4] = ["inside_bridge", "outside_bridge", "qemu", "swtpm"];

/// A Linux interface name: 1 to 15 bytes of `[A-Za-z0-9_.-]`.
pub fn is_ifname(v: &str) -> bool {
    (1..16).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

impl VmConf {
    pub fn parse(text: &str) -> Result<Self, String> {
        let v = parse(text, &CONF_KEYS)?;
        let [inside, outside, qemu, swtpm] = v.as_slice() else {
            return Err("vm.conf: wrong shape".into());
        };
        for bridge in [inside, outside] {
            if !is_ifname(bridge) {
                return Err(format!("`{bridge}` is not an interface name"));
            }
        }
        for program in [qemu, swtpm] {
            if !program.starts_with('/') {
                return Err(format!("`{program}` is not an absolute path"));
            }
        }
        Ok(Self {
            inside_bridge: inside.to_string(),
            outside_bridge: outside.to_string(),
            qemu: qemu.to_string(),
            swtpm: swtpm.to_string(),
        })
    }
}
