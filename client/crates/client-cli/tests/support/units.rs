//! The shipped unit files (`client/dist`), read exactly on D6's canonical
//! subset: one `Key=Value` per line, no `~`, no directive repeated within a
//! section, comments and blank lines aside. From them, the `setpriv` flags
//! that stand in for systemd's capability directives (VE26, VE28).

use std::collections::BTreeMap;
use std::path::PathBuf;

pub struct Unit {
    pub sections: BTreeMap<String, BTreeMap<String, String>>,
}

pub fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dist").join(name)
}

impl Unit {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut sections: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        let mut current: Option<String> = None;
        for (n, line) in text.lines().enumerate() {
            let at = n + 1;
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line != line.trim() || line.ends_with('\\') {
                return Err(format!("line {at}: not canonical"));
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                if sections.insert(name.to_string(), BTreeMap::new()).is_some() {
                    return Err(format!("line {at}: section [{name}] repeated"));
                }
                current = Some(name.to_string());
                continue;
            }
            let (k, v) = line.split_once('=').ok_or(format!("line {at}: want Key=Value"))?;
            if k.is_empty() || k != k.trim() || v != v.trim() || !k.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return Err(format!("line {at}: not canonical"));
            }
            if v.contains('~') {
                return Err(format!("line {at}: a `~` (inverted list)"));
            }
            let sec = current.as_ref().ok_or(format!("line {at}: outside a section"))?;
            if sections.get_mut(sec).unwrap().insert(k.to_string(), v.to_string()).is_some() {
                return Err(format!("line {at}: {k} repeated"));
            }
        }
        Ok(Self { sections })
    }

    pub fn load(name: &str) -> Self {
        let text = std::fs::read_to_string(path(name)).unwrap();
        Self::parse(&text).unwrap_or_else(|e| panic!("units: non-canonical unit file {name}: {e}"))
    }

    pub fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.sections.get(section).and_then(|s| s.get(key)).map(String::as_str)
    }

    /// `setpriv` flags for this unit's `[Service]` capability directives,
    /// under noroot securebits so uid 0 behaves as the unit user (VE26).
    /// A missing `CapabilityBoundingSet=` keeps every capability, as
    /// systemd does.
    pub fn setpriv(&self) -> Vec<String> {
        let caps = |v: &str| -> String {
            v.split_whitespace().map(|c| format!(",+{}", c.trim_start_matches("CAP_").to_ascii_lowercase())).collect()
        };
        let mut out = vec!["--securebits".to_string(), "+noroot,+noroot_locked,+no_setuid_fixup".to_string()];
        let amb = self.get("Service", "AmbientCapabilities").unwrap_or("");
        out.extend(["--inh-caps".to_string(), format!("-all{}", caps(amb))]);
        out.extend(["--ambient-caps".to_string(), format!("-all{}", caps(amb))]);
        if let Some(b) = self.get("Service", "CapabilityBoundingSet") {
            out.extend(["--bounding-set".to_string(), format!("-all{}", caps(b))]);
        }
        if self.get("Service", "NoNewPrivileges") == Some("yes") {
            out.push("--no-new-privs".to_string());
        }
        out
    }
}
