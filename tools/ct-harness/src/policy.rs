//! `policy/ct-declassify.toml`: the declassification sites (M4 plan C9).
//!
//! The file is a list of `[[site]]` tables with `id`, `kind`, `width` and
//! `why`. Only that shape is accepted; anything else refuses the policy.

use mce460896::{CT_LEN, SS_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A 1-byte public predicate (0 or 1).
    Predicate,
    /// A whole harness-boundary output buffer.
    Output,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub id: String,
    pub kind: Kind,
    pub width: usize,
}

/// The widths an `output` site may have: the KEM's output buffers.
const OUTPUT_WIDTHS: [usize; 2] = [CT_LEN, SS_LEN];

pub fn parse(text: &str) -> Result<Vec<Site>, String> {
    let mut tables: Vec<Vec<(String, String)>> = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[site]]" {
            tables.push(Vec::new());
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or(format!("line {}: not key = value", n + 1))?;
        let table = tables
            .last_mut()
            .ok_or(format!("line {}: key outside [[site]]", n + 1))?;
        table.push((k.trim().to_owned(), v.trim().to_owned()));
    }

    let mut sites: Vec<Site> = Vec::new();
    for (i, table) in tables.iter().enumerate() {
        let get = |key: &str| -> Result<&str, String> {
            let mut it = table.iter().filter(|(k, _)| k == key);
            match (it.next(), it.next()) {
                (Some((_, v)), None) => Ok(v.as_str()),
                _ => Err(format!("site {}: want exactly one {key}", i + 1)),
            }
        };
        if let Some((k, _)) = table
            .iter()
            .find(|(k, _)| !["id", "kind", "width", "why"].contains(&k.as_str()))
        {
            return Err(format!("site {}: unknown key {k}", i + 1));
        }
        let id = string(get("id")?)?;
        if id.is_empty()
            || !id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(format!("site {}: id {id:?} is not [a-z0-9-]+", i + 1));
        }
        string(get("why")?)?;
        let kind = match string(get("kind")?)?.as_str() {
            "predicate" => Kind::Predicate,
            "output" => Kind::Output,
            other => {
                return Err(format!(
                    "{id}: kind {other:?} is neither predicate nor output"
                ));
            }
        };
        let width: usize = get("width")?
            .parse()
            .map_err(|_| format!("{id}: width is not an integer"))?;
        match kind {
            Kind::Predicate if width != 1 => {
                return Err(format!("{id}: a predicate is 1 byte, not {width}"));
            }
            Kind::Output if !OUTPUT_WIDTHS.contains(&width) => {
                return Err(format!(
                    "{id}: output width {width} is not a KEM output buffer {OUTPUT_WIDTHS:?}"
                ));
            }
            _ => {}
        }
        if sites.iter().any(|s| s.id == id) {
            return Err(format!("{id}: listed twice"));
        }
        sites.push(Site { id, kind, width });
    }
    if sites.is_empty() {
        return Err("no [[site]] entries".into());
    }
    Ok(sites)
}

fn string(v: &str) -> Result<String, String> {
    v.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .filter(|s| !s.contains('"') && !s.contains('\\'))
        .map(str::to_owned)
        .ok_or(format!("{v}: not a plain quoted string"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
# comment
[[site]]
id = "encaps-accept"
kind = "predicate"
width = 1
why = "the accept bit"

[[site]]
id = "ss-out"
kind = "output"
width = 32
why = "before the compare"
"#;

    #[test]
    fn parses_predicate_and_output_sites() {
        let s = parse(GOOD).expect("good policy");
        assert_eq!(s.len(), 2);
        assert_eq!(
            s[0],
            Site {
                id: "encaps-accept".into(),
                kind: Kind::Predicate,
                width: 1
            }
        );
        assert_eq!(s[1].kind, Kind::Output);
    }

    #[test]
    fn refuses_a_predicate_wider_than_one_byte() {
        let bad = GOOD.replace("width = 1", "width = 2");
        assert!(parse(&bad).unwrap_err().contains("a predicate is 1 byte"));
    }

    #[test]
    fn refuses_an_output_that_is_not_a_kem_output_buffer() {
        let bad = GOOD.replace("width = 32", "width = 576");
        assert!(parse(&bad).unwrap_err().contains("not a KEM output buffer"));
    }

    #[test]
    fn refuses_unknown_keys_and_duplicate_ids() {
        assert!(parse(&GOOD.replace("why = \"the", "note = \"the")).is_err());
        let dup = format!(
            "{GOOD}\n[[site]]\nid = \"ss-out\"\nkind = \"output\"\nwidth = 32\nwhy = \"x\"\n"
        );
        assert!(parse(&dup).unwrap_err().contains("listed twice"));
    }
}
