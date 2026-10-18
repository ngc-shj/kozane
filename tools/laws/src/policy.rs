//! `policy/laws.toml` loading and validation.
//!
//! See the comment header of `policy/laws.toml` for the schema. Anything
//! wrong with the policy file itself (unknown role, a reference to an
//! undeclared PD, a nonsensical cap) is a usage error, not a law violation:
//! the policy is the checker's own input, not the `.system` file under
//! inspection.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Deserialize;

#[derive(Debug)]
pub struct PolicyError(String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "policy error: {}", self.0)
    }
}

fn err(msg: impl Into<String>) -> PolicyError {
    PolicyError(msg.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Driver,
    UntrustedInput,
    Key,
    Data,
    Service,
}

impl Role {
    fn parse(raw: &str) -> Result<Role, PolicyError> {
        match raw {
            "driver" => Ok(Role::Driver),
            "untrusted_input" => Ok(Role::UntrustedInput),
            "key" => Ok(Role::Key),
            "data" => Ok(Role::Data),
            "service" => Ok(Role::Service),
            other => Err(err(format!(
                "unknown role '{other}' (expected driver, untrusted_input, key, data or service)"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SharePerms {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}

impl SharePerms {
    fn parse(raw: &str) -> Result<SharePerms, PolicyError> {
        let mut p = SharePerms::default();
        for c in raw.chars() {
            match c {
                'r' => p.r = true,
                'w' => p.w = true,
                'x' => p.x = true,
                other => return Err(err(format!("unknown permission '{other}' in '{raw}'"))),
            }
        }
        if p.w && !p.r {
            return Err(err(format!("write-only perms ('{raw}') are not supported")));
        }
        Ok(p)
    }

    /// Whether `actual` (from the `.system`) is within what this entry allows.
    pub fn allows(&self, actual: crate::sdf::Perms) -> bool {
        (!actual.r || self.r) && (!actual.w || self.w) && (!actual.x || self.x)
    }
}

#[derive(Debug, Clone)]
pub enum MrPolicy {
    /// MMIO owned by exactly one driver, page-granular (L5).
    Device { owner: String },
    /// DMA buffer owned by exactly one driver, never shared (L5).
    Dma { owner: String },
    /// The one MR holding static secrets, mapped only into `key` (L2).
    Secrets,
    /// Producer writes, declared consumers read only (L3).
    Data { producer: String, consumers: BTreeSet<String> },
    /// Any other shared buffer (e.g. a ring region): explicit per-pd perms.
    Plain { shares: BTreeMap<String, SharePerms> },
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub pds: BTreeMap<String, Role>,
    pub mrs: BTreeMap<String, MrPolicy>,
    pub channels: BTreeSet<(String, String)>,
    pub priority_below: Vec<(Role, Role)>,
    pub ratio_cap: f64,
    pub ratio_sum_cap: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    pds: BTreeMap<String, RawPd>,
    #[serde(default)]
    mrs: BTreeMap<String, RawMr>,
    #[serde(default)]
    channels: Vec<RawChannel>,
    #[serde(default)]
    priority: RawPriority,
    budgets: RawBudgets,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPd {
    role: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RawMr {
    Device { owner: String },
    Dma { owner: String },
    Secrets,
    Data { producer: String, consumers: Vec<String> },
    Plain { shares: BTreeMap<String, String> },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawChannel {
    between: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawPriority {
    #[serde(default)]
    below: Vec<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBudgets {
    ratio_cap: f64,
    ratio_sum_cap: f64,
}

impl Policy {
    pub fn load(text: &str) -> Result<Policy, PolicyError> {
        let raw: RawPolicy = toml::from_str(text).map_err(|e| err(e.to_string()))?;
        Policy::from_raw(raw)
    }

    fn from_raw(raw: RawPolicy) -> Result<Policy, PolicyError> {
        let mut pds = BTreeMap::new();
        for (name, pd) in raw.pds {
            let role = Role::parse(&pd.role)?;
            if pds.insert(name.clone(), role).is_some() {
                return Err(err(format!("duplicate pd '{name}' in policy")));
            }
        }

        let require_pd = |pds: &BTreeMap<String, Role>, name: &str| -> Result<(), PolicyError> {
            if pds.contains_key(name) {
                Ok(())
            } else {
                Err(err(format!("policy references undeclared pd '{name}'")))
            }
        };
        let require_role = |pds: &BTreeMap<String, Role>, name: &str, want: Role| -> Result<(), PolicyError> {
            require_pd(pds, name)?;
            if pds.get(name) == Some(&want) {
                Ok(())
            } else {
                Err(err(format!("pd '{name}' must have role matching its mr ownership")))
            }
        };

        let mut mrs = BTreeMap::new();
        let mut secrets_count = 0usize;
        for (name, mr) in raw.mrs {
            let policy_mr = match mr {
                RawMr::Device { owner } => {
                    require_role(&pds, &owner, Role::Driver)?;
                    MrPolicy::Device { owner }
                }
                RawMr::Dma { owner } => {
                    require_role(&pds, &owner, Role::Driver)?;
                    MrPolicy::Dma { owner }
                }
                RawMr::Secrets => {
                    secrets_count += 1;
                    MrPolicy::Secrets
                }
                RawMr::Data { producer, consumers } => {
                    // The producer's own role (e.g. `driver`) is unrestricted: a
                    // `data`-kind mr is C3's generic producer/consumer sharing
                    // pattern, not limited to pds carrying the `data` role (which
                    // names the dedicated transport-key-holding pd of later
                    // milestones).
                    require_pd(&pds, &producer)?;
                    let mut set = BTreeSet::new();
                    for c in consumers {
                        require_pd(&pds, &c)?;
                        if !set.insert(c.clone()) {
                            return Err(err(format!("duplicate consumer '{c}' for mr '{name}'")));
                        }
                    }
                    MrPolicy::Data { producer, consumers: set }
                }
                RawMr::Plain { shares } => {
                    let mut parsed = BTreeMap::new();
                    for (pd, perms) in shares {
                        require_pd(&pds, &pd)?;
                        parsed.insert(pd, SharePerms::parse(&perms)?);
                    }
                    MrPolicy::Plain { shares: parsed }
                }
            };
            if mrs.insert(name.clone(), policy_mr).is_some() {
                return Err(err(format!("duplicate mr '{name}' in policy")));
            }
        }
        if secrets_count > 1 {
            return Err(err("at most one mr may have kind = \"secrets\" (L2: one MR for static secrets)"));
        }

        let mut channels = BTreeSet::new();
        for c in raw.channels {
            let [a, b]: [String; 2] = c
                .between
                .try_into()
                .map_err(|_| err("channel 'between' must list exactly two pd names"))?;
            require_pd(&pds, &a)?;
            require_pd(&pds, &b)?;
            if a == b {
                return Err(err(format!("channel 'between' names the same pd twice ('{a}')")));
            }
            let pair = if a < b { (a, b) } else { (b, a) };
            channels.insert(pair);
        }

        let mut priority_below = Vec::new();
        for pair in raw.priority.below {
            let [lo, hi]: [String; 2] =
                pair.try_into().map_err(|_| err("priority.below entries must have exactly two roles"))?;
            priority_below.push((Role::parse(&lo)?, Role::parse(&hi)?));
        }

        if raw.budgets.ratio_cap <= 0.0 || raw.budgets.ratio_cap > 1.0 {
            return Err(err("budgets.ratio_cap must be in (0, 1]"));
        }
        if raw.budgets.ratio_sum_cap <= 0.0 || raw.budgets.ratio_sum_cap > 1.0 {
            return Err(err("budgets.ratio_sum_cap must be in (0, 1]"));
        }

        Ok(Policy {
            pds,
            mrs,
            channels,
            priority_below,
            ratio_cap: raw.budgets.ratio_cap,
            ratio_sum_cap: raw.budgets.ratio_sum_cap,
        })
    }

    pub fn role(&self, pd: &str) -> Option<Role> {
        self.pds.get(pd).copied()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn minimal_policy_loads() {
        let text = r#"
            [pds.hello]
            role = "service"

            [budgets]
            ratio_cap = 0.2
            ratio_sum_cap = 0.5
        "#;
        let p = Policy::load(text).unwrap();
        assert_eq!(p.role("hello"), Some(Role::Service));
    }

    #[test]
    fn unknown_role_is_rejected() {
        let text = r#"
            [pds.hello]
            role = "bogus"

            [budgets]
            ratio_cap = 0.2
            ratio_sum_cap = 0.5
        "#;
        assert!(Policy::load(text).is_err());
    }

    #[test]
    fn duplicate_secrets_mr_is_rejected() {
        let text = r#"
            [pds.key]
            role = "key"

            [mrs.secrets_a]
            kind = "secrets"

            [mrs.secrets_b]
            kind = "secrets"

            [budgets]
            ratio_cap = 0.2
            ratio_sum_cap = 0.5
        "#;
        assert!(Policy::load(text).is_err());
    }
}
