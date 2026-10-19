//! The architecture-wide law IDs that `tools/laws` can report (see
//! docs/archive/review/secureos-pq-vpn-architecture-plan.md, "Architecture-wide
//! security laws"). Variant order is the sort order used for the
//! `VIOLATIONS:` summary line.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LawId {
    /// Taint propagation and the `key` exemption.
    L1,
    /// Static secrets live only in secrets MRs, each mapped only into its
    /// owning `key` pd, with disjoint caller sets.
    L2,
    /// Tunnelled plaintext is reachable only by `data` and the inside path.
    L3,
    /// Default deny: anything not described by the policy is a violation.
    L4,
    /// Device/DMA memory-region ownership.
    L5,
    /// Availability: budgets, priorities, passive `key`.
    L13,
}

impl fmt::Display for LawId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LawId::L1 => "L1",
            LawId::L2 => "L2",
            LawId::L3 => "L3",
            LawId::L4 => "L4",
            LawId::L5 => "L5",
            LawId::L13 => "L13",
        };
        f.write_str(s)
    }
}

/// One violation: the law it breaks and a human-readable explanation.
#[derive(Debug, Clone)]
pub struct Finding {
    pub law: LawId,
    pub message: String,
}

impl Finding {
    pub fn new(law: LawId, message: impl Into<String>) -> Self {
        Self { law, message: message.into() }
    }
}
