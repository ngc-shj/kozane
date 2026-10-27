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

use crate::sdf::{DEFAULT_NOTIFY, DEFAULT_PP};

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
    Timer,
    /// The TPM driver (M5 plan C9): untainted, owns the TIS page, callee
    /// of `key` pds only.
    Tpm,
    /// The entropy driver (M7 plan C6): untainted, owns the virtio-rng page
    /// and its DMA mr, callee only, with `key`'s exemption shape towards
    /// every caller (L1 as amended).
    Rng,
    /// The fault handler (M7 plan C8): the parent of every other pd, the
    /// only pd with `smc`, untainted; it maps only a record page `audit`
    /// reads, and its one channel notifies `audit` and is never signalled
    /// back (L1, L4 as amended).
    Supervisor,
}

impl Role {
    fn parse(raw: &str) -> Result<Role, PolicyError> {
        match raw {
            "driver" => Ok(Role::Driver),
            "untrusted_input" => Ok(Role::UntrustedInput),
            "key" => Ok(Role::Key),
            "data" => Ok(Role::Data),
            "service" => Ok(Role::Service),
            "timer" => Ok(Role::Timer),
            "tpm" => Ok(Role::Tpm),
            "rng" => Ok(Role::Rng),
            "supervisor" => Ok(Role::Supervisor),
            other => Err(err(format!(
                "unknown role '{other}' (expected driver, untrusted_input, key, data, service, timer, tpm, rng or \
                 supervisor)"
            ))),
        }
    }

    /// Roles that may own device mrs and claim hardware IRQs (L4/L5).
    pub fn owns_hardware(self) -> bool {
        matches!(self, Role::Driver | Role::Timer)
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

/// The PL011 page, the only page a console mr may be pinned at (M5 plan C6;
/// user-mappable in both Microkit configs per `platform_gen.json`).
pub const PL011_PAGE: (u64, u64) = (0x900_0000, 0x1000);

/// The TPM TIS page, locality 0 (M5 plan C9): QEMU virt's tpm-tis-device,
/// the first device on its platform bus. The only page a tpm mr may be
/// pinned at.
pub const TIS_PAGE: (u64, u64) = (0xc00_0000, 0x1000);

/// The virtio-rng page (M7 plan C6): QEMU virt's virtio-mmio slots 0-7,
/// where `-device virtio-rng-device,bus=virtio-mmio-bus.0` sits and no
/// other device does. The only page an rng mr may be pinned at.
pub const RNG_PAGE: (u64, u64) = (0xa00_0000, 0x1000);

#[derive(Debug, Clone)]
pub enum MrPolicy {
    /// MMIO owned by exactly one driver, page-granular (L5). `phys_addr`
    /// and `size` pin the physical range the `.system` must match exactly
    /// (finding 3) and are what the board-RAM overlap check (finding 2)
    /// uses. `console` marks the one console page, owned by a `service`
    /// pd (L5 as amended by the M5 plan, C6); `tpm` the TIS page, owned by
    /// a `tpm` pd (C9); `rng` the virtio-rng page, owned by an `rng` pd
    /// (M7 plan C6).
    Device { owner: String, phys_addr: u64, size: u64, console: bool, tpm: bool, rng: bool },
    /// DMA buffer owned by exactly one driver (or the `rng` pd), never
    /// shared (L5).
    Dma { owner: String },
    /// An MR holding static secrets, mapped only into its `key`-role owner
    /// (L2). Each key pd owns at most one.
    Secrets { owner: String },
    /// Producer writes, declared consumers read only (L3).
    Data { producer: String, consumers: BTreeSet<String> },
    /// Any other shared buffer (e.g. a ring region): explicit per-pd perms.
    Plain { shares: BTreeMap<String, SharePerms> },
}

impl MrPolicy {
    /// A console mr pinned at the PL011 page: the one device mr that does
    /// not seed taint (L1). Keyed to the pin, not to the flag alone.
    pub fn is_pl011_console(&self) -> bool {
        matches!(self, MrPolicy::Device { console: true, phys_addr, size, .. } if (*phys_addr, *size) == PL011_PAGE)
    }

    /// A tpm mr pinned at the TIS page: like the console, it does not seed
    /// taint (L1, S14), keyed to the pin.
    pub fn is_tis(&self) -> bool {
        matches!(self, MrPolicy::Device { tpm: true, phys_addr, size, .. } if (*phys_addr, *size) == TIS_PAGE)
    }

    /// An rng mr pinned at the virtio-rng page: the entropy device is no
    /// NIC and seeds no taint (L1 as amended by M7 plan C6), keyed to the pin.
    pub fn is_rng_page(&self) -> bool {
        matches!(self, MrPolicy::Device { rng: true, phys_addr, size, .. } if (*phys_addr, *size) == RNG_PAGE)
    }
}

/// Per-pd policy: its role plus, for `driver`-role pds, the hardware IRQ
/// numbers it is allowed to claim (L4/L5).
#[derive(Debug, Clone)]
pub struct PdPolicy {
    pub role: Role,
    pub irqs: BTreeSet<u64>,
}

/// Per-end `pp`/`notify` the `.system` must match exactly (L4). A pd name
/// absent from either map falls back to the Microkit default for that
/// attribute, same as an absent attribute in the `.system` itself.
#[derive(Debug, Clone, Default)]
pub struct ChannelPolicy {
    pp: BTreeMap<String, bool>,
    notify: BTreeMap<String, bool>,
}

impl ChannelPolicy {
    pub fn expected_pp(&self, pd: &str) -> bool {
        self.pp.get(pd).copied().unwrap_or(DEFAULT_PP)
    }

    pub fn expected_notify(&self, pd: &str) -> bool {
        self.notify.get(pd).copied().unwrap_or(DEFAULT_NOTIFY)
    }
}

/// Hard ceiling on `budgets.ratio_sum_cap` (M3 plan, Budgets): what is left
/// covers the untainted `timer` reservation and the passive pds' init.
pub const RATIO_SUM_CEILING: f64 = 0.95;

#[derive(Debug, Clone)]
pub struct Policy {
    pds: BTreeMap<String, PdPolicy>,
    pub mrs: BTreeMap<String, MrPolicy>,
    pub channels: BTreeMap<(String, String), ChannelPolicy>,
    pub priority_below: Vec<(Role, Role)>,
    pub ratio_cap: f64,
    pub ratio_sum_cap: f64,
    /// Board RAM ranges (half-open `[start, end)`), from `[board] ram`.
    pub ram: Vec<(u64, u64)>,
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
    board: RawBoard,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPd {
    role: String,
    #[serde(default)]
    irqs: Vec<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RawMr {
    Device {
        owner: String,
        phys_addr: u64,
        size: u64,
        #[serde(default)]
        console: bool,
        #[serde(default)]
        tpm: bool,
        #[serde(default)]
        rng: bool,
    },
    Dma { owner: String },
    // `Option` so a missing owner gets an L2-specific policy error rather
    // than serde's generic "missing field".
    Secrets { owner: Option<String> },
    Data { producer: String, consumers: Vec<String> },
    Plain { shares: BTreeMap<String, String> },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawChannel {
    between: Vec<String>,
    #[serde(default)]
    pp: BTreeMap<String, bool>,
    #[serde(default)]
    notify: BTreeMap<String, bool>,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBoard {
    ram: Vec<RawRamRegion>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRamRegion {
    start: u64,
    size: u64,
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
            let mut irqs = BTreeSet::new();
            for n in pd.irqs {
                if !irqs.insert(n) {
                    return Err(err(format!("duplicate irq {n} declared for pd '{name}'")));
                }
            }
            if !irqs.is_empty() && !role.owns_hardware() {
                return Err(err(format!("pd '{name}' declares irqs but its role is not 'driver' or 'timer'")));
            }
            if pds.insert(name.clone(), PdPolicy { role, irqs }).is_some() {
                return Err(err(format!("duplicate pd '{name}' in policy")));
            }
        }

        let require_pd = |pds: &BTreeMap<String, PdPolicy>, name: &str| -> Result<(), PolicyError> {
            if pds.contains_key(name) {
                Ok(())
            } else {
                Err(err(format!("policy references undeclared pd '{name}'")))
            }
        };
        let require_role = |pds: &BTreeMap<String, PdPolicy>, name: &str, want: Role| -> Result<(), PolicyError> {
            require_pd(pds, name)?;
            if pds.get(name).map(|p| p.role) == Some(want) {
                Ok(())
            } else {
                Err(err(format!("pd '{name}' must have role matching its mr ownership")))
            }
        };

        let mut mrs = BTreeMap::new();
        let mut secrets_owners: BTreeMap<String, String> = BTreeMap::new();
        for (name, mr) in raw.mrs {
            let policy_mr = match mr {
                RawMr::Device { owner, phys_addr, size, console, tpm, rng } => {
                    require_pd(&pds, &owner)?;
                    let role = pds.get(&owner).map(|p| p.role);
                    // A service or tpm pd's devices are judged by the laws
                    // (only a console, C6, or the TIS page, C9), so a wrong
                    // one is a reported violation rather than an unloadable
                    // policy.
                    if !role.is_some_and(|r| r.owns_hardware() || matches!(r, Role::Service | Role::Tpm | Role::Rng)) {
                        return Err(err(format!(
                            "device mr '{name}' owner '{owner}' must have role 'driver', 'timer', 'service', 'tpm' or 'rng'"
                        )));
                    }
                    if rng && role != Some(Role::Rng) {
                        return Err(err(format!(
                            "device mr '{name}' is marked rng but its owner '{owner}' is not an rng pd"
                        )));
                    }
                    if console && role != Some(Role::Service) {
                        return Err(err(format!(
                            "device mr '{name}' is marked console but its owner '{owner}' is not a service pd"
                        )));
                    }
                    if tpm && role != Some(Role::Tpm) {
                        return Err(err(format!(
                            "device mr '{name}' is marked tpm but its owner '{owner}' is not a tpm pd"
                        )));
                    }
                    if size == 0 {
                        return Err(err(format!("device mr '{name}' must have a nonzero size")));
                    }
                    if phys_addr.checked_add(size).is_none() {
                        return Err(err(format!("device mr '{name}' phys_addr + size overflows a 64-bit address")));
                    }
                    MrPolicy::Device { owner, phys_addr, size, console, tpm, rng }
                }
                RawMr::Dma { owner } => {
                    require_pd(&pds, &owner)?;
                    if !matches!(pds.get(&owner).map(|p| p.role), Some(Role::Driver | Role::Rng)) {
                        return Err(err(format!("dma mr '{name}' owner '{owner}' must have role 'driver' or 'rng'")));
                    }
                    MrPolicy::Dma { owner }
                }
                RawMr::Secrets { owner } => {
                    let owner = owner.ok_or_else(|| {
                        err(format!("secrets mr '{name}' has no owner (L2: every secrets mr names its key pd)"))
                    })?;
                    require_role(&pds, &owner, Role::Key)?;
                    if let Some(other) = secrets_owners.insert(owner.clone(), name.clone()) {
                        return Err(err(format!(
                            "key pd '{owner}' owns both secrets mrs '{other}' and '{name}' (L2: one each)"
                        )));
                    }
                    MrPolicy::Secrets { owner }
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
        let mut channels = BTreeMap::new();
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
            for pd_name in c.pp.keys().chain(c.notify.keys()) {
                if pd_name != &a && pd_name != &b {
                    return Err(err(format!(
                        "channel between '{a}' and '{b}' has a pp/notify override for '{pd_name}', which is neither end"
                    )));
                }
            }
            let pair = if a < b { (a.clone(), b.clone()) } else { (b.clone(), a.clone()) };
            if channels.insert(pair, ChannelPolicy { pp: c.pp, notify: c.notify }).is_some() {
                return Err(err(format!("duplicate channel between '{a}' and '{b}' in policy")));
            }
        }

        let mut priority_below = Vec::new();
        for pair in raw.priority.below {
            let [lo, hi]: [String; 2] =
                pair.try_into().map_err(|_| err("priority.below entries must have exactly two roles"))?;
            priority_below.push((Role::parse(&lo)?, Role::parse(&hi)?));
        }

        // `!(x > 0.0 && x <= 1.0)` rather than `x <= 0.0 || x > 1.0`: the
        // latter lets NaN through (every comparison against NaN is false),
        // silently disabling both ratio caps.
        if !(raw.budgets.ratio_cap > 0.0 && raw.budgets.ratio_cap <= 1.0) {
            return Err(err("budgets.ratio_cap must be in (0, 1]"));
        }
        if !(raw.budgets.ratio_sum_cap > 0.0 && raw.budgets.ratio_sum_cap <= RATIO_SUM_CEILING) {
            return Err(err(format!(
                "budgets.ratio_sum_cap must be in (0, {RATIO_SUM_CEILING}]: raising it past the ceiling means re-planning, not an amendment"
            )));
        }

        // An empty list would silently disable the board-RAM overlap check.
        if raw.board.ram.is_empty() {
            return Err(err("board.ram must list at least one RAM region"));
        }
        let mut ram = Vec::new();
        for r in raw.board.ram {
            if r.size == 0 {
                return Err(err("board.ram region must have a nonzero size"));
            }
            let end = r.start.checked_add(r.size).ok_or_else(|| err("board.ram region start + size overflows a 64-bit address"))?;
            ram.push((r.start, end));
        }

        Ok(Policy {
            pds,
            mrs,
            channels,
            priority_below,
            ratio_cap: raw.budgets.ratio_cap,
            ratio_sum_cap: raw.budgets.ratio_sum_cap,
            ram,
        })
    }

    pub fn role(&self, pd: &str) -> Option<Role> {
        self.pds.get(pd).map(|p| p.role)
    }

    /// Every pd the policy describes, by name.
    pub fn pd_names(&self) -> impl Iterator<Item = &str> {
        self.pds.keys().map(String::as_str)
    }

    /// The driver irqs declared for `pd`, or `None` if `pd` is undeclared.
    pub fn irqs(&self, pd: &str) -> Option<&BTreeSet<u64>> {
        self.pds.get(pd).map(|p| &p.irqs)
    }

    /// The declared policy for the channel between `a` and `b` (order
    /// doesn't matter), if any.
    pub fn channel(&self, a: &str, b: &str) -> Option<&ChannelPolicy> {
        let pair = if a < b { (a.to_string(), b.to_string()) } else { (b.to_string(), a.to_string()) };
        self.channels.get(&pair)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const BOARD: &str = r#"
        [board]
        ram = [{ start = 0x4000_0000, size = 0x8000_0000 }]
    "#;

    #[test]
    fn minimal_policy_loads() {
        let text = format!(
            r#"
            [pds.hello]
            role = "service"

            [budgets]
            ratio_cap = 0.2
            ratio_sum_cap = 0.5
            {BOARD}
        "#
        );
        let p = Policy::load(&text).unwrap();
        assert_eq!(p.role("hello"), Some(Role::Service));
    }

    #[test]
    fn unknown_role_is_rejected() {
        let text = format!(
            r#"
            [pds.hello]
            role = "bogus"

            [budgets]
            ratio_cap = 0.2
            ratio_sum_cap = 0.5
            {BOARD}
        "#
        );
        assert!(Policy::load(&text).is_err());
    }

    fn secrets_policy(mrs: &str) -> String {
        format!(
            r#"
            [pds.key]
            role = "key"

            [pds.pqkey]
            role = "key"

            [pds.hs]
            role = "service"
            {mrs}

            [budgets]
            ratio_cap = 0.2
            ratio_sum_cap = 0.5
            {BOARD}
        "#
        )
    }

    #[test]
    fn two_secrets_mrs_owned_by_one_key_pd_are_rejected() {
        let text = secrets_policy(
            r#"
            [mrs.secrets_a]
            kind = "secrets"
            owner = "key"

            [mrs.secrets_b]
            kind = "secrets"
            owner = "key"
        "#,
        );
        assert!(Policy::load(&text).is_err());
    }

    #[test]
    fn one_secrets_mr_per_key_pd_loads() {
        let text = secrets_policy(
            r#"
            [mrs.secrets_a]
            kind = "secrets"
            owner = "key"

            [mrs.secrets_b]
            kind = "secrets"
            owner = "pqkey"
        "#,
        );
        assert!(Policy::load(&text).is_ok());
    }

    #[test]
    fn secrets_mr_without_owner_is_rejected() {
        let text = secrets_policy(
            r#"
            [mrs.secrets_a]
            kind = "secrets"
        "#,
        );
        let e = Policy::load(&text).unwrap_err().to_string();
        assert!(e.contains("has no owner"), "{e}");
    }

    #[test]
    fn secrets_mr_owned_by_a_non_key_pd_is_rejected() {
        let text = secrets_policy(
            r#"
            [mrs.secrets_a]
            kind = "secrets"
            owner = "hs"
        "#,
        );
        assert!(Policy::load(&text).is_err());
    }

    #[test]
    fn empty_board_ram_is_rejected() {
        let text = r#"
            [pds.hello]
            role = "service"

            [budgets]
            ratio_cap = 0.2
            ratio_sum_cap = 0.5

            [board]
            ram = []
        "#;
        assert!(Policy::load(text).is_err());
    }

    #[test]
    fn missing_board_is_rejected() {
        let text = r#"
            [pds.hello]
            role = "service"

            [budgets]
            ratio_cap = 0.2
            ratio_sum_cap = 0.5
        "#;
        assert!(Policy::load(text).is_err());
    }

    #[test]
    fn nan_ratio_cap_is_rejected() {
        let text = format!(
            r#"
            [pds.hello]
            role = "service"

            [budgets]
            ratio_cap = nan
            ratio_sum_cap = 0.5
            {BOARD}
        "#
        );
        assert!(Policy::load(&text).is_err());
    }

    #[test]
    fn ratio_cap_of_exactly_one_is_accepted() {
        let text = format!(
            r#"
            [pds.hello]
            role = "service"

            [budgets]
            ratio_cap = 1.0
            ratio_sum_cap = 0.5
            {BOARD}
        "#
        );
        assert!(Policy::load(&text).is_ok());
    }

    #[test]
    fn ratio_sum_cap_of_one_is_above_the_ceiling() {
        let text = format!(
            r#"
            [pds.hello]
            role = "service"

            [budgets]
            ratio_cap = 0.2
            ratio_sum_cap = 1.0
            {BOARD}
        "#
        );
        assert!(Policy::load(&text).is_err());
    }

    fn console_policy(owner_role: &str) -> String {
        format!(
            r#"
            [pds.audit]
            role = "{owner_role}"

            [mrs.uart]
            kind = "device"
            owner = "audit"
            phys_addr = 0x9000000
            size = 0x1000
            console = true

            [budgets]
            ratio_cap = 0.2
            ratio_sum_cap = 0.5
            {BOARD}
        "#
        )
    }

    #[test]
    fn console_owned_by_a_service_pd_loads() {
        let p = Policy::load(&console_policy("service")).unwrap();
        assert!(p.mrs["uart"].is_pl011_console());
    }

    #[test]
    fn console_owned_by_a_driver_is_rejected() {
        let e = Policy::load(&console_policy("driver")).unwrap_err().to_string();
        assert!(e.contains("is marked console but its owner 'audit' is not a service pd"), "{e}");
    }

    fn tpm_policy(owner_role: &str) -> String {
        format!(
            r#"
            [pds.tpm]
            role = "{owner_role}"

            [mrs.tis]
            kind = "device"
            owner = "tpm"
            phys_addr = 0xc000000
            size = 0x1000
            tpm = true

            [budgets]
            ratio_cap = 0.2
            ratio_sum_cap = 0.5
            {BOARD}
        "#
        )
    }

    #[test]
    fn the_tis_page_owned_by_a_tpm_pd_loads() {
        let p = Policy::load(&tpm_policy("tpm")).unwrap();
        assert_eq!(p.role("tpm"), Some(Role::Tpm));
        assert!(p.mrs["tis"].is_tis());
    }

    #[test]
    fn a_tpm_mr_owned_by_a_driver_is_rejected() {
        let e = Policy::load(&tpm_policy("driver")).unwrap_err().to_string();
        assert!(e.contains("is marked tpm but its owner 'tpm' is not a tpm pd"), "{e}");
    }

    #[test]
    fn irqs_on_a_non_driver_pd_are_rejected() {
        let text = format!(
            r#"
            [pds.hello]
            role = "service"
            irqs = [1]

            [budgets]
            ratio_cap = 0.2
            ratio_sum_cap = 0.5
            {BOARD}
        "#
        );
        assert!(Policy::load(&text).is_err());
    }
}
