//! Evaluates a parsed [`System`] against a [`Policy`]: L1-L5 and L13 from
//! docs/archive/review/secureos-pq-vpn-architecture-plan.md.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

use crate::law::{Finding, LawId};
use crate::policy::{MrPolicy, Policy, Role};
use crate::sdf::{Perms, System};

pub fn check(system: &System, policy: &Policy) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Default deny (L4): every pd/mr/channel pair not described by the
    // policy is a violation. Done first so later checks can assume names
    // they look up either exist in the policy or have already been flagged.
    check_default_deny(system, policy, &mut findings);

    let tainted = compute_taint(system, policy, &mut findings);

    check_secrets_and_taint(system, policy, &tainted, &mut findings);
    check_device_and_dma(system, policy, &mut findings);
    check_dma_setvar_present(system, policy, &mut findings);
    check_irq_duplicates(system, &mut findings);
    check_data_confinement(system, policy, &mut findings);
    check_availability(system, policy, &tainted, &mut findings);

    findings
}

fn pd_by_name<'a>(system: &'a System, name: &str) -> Option<&'a crate::sdf::Pd> {
    system.pds.iter().find(|p| p.name == name)
}

fn mrs_mapped_by(pd: &crate::sdf::Pd) -> impl Iterator<Item = &crate::sdf::Map> {
    pd.maps.iter()
}

/// L4: unknown pd/mr names, undeclared channels, out-of-policy perms, and
/// the always-denied constructs that are only meaningful once the pd's
/// policy role is known (`irq` outside a driver pd).
fn check_default_deny(system: &System, policy: &Policy, findings: &mut Vec<Finding>) {
    for pd in &system.pds {
        if policy.role(&pd.name).is_none() {
            findings.push(Finding::new(LawId::L4, format!("pd '{}' is not described by policy", pd.name)));
            continue;
        }
        if !pd.irqs.is_empty() && !policy.role(&pd.name).is_some_and(Role::owns_hardware) {
            findings.push(Finding::new(
                LawId::L4,
                format!("pd '{}' declares <irq> but is not a driver or timer", pd.name),
            ));
        }
        for irq in &pd.irqs {
            if !policy.irqs(&pd.name).is_some_and(|declared| declared.contains(irq)) {
                findings.push(Finding::new(
                    LawId::L4,
                    format!("pd '{}' claims irq {irq}, which is not listed in its policy irqs", pd.name),
                ));
            }
        }
    }

    for mr in &system.mrs {
        if !policy.mrs.contains_key(&mr.name) {
            findings.push(Finding::new(LawId::L4, format!("mr '{}' is not described by policy", mr.name)));
        }
    }

    // Channel pair presence, then each end's effective (default-applied)
    // pp/notify against what the policy declares for that end (finding 1).
    for channel in &system.channels {
        let [a, b] = &channel.ends;
        match policy.channel(&a.pd, &b.pd) {
            None => findings.push(Finding::new(
                LawId::L4,
                format!("channel between '{}' and '{}' is not described by policy", a.pd, b.pd),
            )),
            Some(cp) => {
                for end in [a, b] {
                    if end.pp != cp.expected_pp(&end.pd) {
                        findings.push(Finding::new(
                            LawId::L4,
                            format!(
                                "channel end for pd '{}' has pp={}, policy declares pp={}",
                                end.pd,
                                end.pp,
                                cp.expected_pp(&end.pd)
                            ),
                        ));
                    }
                    if end.notify != cp.expected_notify(&end.pd) {
                        findings.push(Finding::new(
                            LawId::L4,
                            format!(
                                "channel end for pd '{}' has notify={}, policy declares notify={}",
                                end.pd,
                                end.notify,
                                cp.expected_notify(&end.pd)
                            ),
                        ));
                    }
                }
            }
        }
    }

    // Executable permission on any mr mapped into more than one distinct
    // pd (denied outright regardless of mr kind).
    let mut mappers: BTreeMap<&str, HashSet<&str>> = BTreeMap::new();
    for pd in &system.pds {
        for m in mrs_mapped_by(pd) {
            mappers.entry(m.mr.as_str()).or_default().insert(pd.name.as_str());
        }
    }
    for pd in &system.pds {
        for m in mrs_mapped_by(pd) {
            if m.perms.x && mappers.get(m.mr.as_str()).is_some_and(|s| s.len() > 1) {
                findings.push(Finding::new(
                    LawId::L4,
                    format!("executable permission on shared mr '{}' mapped into pd '{}'", m.mr, pd.name),
                ));
            }
        }
    }

    // A map into an mr/pd combination the policy's `plain` share table does
    // not list, or with perms beyond what it lists.
    for pd in &system.pds {
        for m in mrs_mapped_by(pd) {
            if let Some(MrPolicy::Plain { shares }) = policy.mrs.get(m.mr.as_str()) {
                match shares.get(pd.name.as_str()) {
                    None => findings.push(Finding::new(
                        LawId::L4,
                        format!("pd '{}' maps mr '{}' but is not in its policy share list", pd.name, m.mr),
                    )),
                    Some(allowed) if !allowed.allows(m.perms) => findings.push(Finding::new(
                        LawId::L4,
                        format!("pd '{}' maps mr '{}' with perms beyond its policy allowance", pd.name, m.mr),
                    )),
                    Some(_) => {}
                }
            }
        }
    }
}

/// Pds tainted per L1: seeded by mapping a device mr, propagated over
/// channels and shared mrs, with the `key` and `timer` exemptions. A
/// `timer`'s own device page (not a NIC) does not seed taint.
fn compute_taint(system: &System, policy: &Policy, findings: &mut Vec<Finding>) -> BTreeSet<String> {
    let mut adjacency: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut add_edge = |from: &str, to: &str| {
        adjacency.entry(from.to_string()).or_default().insert(to.to_string());
    };

    // Shared-mr edges: unconditional, both directions, for every pair of
    // distinct pds that map the same mr.
    let mut mappers: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for pd in &system.pds {
        for m in mrs_mapped_by(pd) {
            mappers.entry(m.mr.as_str()).or_default().push(pd.name.as_str());
        }
    }
    for pds in mappers.values() {
        for a in pds {
            for b in pds {
                if a != b {
                    add_edge(a, b);
                }
            }
        }
    }

    // Channel edges, with the `key` and `timer` exemptions evaluated
    // directly (and reported as an L1 finding when they fail) below.
    for channel in &system.channels {
        let [a, b] = &channel.ends;
        let a_role = policy.role(&a.pd);
        let b_role = policy.role(&b.pd);

        let a_exempt = match a_role {
            Some(Role::Key) => channel_is_exempt(system, policy, a, b, findings),
            Some(Role::Timer) => timer_channel_is_exempt(system, policy, a, b, findings),
            _ => false,
        };
        let b_exempt = match b_role {
            Some(Role::Key) => channel_is_exempt(system, policy, b, a, findings),
            Some(Role::Timer) => timer_channel_is_exempt(system, policy, b, a, findings),
            _ => false,
        };

        if !a_exempt {
            add_edge(&b.pd, &a.pd);
        }
        if !b_exempt {
            add_edge(&a.pd, &b.pd);
        }
    }

    // `key` maps no mr except the secrets mr (L1), independent of taint.
    for pd in &system.pds {
        if policy.role(&pd.name) != Some(Role::Key) {
            continue;
        }
        for m in mrs_mapped_by(pd) {
            if !matches!(policy.mrs.get(m.mr.as_str()), Some(MrPolicy::Secrets)) {
                findings.push(Finding::new(
                    LawId::L1,
                    format!("key pd '{}' maps mr '{}', not just the secrets mr", pd.name, m.mr),
                ));
            }
        }
    }

    let seeds: Vec<&str> = system
        .pds
        .iter()
        .filter(|pd| policy.role(&pd.name) != Some(Role::Timer))
        .filter(|pd| mrs_mapped_by(pd).any(|m| matches!(policy.mrs.get(m.mr.as_str()), Some(MrPolicy::Device { .. }))))
        .map(|pd| pd.name.as_str())
        .collect();

    let mut tainted: BTreeSet<String> = seeds.iter().map(|s| s.to_string()).collect();
    let mut queue: VecDeque<String> = tainted.iter().cloned().collect();
    while let Some(next) = queue.pop_front() {
        if let Some(neighbours) = adjacency.get(&next) {
            for n in neighbours {
                if tainted.insert(n.clone()) {
                    queue.push_back(n.clone());
                }
            }
        }
    }
    // A `timer` is trusted by later laws (L8, L13); one reached by taint
    // through any edge (e.g. a shared mr) is an L1 violation, not just a
    // tainted pd.
    for pd in &system.pds {
        if policy.role(&pd.name) == Some(Role::Timer) && tainted.contains(&pd.name) {
            findings.push(Finding::new(LawId::L1, format!("timer pd '{}' is tainted", pd.name)));
        }
    }
    tainted
}

/// Whether the channel between `key_end` (a `key`-role pd) and `peer`
/// satisfies L1's exemption: `peer.pp == true`, `key_end.pp == false`,
/// `peer.notify == false`. A failure is reported as L1 directly, in
/// addition to the edge then propagating taint normally.
fn channel_is_exempt(
    system: &System,
    policy: &Policy,
    key_end: &crate::sdf::ChannelEnd,
    peer: &crate::sdf::ChannelEnd,
    findings: &mut Vec<Finding>,
) -> bool {
    let key_maps_only_secrets = pd_by_name(system, &key_end.pd)
        .into_iter()
        .flat_map(mrs_mapped_by)
        .all(|m| matches!(policy.mrs.get(m.mr.as_str()), Some(MrPolicy::Secrets)));
    let ok = peer.pp && !key_end.pp && !peer.notify && key_maps_only_secrets;
    if !ok {
        findings.push(Finding::new(
            LawId::L1,
            format!(
                "channel between key pd '{}' and '{}' does not meet the key exemption \
                 (peer pp=true, key pp=false, peer notify=false, key maps only the secrets mr)",
                key_end.pd, peer.pd
            ),
        ));
    }
    ok
}

/// Whether the channel between `timer_end` (a `timer`-role pd) and `peer`
/// satisfies L1's notify-only exemption: `pp == false` on both ends (a
/// PPC reply would carry data chosen by the callee into the timer),
/// `peer.notify == false`, and the timer maps only its own device mrs (so
/// it shares no memory). A failure is reported as L1 directly.
fn timer_channel_is_exempt(
    system: &System,
    policy: &Policy,
    timer_end: &crate::sdf::ChannelEnd,
    peer: &crate::sdf::ChannelEnd,
    findings: &mut Vec<Finding>,
) -> bool {
    let maps_only_own_device = pd_by_name(system, &timer_end.pd)
        .into_iter()
        .flat_map(mrs_mapped_by)
        .all(|m| matches!(policy.mrs.get(m.mr.as_str()), Some(MrPolicy::Device { owner, .. }) if owner == &timer_end.pd));
    let ok = !peer.pp && !timer_end.pp && !peer.notify && maps_only_own_device;
    if !ok {
        findings.push(Finding::new(
            LawId::L1,
            format!(
                "channel between timer pd '{}' and '{}' does not meet the timer exemption \
                 (pp=false on both ends, peer notify=false, timer maps only its own device mr)",
                timer_end.pd, peer.pd
            ),
        ));
    }
    ok
}

/// L1 (tainted pds map no secret mr) and L2 (the secrets mr is mapped only
/// into `key`, and `prefill_path` appears only on the secrets mr).
fn check_secrets_and_taint(
    system: &System,
    policy: &Policy,
    tainted: &BTreeSet<String>,
    findings: &mut Vec<Finding>,
) {
    let secrets_mr: Option<&str> =
        policy.mrs.iter().find(|(_, mr)| matches!(mr, MrPolicy::Secrets)).map(|(name, _)| name.as_str());

    for pd in &system.pds {
        for m in mrs_mapped_by(pd) {
            if matches!(policy.mrs.get(m.mr.as_str()), Some(MrPolicy::Secrets)) {
                if tainted.contains(&pd.name) {
                    findings.push(Finding::new(
                        LawId::L1,
                        format!("tainted pd '{}' maps secrets mr '{}'", pd.name, m.mr),
                    ));
                }
                if policy.role(&pd.name) != Some(Role::Key) {
                    findings.push(Finding::new(
                        LawId::L2,
                        format!("secrets mr '{}' is mapped into non-key pd '{}'", m.mr, pd.name),
                    ));
                }
            }
        }
    }

    for mr in &system.mrs {
        if mr.prefill_path.is_some() && Some(mr.name.as_str()) != secrets_mr {
            findings.push(Finding::new(
                LawId::L2,
                format!("prefill_path is only allowed on the secrets mr, not '{}'", mr.name),
            ));
        }
    }

    // L2: at most one pd may hold the `key` role, and the secrets mr (if
    // any) may be mapped by at most one pd — either violation defeats "one
    // MR for static secrets, mapped only into key".
    let key_pds: Vec<&str> =
        system.pds.iter().filter(|pd| policy.role(&pd.name) == Some(Role::Key)).map(|pd| pd.name.as_str()).collect();
    if key_pds.len() > 1 {
        findings.push(Finding::new(LawId::L2, format!("more than one pd has role 'key': {}", key_pds.join(", "))));
    }

    if let Some(secrets_mr) = secrets_mr {
        let mappers: Vec<&str> = system
            .pds
            .iter()
            .filter(|pd| mrs_mapped_by(pd).any(|m| m.mr == secrets_mr))
            .map(|pd| pd.name.as_str())
            .collect();
        if mappers.len() > 1 {
            findings.push(Finding::new(
                LawId::L2,
                format!("secrets mr '{secrets_mr}' is mapped into more than one pd: {}", mappers.join(", ")),
            ));
        }
    }
}

/// L5: device/DMA ownership, page-granular overlap, physical-range pinning
/// against the policy, board-RAM overlap, and `setvar region_paddr`.
fn check_device_and_dma(system: &System, policy: &Policy, findings: &mut Vec<Finding>) {
    // Device mr ownership and page-granular overlap across different owners.
    let mut device_ranges: Vec<(&str, &str, u64, u64)> = Vec::new(); // (mr, owner, start, end)
    for mr in &system.mrs {
        let Some(MrPolicy::Device { owner, .. }) = policy.mrs.get(mr.name.as_str()) else { continue };
        if let Some(phys_addr) = mr.phys_addr {
            let size = mr.size.unwrap_or(mr.page_size);
            device_ranges.push((mr.name.as_str(), owner.as_str(), phys_addr, phys_addr.saturating_add(size)));
        }
    }
    for i in 0..device_ranges.len() {
        for j in (i + 1)..device_ranges.len() {
            let (mr_a, owner_a, start_a, end_a) = device_ranges[i];
            let (mr_b, owner_b, start_b, end_b) = device_ranges[j];
            if owner_a != owner_b && start_a < end_b && start_b < end_a {
                findings.push(Finding::new(
                    LawId::L5,
                    format!(
                        "device mr '{mr_a}' (owner '{owner_a}') overlaps mr '{mr_b}' (owner '{owner_b}') \
                         on the same physical pages"
                    ),
                ));
            }
        }
    }

    // phys_addr is only allowed on policy-declared device mrs.
    for mr in &system.mrs {
        if mr.phys_addr.is_some() && !matches!(policy.mrs.get(mr.name.as_str()), Some(MrPolicy::Device { .. })) {
            findings.push(Finding::new(
                LawId::L5,
                format!("mr '{}' has phys_addr but is not a policy-declared device mr", mr.name),
            ));
        }
    }

    // The `.system`'s phys_addr/size for a device mr must match the pinned
    // value the policy declares (finding 3): a mismatch is otherwise
    // invisible to every other check here, which all trust the policy's
    // numbers rather than the `.system`'s.
    for mr in &system.mrs {
        if let Some(MrPolicy::Device { phys_addr, size, .. }) = policy.mrs.get(mr.name.as_str())
            && (mr.phys_addr != Some(*phys_addr) || mr.size != Some(*size))
        {
            findings.push(Finding::new(
                LawId::L5,
                format!(
                    "device mr '{}' has phys_addr={:?}/size={:?}, policy pins phys_addr={phys_addr:#x}/size={size:#x}",
                    mr.name, mr.phys_addr, mr.size
                ),
            ));
        }
    }

    // A device mr's pinned physical range must not intersect board RAM
    // (C7: phys_addr is only allowed on device mrs "with no overlap with
    // board RAM"). Checked against the policy's own pinned range rather
    // than the `.system`'s, since a mismatch between the two is already
    // reported above.
    for (name, mp) in &policy.mrs {
        let MrPolicy::Device { phys_addr, size, .. } = mp else { continue };
        let end = phys_addr.saturating_add(*size);
        for (ram_start, ram_end) in &policy.ram {
            if phys_addr < ram_end && ram_start < &end {
                findings.push(Finding::new(
                    LawId::L5,
                    format!(
                        "device mr '{name}' [{phys_addr:#x}, {end:#x}) overlaps board ram [{ram_start:#x}, {ram_end:#x})"
                    ),
                ));
            }
        }
    }

    for pd in &system.pds {
        for m in mrs_mapped_by(pd) {
            match policy.mrs.get(m.mr.as_str()) {
                Some(MrPolicy::Device { owner, .. }) if owner != &pd.name => {
                    findings.push(Finding::new(
                        LawId::L5,
                        format!("device mr '{}' (owner '{owner}') is also mapped into pd '{}'", m.mr, pd.name),
                    ));
                }
                Some(MrPolicy::Dma { owner }) if owner != &pd.name => {
                    findings.push(Finding::new(
                        LawId::L5,
                        format!("dma mr '{}' (owner '{owner}') is also mapped into pd '{}'", m.mr, pd.name),
                    ));
                }
                _ => {}
            }
        }

        for sv in &pd.setvars {
            match policy.mrs.get(sv.region_paddr.as_str()) {
                Some(MrPolicy::Dma { owner }) if owner == &pd.name && policy.role(&pd.name) == Some(Role::Driver) => {}
                _ => findings.push(Finding::new(
                    LawId::L5,
                    format!(
                        "setvar '{}' names region_paddr '{}', which is not pd '{}'s own policy-declared dma mr",
                        sv.symbol, sv.region_paddr, pd.name
                    ),
                )),
            }
        }
    }
}

/// L5: the same hardware IRQ number claimed by more than one pd's `<irq>`.
/// Independent of whether either claim is itself policy-declared (L4
/// already covers that); two pds racing to ack the same line is a
/// device-ownership violation in its own right.
fn check_irq_duplicates(system: &System, findings: &mut Vec<Finding>) {
    let mut claimants: BTreeMap<u64, BTreeSet<&str>> = BTreeMap::new();
    for pd in &system.pds {
        for irq in &pd.irqs {
            claimants.entry(*irq).or_default().insert(pd.name.as_str());
        }
    }
    for (irq, pds) in claimants {
        if pds.len() > 1 {
            let names: Vec<&str> = pds.into_iter().collect();
            findings.push(Finding::new(LawId::L5, format!("irq {irq} is claimed by more than one pd: {}", names.join(", "))));
        }
    }
}

/// L5: every policy-declared DMA mr needs its owner's `setvar region_paddr`;
/// otherwise the driver's paddr symbol keeps its default of 0, which is a
/// real physical address the device would be programmed to use.
fn check_dma_setvar_present(system: &System, policy: &Policy, findings: &mut Vec<Finding>) {
    for (mr, mp) in &policy.mrs {
        let MrPolicy::Dma { owner } = mp else { continue };
        let has = system
            .pds
            .iter()
            .any(|pd| &pd.name == owner && pd.setvars.iter().any(|sv| sv.region_paddr == *mr));
        if !has {
            findings.push(Finding::new(
                LawId::L5,
                format!("dma mr '{mr}' has no setvar region_paddr in its owner '{owner}'"),
            ));
        }
    }
}

/// L3: a `data` mr is mapped only into its producer (any perms) and its
/// declared consumers (read-only).
fn check_data_confinement(system: &System, policy: &Policy, findings: &mut Vec<Finding>) {
    for pd in &system.pds {
        for m in mrs_mapped_by(pd) {
            let Some(MrPolicy::Data { producer, consumers }) = policy.mrs.get(m.mr.as_str()) else { continue };
            if &pd.name == producer {
                continue;
            }
            if !consumers.contains(&pd.name) {
                findings.push(Finding::new(
                    LawId::L3,
                    format!("pd '{}' maps data mr '{}' but is neither its producer nor a declared consumer", pd.name, m.mr),
                ));
            } else if m.perms != (Perms { r: true, w: false, x: false }) {
                findings.push(Finding::new(
                    LawId::L3,
                    format!("consumer pd '{}' must map data mr '{}' read-only", pd.name, m.mr),
                ));
            }
        }
    }
}

/// L13: explicit `budget < period` and the per-pd/sum ratio caps on every
/// tainted pd, `key` passive, and priority ordering.
fn check_availability(system: &System, policy: &Policy, tainted: &BTreeSet<String>, findings: &mut Vec<Finding>) {
    for pd in &system.pds {
        if policy.role(&pd.name) == Some(Role::Key) && !pd.passive {
            findings.push(Finding::new(LawId::L13, format!("key pd '{}' must be passive", pd.name)));
        }
    }

    for (below, above) in &policy.priority_below {
        for a in system.pds.iter().filter(|pd| policy.role(&pd.name) == Some(*below)) {
            for b in system.pds.iter().filter(|pd| policy.role(&pd.name) == Some(*above)) {
                if a.priority >= b.priority {
                    findings.push(Finding::new(
                        LawId::L13,
                        format!("pd '{}' (priority {}) must be strictly below pd '{}' (priority {})", a.name, a.priority, b.name, b.priority),
                    ));
                }
            }
        }
    }

    let mut ratio_sum = 0.0;
    for pd in &system.pds {
        if !tainted.contains(&pd.name) {
            continue;
        }
        if !pd.budget_explicit || !pd.period_explicit || pd.budget_us >= pd.period_us {
            findings.push(Finding::new(
                LawId::L13,
                format!("tainted pd '{}' needs an explicit budget < period", pd.name),
            ));
            continue;
        }
        #[allow(clippy::cast_precision_loss)] // microsecond budgets/periods fit a f64 mantissa comfortably
        let ratio = pd.budget_us as f64 / pd.period_us as f64;
        ratio_sum += ratio;
        if ratio > policy.ratio_cap {
            findings.push(Finding::new(
                LawId::L13,
                format!("tainted pd '{}' budget/period ratio {ratio:.3} exceeds the per-pd cap {}", pd.name, policy.ratio_cap),
            ));
        }
    }
    if ratio_sum > policy.ratio_sum_cap {
        findings.push(Finding::new(
            LawId::L13,
            format!("tainted pds' summed budget/period ratio {ratio_sum:.3} exceeds the sum cap {}", policy.ratio_sum_cap),
        ));
    }
}
