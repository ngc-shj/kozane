//! Evaluates a parsed [`System`] against a [`Policy`]: L1-L5 and L13 from
//! docs/archive/review/secureos-pq-vpn-architecture-plan.md.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

use crate::law::{Finding, LawId};
use crate::policy::{MrPolicy, PL011_PAGE, Policy, RNG_PAGE, Role, TIS_PAGE};
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
    check_console(system, policy, &mut findings);
    check_tpm(system, policy, &tainted, &mut findings);
    check_rng(system, policy, &tainted, &mut findings);
    check_dma_setvar_present(system, policy, &mut findings);
    check_irq_duplicates(system, &mut findings);
    check_data_confinement(system, policy, &mut findings);
    check_availability(system, policy, &tainted, &mut findings);
    check_stack_guard(system, &mut findings);

    findings
}

/// Top of every pd's stack in Microkit 2.3.1 (`tool/microkit/src/sel4.rs`:
/// the IPC buffer at 0xfffffff000, one unmapped guard page, then the
/// stack growing down).
const STACK_TOP: u64 = 0xff_ffff_e000;

/// L4 (M3 GUARD): Microkit places a guard page above the stack only. The
/// page below it is unmapped only if no `<map>` reaches it, so every map
/// must end at least one page below the stack bottom. A pd without
/// `stack_size` is judged at the largest stack Microkit accepts.
fn check_stack_guard(system: &System, findings: &mut Vec<Finding>) {
    for pd in &system.pds {
        let bottom = STACK_TOP - pd.stack_size.unwrap_or(crate::sdf::MAX_STACK_SIZE);
        for m in mrs_mapped_by(pd) {
            let size = system.mrs.iter().find(|mr| mr.name == m.mr).map_or(0, |mr| mr.size.unwrap_or(mr.page_size));
            let end = m.vaddr.saturating_add(size);
            if end > bottom - 0x1000 {
                findings.push(Finding::new(
                    LawId::L4,
                    format!(
                        "pd '{}' maps mr '{}' up to {end:#x}, leaving no unmapped guard page below its stack at {bottom:#x}",
                        pd.name, m.mr
                    ),
                ));
            }
        }
    }
}

/// Σ budget/period, summed as an exact fraction and rounded once: adding
/// the rounded ratios drifts upwards (the M6 system's 0.1 + ... + 0.05 adds
/// up to 0.9500000000000001), and a sum exactly at the cap must pass. Falls
/// back to adding the rounded ratios if the fraction outgrows u128 (many
/// pairwise coprime periods), which no Microkit system comes near.
fn ratio_sum(ratios: &[(u64, u64)]) -> f64 {
    fn gcd(a: u128, b: u128) -> u128 {
        if b == 0 { a } else { gcd(b, a % b) }
    }
    let exact = ratios.iter().try_fold((0u128, 1u128), |(num, den), &(budget, period)| {
        let (b, p) = (u128::from(budget), u128::from(period));
        let num = num.checked_mul(p)?.checked_add(b.checked_mul(den)?)?;
        let den = den.checked_mul(p)?;
        let g = gcd(num, den).max(1);
        Some((num / g, den / g))
    });
    #[allow(clippy::cast_precision_loss)] // reduced fractions of microsecond budgets stay far below 2^53
    match exact {
        Some((num, den)) if den != 0 => num as f64 / den as f64,
        _ => ratios.iter().map(|&(b, p)| b as f64 / p as f64).sum(),
    }
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
/// `timer`'s own device page, the PL011 console and the TPM's TIS page
/// (none a NIC) do not seed taint. A `key` pd's call to a `tpm` pd (L1 as
/// amended by the M5 plan, C9) is no exemption: taint crosses it both ways,
/// and both ends must stay untainted.
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
            Some(Role::Key) if a.pp && matches!(b_role, Some(Role::Tpm | Role::Rng)) => false,
            Some(Role::Key) => channel_is_exempt(system, policy, a, b, findings),
            Some(Role::Timer) => timer_channel_is_exempt(system, policy, a, b, findings),
            Some(Role::Rng) => rng_channel_is_exempt(system, policy, a, b, findings),
            _ => false,
        };
        let b_exempt = match b_role {
            Some(Role::Key) if b.pp && matches!(a_role, Some(Role::Tpm | Role::Rng)) => false,
            Some(Role::Key) => channel_is_exempt(system, policy, b, a, findings),
            Some(Role::Timer) => timer_channel_is_exempt(system, policy, b, a, findings),
            Some(Role::Rng) => rng_channel_is_exempt(system, policy, b, a, findings),
            _ => false,
        };

        if !a_exempt {
            add_edge(&b.pd, &a.pd);
        }
        if !b_exempt {
            add_edge(&a.pd, &b.pd);
        }
    }

    // `key` maps no mr except a secrets mr (L1), independent of taint;
    // which one is L2's business.
    for pd in &system.pds {
        if policy.role(&pd.name) != Some(Role::Key) {
            continue;
        }
        for m in mrs_mapped_by(pd) {
            if !matches!(policy.mrs.get(m.mr.as_str()), Some(MrPolicy::Secrets { .. })) {
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
        .filter(|pd| {
            mrs_mapped_by(pd).any(|m| {
                policy.mrs.get(m.mr.as_str()).is_some_and(|mp| {
                    matches!(mp, MrPolicy::Device { .. })
                        && !mp.is_pl011_console()
                        && !mp.is_tis()
                        && !mp.is_rng_page()
                })
            })
        })
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
        .all(|m| matches!(policy.mrs.get(m.mr.as_str()), Some(MrPolicy::Secrets { .. })));
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

/// Whether the channel between `rng_end` (an `rng`-role pd) and `peer`
/// satisfies L1's exemption as amended by the M7 plan (C6), `key`'s shape:
/// `peer.pp == true`, `rng_end.pp == false`, `peer.notify == false`, and
/// the rng pd maps only its own rng device mr and its own dma mr (so it
/// shares no memory). A failure is reported as L1 directly.
fn rng_channel_is_exempt(
    system: &System,
    policy: &Policy,
    rng_end: &crate::sdf::ChannelEnd,
    peer: &crate::sdf::ChannelEnd,
    findings: &mut Vec<Finding>,
) -> bool {
    let maps_only_own = pd_by_name(system, &rng_end.pd).into_iter().flat_map(mrs_mapped_by).all(|m| {
        matches!(policy.mrs.get(m.mr.as_str()),
            Some(MrPolicy::Device { owner, rng: true, .. } | MrPolicy::Dma { owner }) if owner == &rng_end.pd)
    });
    let ok = peer.pp && !rng_end.pp && !peer.notify && maps_only_own;
    if !ok {
        findings.push(Finding::new(
            LawId::L1,
            format!(
                "channel between rng pd '{}' and '{}' does not meet the rng exemption \
                 (peer pp=true, rng pp=false, peer notify=false, rng maps only its device and dma mrs)",
                rng_end.pd, peer.pd
            ),
        ));
    }
    ok
}

/// L1 (tainted pds map no secret mr) and L2 (M3 plan amendment): every
/// secrets mr is mapped only by its policy owner and only read-only, each `key`-role pd maps
/// exactly its own secrets mr and nothing else, `prefill_path` appears
/// only on secrets mrs, no pd holds `pp` channels to two key pds, and no
/// key pd has two `pp` callers (M6 plan C12).
fn check_secrets_and_taint(
    system: &System,
    policy: &Policy,
    tainted: &BTreeSet<String>,
    findings: &mut Vec<Finding>,
) {
    for pd in &system.pds {
        for m in mrs_mapped_by(pd) {
            if let Some(MrPolicy::Secrets { owner }) = policy.mrs.get(m.mr.as_str()) {
                if tainted.contains(&pd.name) {
                    findings.push(Finding::new(
                        LawId::L1,
                        format!("tainted pd '{}' maps secrets mr '{}'", pd.name, m.mr),
                    ));
                }
                if owner != &pd.name {
                    findings.push(Finding::new(
                        LawId::L2,
                        format!("secrets mr '{}' (owner '{owner}') is mapped into pd '{}'", m.mr, pd.name),
                    ));
                }
                // The blob is prefilled by the loader and only ever read: a
                // writable or executable mapping lets a compromised owner
                // corrupt it in place.
                if m.perms != (Perms { r: true, w: false, x: false }) {
                    findings.push(Finding::new(
                        LawId::L2,
                        format!("secrets mr '{}' is mapped into pd '{}' with perms other than r", m.mr, pd.name),
                    ));
                }
            }
        }
    }

    for pd in system.pds.iter().filter(|pd| policy.role(&pd.name) == Some(Role::Key)) {
        let own: Vec<&str> = mrs_mapped_by(pd)
            .filter(|m| matches!(policy.mrs.get(m.mr.as_str()), Some(MrPolicy::Secrets { owner }) if owner == &pd.name))
            .map(|m| m.mr.as_str())
            .collect();
        if own.len() != 1 {
            findings.push(Finding::new(
                LawId::L2,
                format!("key pd '{}' maps {} of its own secrets mrs, expected exactly one", pd.name, own.len()),
            ));
        }
        for m in mrs_mapped_by(pd) {
            if !own.contains(&m.mr.as_str()) {
                findings.push(Finding::new(
                    LawId::L2,
                    format!("key pd '{}' maps mr '{}', which is not its own secrets mr", pd.name, m.mr),
                ));
            }
        }
    }

    for mr in &system.mrs {
        if mr.prefill_path.is_some() && !matches!(policy.mrs.get(mr.name.as_str()), Some(MrPolicy::Secrets { .. })) {
            findings.push(Finding::new(
                LawId::L2,
                format!("prefill_path is only allowed on secrets mrs, not '{}'", mr.name),
            ));
        }
    }

    // Disjoint caller sets: a pd able to call two key pds could combine
    // their label tables, which neither table was reviewed for.
    let mut callees: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for channel in &system.channels {
        let [a, b] = &channel.ends;
        for (caller, callee) in [(a, b), (b, a)] {
            if caller.pp && policy.role(&callee.pd) == Some(Role::Key) {
                callees.entry(caller.pd.as_str()).or_default().insert(callee.pd.as_str());
            }
        }
    }
    for (caller, keys) in callees {
        if keys.len() > 1 {
            let names: Vec<&str> = keys.into_iter().collect();
            findings.push(Finding::new(
                LawId::L2,
                format!("pd '{caller}' has pp channels to more than one key pd: {}", names.join(", ")),
            ));
        }
    }

    // At most one pp caller per key pd (M6 plan C12): with the rule above,
    // no key pd is shared, so no caller can delay or starve another's calls
    // into it. A caller is a channel whose peer end is pp=true and whose key
    // end is pp=false; the key pd's own PPC to `tpm` (pp=true on its end) is
    // none.
    let mut callers: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for channel in &system.channels {
        let [a, b] = &channel.ends;
        for (key, peer) in [(a, b), (b, a)] {
            if policy.role(&key.pd) == Some(Role::Key) && peer.pp && !key.pp {
                callers.entry(key.pd.as_str()).or_default().push(peer.pd.as_str());
            }
        }
    }
    for (key, mut peers) in callers {
        if peers.len() > 1 {
            peers.sort_unstable();
            findings.push(Finding::new(
                LawId::L2,
                format!("key pd '{key}' has {} pp callers, at most one: {}", peers.len(), peers.join(", ")),
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
                Some(MrPolicy::Dma { owner })
                    if owner == &pd.name && matches!(policy.role(&pd.name), Some(Role::Driver | Role::Rng)) => {}
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

/// L5 as amended by the M5 plan (C6): a `service` pd owns no device mr but
/// a console, at most one console mr exists, it is pinned at the PL011
/// page, and it is mapped `rw`. Mapping it into another pd is the general
/// device-ownership finding, and an irq on its owner is L4's.
fn check_console(system: &System, policy: &Policy, findings: &mut Vec<Finding>) {
    let consoles: Vec<&str> = policy
        .mrs
        .iter()
        .filter(|(_, mp)| matches!(mp, MrPolicy::Device { console: true, .. }))
        .map(|(name, _)| name.as_str())
        .collect();
    if consoles.len() > 1 {
        findings.push(Finding::new(
            LawId::L5,
            format!("{} console mrs are declared ({}); the PL011 page is the only console", consoles.len(), consoles.join(", ")),
        ));
    }
    for (name, mp) in &policy.mrs {
        let MrPolicy::Device { owner, phys_addr, size, console, .. } = mp else { continue };
        if *console && (*phys_addr, *size) != PL011_PAGE {
            findings.push(Finding::new(
                LawId::L5,
                format!(
                    "console mr '{name}' is pinned at phys_addr={phys_addr:#x}/size={size:#x}, not the PL011 page \
                     (phys_addr={:#x}/size={:#x})",
                    PL011_PAGE.0, PL011_PAGE.1
                ),
            ));
        }
        if !*console && policy.role(owner) == Some(Role::Service) {
            findings.push(Finding::new(
                LawId::L5,
                format!("service pd '{owner}' owns device mr '{name}', which is not a console mr"),
            ));
        }
    }
    for pd in &system.pds {
        for m in mrs_mapped_by(pd) {
            if matches!(policy.mrs.get(m.mr.as_str()), Some(MrPolicy::Device { console: true, .. }))
                && m.perms != (Perms { r: true, w: true, x: false })
            {
                findings.push(Finding::new(
                    LawId::L5,
                    format!("console mr '{}' is mapped into pd '{}' with perms other than rw", m.mr, pd.name),
                ));
            }
        }
    }
}

/// The `rng` role (M7 plan C6). L5 as amended: an rng mr is pinned at the
/// virtio-rng page, at most one is declared, and an `rng` pd owns no other
/// device. L1 as amended: an `rng` pd is untainted, maps nothing but its
/// rng mr and its dma mr, and is a callee only (pp=false on its own end;
/// the exemption, checked per channel, holds the rest).
fn check_rng(system: &System, policy: &Policy, tainted: &BTreeSet<String>, findings: &mut Vec<Finding>) {
    let rngs: Vec<&str> = policy
        .mrs
        .iter()
        .filter(|(_, mp)| matches!(mp, MrPolicy::Device { rng: true, .. }))
        .map(|(name, _)| name.as_str())
        .collect();
    if rngs.len() > 1 {
        findings.push(Finding::new(
            LawId::L5,
            format!("{} rng mrs are declared ({}); the virtio-rng page is the only one", rngs.len(), rngs.join(", ")),
        ));
    }
    for (name, mp) in &policy.mrs {
        let MrPolicy::Device { owner, phys_addr, size, rng, .. } = mp else { continue };
        if *rng && (*phys_addr, *size) != RNG_PAGE {
            findings.push(Finding::new(
                LawId::L5,
                format!(
                    "rng mr '{name}' is pinned at phys_addr={phys_addr:#x}/size={size:#x}, not the virtio-rng page \
                     (phys_addr={:#x}/size={:#x})",
                    RNG_PAGE.0, RNG_PAGE.1
                ),
            ));
        }
        if !*rng && policy.role(owner) == Some(Role::Rng) {
            findings.push(Finding::new(
                LawId::L5,
                format!("rng pd '{owner}' owns device mr '{name}', which is not the rng mr"),
            ));
        }
    }
    for pd in system.pds.iter().filter(|pd| policy.role(&pd.name) == Some(Role::Rng)) {
        if tainted.contains(&pd.name) {
            findings.push(Finding::new(LawId::L1, format!("rng pd '{}' is tainted", pd.name)));
        }
    }
    // Its callers are the PDs that draw randomness (M7 plan C7's member
    // set): `key` pds and `untrusted_input` ones. A `data`, `driver`,
    // `service`, `timer` or `tpm` pd has no business asking for seeds.
    for channel in &system.channels {
        let [a, b] = &channel.ends;
        for (end, peer) in [(a, b), (b, a)] {
            if policy.role(&end.pd) == Some(Role::Rng)
                && !matches!(policy.role(&peer.pd), Some(Role::Key | Role::UntrustedInput))
            {
                findings.push(Finding::new(
                    LawId::L1,
                    format!("rng pd '{}' has a channel to '{}', which is not a key or untrusted_input pd", end.pd, peer.pd),
                ));
            }
        }
    }
}

/// The `tpm` role (M5 plan C9). L5 as amended: a tpm mr is pinned at the
/// TIS page, at most one is declared, and a `tpm` pd owns no other device.
/// L1 as amended: a `tpm` pd is untainted, maps nothing but its tpm mr, has
/// channels only to `key` pds and is their callee (never pp on its own
/// end); a `key` pd has at most one channel with pp on its own end, and it
/// leads to a `tpm` pd (a pp end towards anything else is the key
/// exemption's finding).
fn check_tpm(system: &System, policy: &Policy, tainted: &BTreeSet<String>, findings: &mut Vec<Finding>) {
    let tpms: Vec<&str> = policy
        .mrs
        .iter()
        .filter(|(_, mp)| matches!(mp, MrPolicy::Device { tpm: true, .. }))
        .map(|(name, _)| name.as_str())
        .collect();
    if tpms.len() > 1 {
        findings.push(Finding::new(
            LawId::L5,
            format!("{} tpm mrs are declared ({}); the TIS page is the only one", tpms.len(), tpms.join(", ")),
        ));
    }
    for (name, mp) in &policy.mrs {
        let MrPolicy::Device { owner, phys_addr, size, tpm, .. } = mp else { continue };
        if *tpm && (*phys_addr, *size) != TIS_PAGE {
            findings.push(Finding::new(
                LawId::L5,
                format!(
                    "tpm mr '{name}' is pinned at phys_addr={phys_addr:#x}/size={size:#x}, not the TIS page \
                     (phys_addr={:#x}/size={:#x})",
                    TIS_PAGE.0, TIS_PAGE.1
                ),
            ));
        }
        if !*tpm && policy.role(owner) == Some(Role::Tpm) {
            findings.push(Finding::new(
                LawId::L5,
                format!("tpm pd '{owner}' owns device mr '{name}', which is not the TIS mr"),
            ));
        }
    }

    for pd in system.pds.iter().filter(|pd| policy.role(&pd.name) == Some(Role::Tpm)) {
        if tainted.contains(&pd.name) {
            findings.push(Finding::new(LawId::L1, format!("tpm pd '{}' is tainted", pd.name)));
        }
        for m in mrs_mapped_by(pd) {
            if !matches!(policy.mrs.get(m.mr.as_str()), Some(MrPolicy::Device { tpm: true, owner, .. }) if owner == &pd.name) {
                findings.push(Finding::new(
                    LawId::L1,
                    format!("tpm pd '{}' maps mr '{}', not just its TIS mr", pd.name, m.mr),
                ));
            }
        }
    }

    let mut key_pp: BTreeMap<(&str, bool), usize> = BTreeMap::new();
    for channel in &system.channels {
        let [a, b] = &channel.ends;
        for (end, peer) in [(a, b), (b, a)] {
            let peer_role = policy.role(&peer.pd);
            match policy.role(&end.pd) {
                Some(Role::Tpm) if peer_role != Some(Role::Key) => findings.push(Finding::new(
                    LawId::L1,
                    format!("tpm pd '{}' has a channel to '{}', which is not a key pd", end.pd, peer.pd),
                )),
                Some(Role::Tpm) if end.pp => findings.push(Finding::new(
                    LawId::L1,
                    format!("tpm pd '{}' has pp=true on its channel to '{}'; it is a callee only", end.pd, peer.pd),
                )),
                Some(Role::Key) if end.pp => {
                    *key_pp.entry((end.pd.as_str(), peer_role == Some(Role::Rng))).or_default() += 1
                }
                _ => {}
            }
        }
    }
    for ((pd, to_rng), n) in key_pp {
        if n > 1 {
            let to = if to_rng { "an rng pd" } else { "a tpm pd" };
            findings.push(Finding::new(
                LawId::L1,
                format!(
                    "key pd '{pd}' has {n} channels with pp=true on its own end towards {to}; at most one to a tpm \
                     pd and one to an rng pd"
                ),
            ));
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

    let mut ratios = Vec::new();
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
        ratios.push((pd.budget_us, pd.period_us));
        if ratio > policy.ratio_cap {
            findings.push(Finding::new(
                LawId::L13,
                format!("tainted pd '{}' budget/period ratio {ratio:.3} exceeds the per-pd cap {}", pd.name, policy.ratio_cap),
            ));
        }
    }
    let ratio_sum = ratio_sum(&ratios);
    if ratio_sum > policy.ratio_sum_cap {
        findings.push(Finding::new(
            LawId::L13,
            format!("tainted pds' summed budget/period ratio {ratio_sum:.3} exceeds the sum cap {}", policy.ratio_sum_cap),
        ));
    }
}
