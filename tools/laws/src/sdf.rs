//! Parses a Microkit System Description File (SDF) into a [`System`],
//! applying the same defaults the `microkit` tool applies (Microkit 2.3.1
//! manual, section 7), and collecting [`Finding`]s for anything the SDF
//! grammar allows but this checker's supported subset does not: unknown
//! elements, unknown attributes on any element (`<system>`,
//! `<memory_region>`, `<channel>`/`<end>` included, same as `<map>`/
//! `<protection_domain>`), `cspace`, child `protection_domain`,
//! `virtual_machine`, `smc`, `ioport`, `domains` — all L4, default deny.
//!
//! A document that is not even valid XML, or that violates the SDF grammar
//! itself (a required attribute missing, a malformed number, an invalid
//! `perms` string, `DOCTYPE`/entities/duplicate attributes), is a parse
//! error ([`SdfError`]) rather than a law violation: a parse error must
//! never be reported as a law violation (C7 interface).

use std::collections::HashSet;
use std::fmt;

use roxmltree::{Document, Node};

use crate::law::{Finding, LawId};
use crate::numbers::{parse_bool, parse_u64};

#[derive(Debug)]
pub struct SdfError(String);

impl fmt::Display for SdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "parse error: {}", self.0)
    }
}

fn err(msg: impl Into<String>) -> SdfError {
    SdfError(msg.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Perms {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}

impl Perms {
    const DEFAULT: Perms = Perms { r: true, w: true, x: false };

    fn parse(raw: &str) -> Result<Perms, SdfError> {
        let mut p = Perms::default();
        let mut seen = HashSet::new();
        for c in raw.chars() {
            if !seen.insert(c) {
                return Err(err(format!("duplicate permission '{c}' in perms '{raw}'")));
            }
            match c {
                'r' => p.r = true,
                'w' => p.w = true,
                'x' => p.x = true,
                other => return Err(err(format!("unknown permission '{other}' in perms '{raw}'"))),
            }
        }
        if p.w && !p.r {
            return Err(err(format!("write-only perms ('{raw}') are not supported")));
        }
        if !p.r && !p.w && !p.x {
            return Err(err("empty perms"));
        }
        Ok(p)
    }
}

/// The largest `stack_size` Microkit accepts.
pub const MAX_STACK_SIZE: u64 = 0x100_0000;

#[derive(Debug, Clone)]
pub struct Map {
    pub mr: String,
    pub vaddr: u64,
    pub perms: Perms,
}

#[derive(Debug, Clone)]
pub struct Setvar {
    pub symbol: String,
    pub region_paddr: String,
}

#[derive(Debug, Clone)]
pub struct Pd {
    pub name: String,
    pub priority: u8,
    pub budget_us: u64,
    pub budget_explicit: bool,
    pub period_us: u64,
    pub period_explicit: bool,
    pub passive: bool,
    /// `stack_size` if given; `None` means Microkit's default.
    pub stack_size: Option<u64>,
    pub program_image: String,
    pub path_for_symbols: Option<String>,
    pub maps: Vec<Map>,
    pub setvars: Vec<Setvar>,
    /// Hardware interrupt numbers from this pd's `<irq irq="...">` elements
    /// (manual §7.1); empty if it declares none.
    pub irqs: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub name: String,
    pub size: Option<u64>,
    pub page_size: u64,
    pub phys_addr: Option<u64>,
    pub prefill_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChannelEnd {
    pub pd: String,
    pub pp: bool,
    pub notify: bool,
}

#[derive(Debug, Clone)]
pub struct Channel {
    pub ends: [ChannelEnd; 2],
}

#[derive(Debug, Clone, Default)]
pub struct System {
    pub pds: Vec<Pd>,
    pub mrs: Vec<MemoryRegion>,
    pub channels: Vec<Channel>,
}

const DEFAULT_BUDGET_US: u64 = 1000;

/// Microkit channel `<end>` defaults (manual §7.6): `pp` defaults to
/// `false`, `notify` to `true`. Shared with `policy.rs`, which compares
/// these same effective values against its own per-end declarations (L4).
pub const DEFAULT_PP: bool = false;
pub const DEFAULT_NOTIFY: bool = true;

/// Page sizes Microkit supports on every architecture this checker covers
/// (manual §7.5.1), largest first.
const PAGE_SIZES: [u64; 2] = [0x200_000, 0x1000];

/// Mirrors the Microkit tool's own `page_size` default (manual §7.2): when
/// `page_size` is omitted, use the largest supported page size the region
/// is aligned to (both `size` and, if given, `phys_addr` must be a
/// multiple of the candidate). A `prefill_path`-only mr (`size` not yet
/// known here) defaults to the smallest page size, the conservative choice
/// available before the prefill file's length is known.
fn default_page_size(size: Option<u64>, phys_addr: Option<u64>) -> u64 {
    let Some(size) = size else { return 0x1000 };
    for p in PAGE_SIZES {
        if size % p == 0 && phys_addr.is_none_or(|a| a % p == 0) {
            return p;
        }
    }
    0x1000
}

/// Parses `xml` and returns the structural model plus any L4 (default-deny)
/// findings for SDF constructs outside this checker's supported subset.
/// `roxmltree::Document::parse` rejects `DOCTYPE`/entities on its own
/// (`ParsingOptions::default().allow_dtd == false`); duplicate attributes are
/// rejected explicitly below since relying on that alone would be fragile.
pub fn parse(xml: &str) -> Result<(System, Vec<Finding>), SdfError> {
    let doc = Document::parse(xml).map_err(|e| err(e.to_string()))?;
    let root = doc.root_element();
    if root.tag_name().name() != "system" {
        return Err(err(format!("root element must be <system>, found <{}>", root.tag_name().name())));
    }
    check_no_duplicate_attrs(root)?;

    let mut system = System::default();
    let mut findings = Vec::new();

    // <system> itself supports no attributes (manual §7); any present are a
    // default-deny finding (L4) like unknown attributes elsewhere, not a
    // parse error.
    check_unknown_attrs(root, &[], &mut findings);

    for child in root.children().filter(Node::is_element) {
        check_no_duplicate_attrs(child)?;
        match child.tag_name().name() {
            "protection_domain" => {
                let pd = parse_pd(child, &mut findings)?;
                system.pds.push(pd);
            }
            "memory_region" => system.mrs.push(parse_mr(child, &mut findings)?),
            "channel" => system.channels.push(parse_channel(child, &mut findings)?),
            other => findings.push(Finding::new(
                LawId::L4,
                format!("unsupported element <{other}> under <system>"),
            )),
        }
    }

    Ok((system, findings))
}

fn check_no_duplicate_attrs(node: Node) -> Result<(), SdfError> {
    let mut seen = HashSet::new();
    for a in node.attributes() {
        if !seen.insert(a.name()) {
            return Err(err(format!(
                "duplicate attribute '{}' on <{}>",
                a.name(),
                node.tag_name().name()
            )));
        }
    }
    Ok(())
}

/// Flags attributes on `node` that are not in `allowed` as L4 findings.
fn check_unknown_attrs(node: Node, allowed: &[&str], findings: &mut Vec<Finding>) {
    for a in node.attributes() {
        if !allowed.contains(&a.name()) {
            findings.push(Finding::new(
                LawId::L4,
                format!("unsupported attribute '{}' on <{}>", a.name(), node.tag_name().name()),
            ));
        }
    }
}

fn required_attr<'a>(node: Node<'a, 'a>, name: &str) -> Result<&'a str, SdfError> {
    node.attribute(name)
        .ok_or_else(|| err(format!("<{}> is missing required attribute '{name}'", node.tag_name().name())))
}

fn parse_pd(node: Node, findings: &mut Vec<Finding>) -> Result<Pd, SdfError> {
    const ALLOWED: &[&str] =
        &["name", "priority", "budget", "period", "passive", "stack_size", "cpu", "smc", "fpu"];
    check_unknown_attrs(node, ALLOWED, findings);

    let name = required_attr(node, "name")?.to_string();

    let priority = match node.attribute("priority") {
        Some(v) => {
            let n = parse_u64(v).map_err(|e| err(e.to_string()))?;
            u8::try_from(n).map_err(|_| err(format!("priority {n} out of range (0-254) on pd '{name}'")))?
        }
        None => 0,
    };
    if priority > 254 {
        return Err(err(format!("priority {priority} out of range (0-254) on pd '{name}'")));
    }

    let budget_explicit = node.attribute("budget").is_some();
    let budget_us = match node.attribute("budget") {
        Some(v) => parse_u64(v).map_err(|e| err(e.to_string()))?,
        None => DEFAULT_BUDGET_US,
    };
    let period_explicit = node.attribute("period").is_some();
    let period_us = match node.attribute("period") {
        Some(v) => parse_u64(v).map_err(|e| err(e.to_string()))?,
        None => budget_us,
    };

    let passive = match node.attribute("passive") {
        Some(v) => parse_bool(v).map_err(|e| err(e.to_string()))?,
        None => false,
    };

    let stack_size = match node.attribute("stack_size") {
        Some(v) => {
            let size = parse_u64(v).map_err(|e| err(e.to_string()))?;
            if !(0x1000..=MAX_STACK_SIZE).contains(&size) || size % 0x1000 != 0 {
                return Err(err(format!("stack_size {size:#x} on pd '{name}' is out of range or not page-aligned")));
            }
            Some(size)
        }
        None => None,
    };

    if let Some(v) = node.attribute("smc")
        && parse_bool(v).map_err(|e| err(e.to_string()))?
    {
        findings.push(Finding::new(LawId::L4, format!("smc is denied outright (pd '{name}')")));
    }
    // "fpu" is accepted and otherwise unchecked; it carries no law of its own.

    let mut program_image = None;
    let mut path_for_symbols = None;
    let mut maps = Vec::new();
    let mut setvars = Vec::new();
    let mut irqs = Vec::new();

    for child in node.children().filter(Node::is_element) {
        check_no_duplicate_attrs(child)?;
        match child.tag_name().name() {
            "program_image" => {
                if program_image.is_some() {
                    return Err(err(format!("pd '{name}' has more than one <program_image>")));
                }
                check_unknown_attrs(child, &["path", "path_for_symbols"], findings);
                program_image = Some(required_attr(child, "path")?.to_string());
                path_for_symbols = child.attribute("path_for_symbols").map(str::to_string);
            }
            "map" => {
                check_unknown_attrs(
                    child,
                    &["mr", "vaddr", "perms", "cached", "setvar_vaddr", "setvar_size", "setvar_prefill_size"],
                    findings,
                );
                let mr = required_attr(child, "mr")?.to_string();
                let vaddr = parse_u64(required_attr(child, "vaddr")?).map_err(|e| err(e.to_string()))?;
                let perms = match child.attribute("perms") {
                    Some(v) => Perms::parse(v)?,
                    None => Perms::DEFAULT,
                };
                if let Some(v) = child.attribute("cached") {
                    parse_bool(v).map_err(|e| err(e.to_string()))?;
                }
                maps.push(Map { mr, vaddr, perms });
            }
            "setvar" => {
                check_unknown_attrs(child, &["symbol", "region_paddr"], findings);
                let symbol = required_attr(child, "symbol")?.to_string();
                let region_paddr = required_attr(child, "region_paddr")?.to_string();
                setvars.push(Setvar { symbol, region_paddr });
            }
            "irq" => {
                check_unknown_attrs(child, &["irq", "id", "trigger", "setvar_id"], findings);
                let irq = parse_u64(required_attr(child, "irq")?).map_err(|e| err(e.to_string()))?;
                let id = parse_u64(required_attr(child, "id")?).map_err(|e| err(e.to_string()))?;
                if id >= 63 {
                    return Err(err(format!("irq id {id} out of range (0-62) on pd '{name}'")));
                }
                irqs.push(irq);
            }
            other => findings.push(Finding::new(
                LawId::L4,
                format!("unsupported element <{other}> on pd '{name}'"),
            )),
        }
    }

    let program_image = program_image
        .ok_or_else(|| err(format!("pd '{name}' is missing required <program_image>")))?;

    Ok(Pd {
        name,
        priority,
        budget_us,
        budget_explicit,
        period_us,
        period_explicit,
        passive,
        stack_size,
        program_image,
        path_for_symbols,
        maps,
        setvars,
        irqs,
    })
}

fn parse_mr(node: Node, findings: &mut Vec<Finding>) -> Result<MemoryRegion, SdfError> {
    const ALLOWED: &[&str] = &["name", "size", "page_size", "phys_addr", "prefill_path", "prefill_bootinfo"];
    // Unknown attributes are a default-deny (L4) finding, same as on <map>
    // and <protection_domain>: an undescribed-but-structurally-valid
    // attribute is exactly what L4 exists to catch, not a parse error.
    check_unknown_attrs(node, ALLOWED, findings);

    let name = required_attr(node, "name")?.to_string();
    let prefill_path = node.attribute("prefill_path").map(str::to_string);

    let size = match node.attribute("size") {
        Some(v) => Some(parse_u64(v).map_err(|e| err(e.to_string()))?),
        None => {
            if prefill_path.is_none() {
                return Err(err(format!("memory_region '{name}' needs 'size' (no prefill_path to infer it)")));
            }
            None
        }
    };

    let phys_addr = match node.attribute("phys_addr") {
        Some(v) => Some(parse_u64(v).map_err(|e| err(e.to_string()))?),
        None => None,
    };

    let page_size = match node.attribute("page_size") {
        Some(v) => parse_u64(v).map_err(|e| err(e.to_string()))?,
        None => default_page_size(size, phys_addr),
    };

    if node.attribute("prefill_bootinfo").is_some() {
        // Accepted syntactically; not used by any M0/M1 PD and not checked
        // further (no law constrains it yet).
    }

    Ok(MemoryRegion { name, size, page_size, phys_addr, prefill_path })
}

fn parse_channel(node: Node, findings: &mut Vec<Finding>) -> Result<Channel, SdfError> {
    // <channel> itself takes no attributes (manual §7.6); any present are
    // an L4 finding, not a parse error.
    check_unknown_attrs(node, &[], findings);
    let mut ends = Vec::new();
    for child in node.children().filter(Node::is_element) {
        check_no_duplicate_attrs(child)?;
        if child.tag_name().name() != "end" {
            return Err(err(format!("<channel> may only contain <end>, found <{}>", child.tag_name().name())));
        }
        check_unknown_attrs(child, &["pd", "id", "pp", "notify", "setvar_id"], findings);
        let pd = required_attr(child, "pd")?.to_string();
        let id = parse_u64(required_attr(child, "id")?).map_err(|e| err(e.to_string()))?;
        if id >= 63 {
            return Err(err(format!("channel end id {id} out of range (0-62) for pd '{pd}'")));
        }
        let pp = match child.attribute("pp") {
            Some(v) => parse_bool(v).map_err(|e| err(e.to_string()))?,
            None => DEFAULT_PP,
        };
        let notify = match child.attribute("notify") {
            Some(v) => parse_bool(v).map_err(|e| err(e.to_string()))?,
            None => DEFAULT_NOTIFY,
        };
        ends.push(ChannelEnd { pd, pp, notify });
    }
    let ends: [ChannelEnd; 2] =
        ends.try_into().map_err(|_| err("<channel> must have exactly two <end> children"))?;
    Ok(Channel { ends })
}
