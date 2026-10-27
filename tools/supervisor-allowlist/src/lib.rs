//! The supervisor's allowlist (M7 plan C8, RM7-5): the supervisor holds
//! every child's TCB cap and the SMC cap, so what its source may name is a
//! fixed list, checked over the parsed crate rather than its text.
//!
//! - S1 `unsafe` (block, fn, impl, trait) or an `extern` block outside the
//!   reset module.
//! - S2 a path rooted in a `sel4*` crate, in a `use` item, an expression,
//!   a type or a macro name, that is not on the list: the handler and
//!   fault types anywhere ([`ANYWHERE`]), the SMC call's pieces in the
//!   reset module only ([`RESET_ONLY`]); a listed item's associated items
//!   are listed with it.
//! - S3 a TCB name (`tcb`, `tcb_*`, `Tcb`) outside the reset module.
//! - S4 a raw capability name (`from_bits`, `from_cptr`, `CPtr`) outside
//!   the reset module.
//! - S5 an SMC name (any identifier containing `smc`, any case) outside
//!   the reset module.
//! - S6 an integer literal shaped as an SMCCC fast-call function ID other
//!   than PSCI SYSTEM_RESET, anywhere.
//! - S7 no reset module, or no SYSTEM_RESET literal in it.
//! - S8 a file that does not parse.
//!
//! A best-effort tripwire: a macro's input tokens are not parsed (a macro
//! expanding to an unlisted path escapes it), and neither is code in a
//! dependency the crate already uses.

use std::fmt;

use proc_macro2::Span;
use syn::visit::{self, Visit};

/// The reset module's file name (crate-relative).
pub const RESET_MODULE: &str = "reset.rs";
/// PSCI SYSTEM_RESET, the one SMCCC function ID the crate may build.
pub const SYSTEM_RESET: u64 = 0x8400_0009;

/// `sel4*` paths any file may name.
pub const ANYWHERE: &[&str] = &[
    "sel4_microkit::Channel",
    "sel4_microkit::Child",
    "sel4_microkit::Handler",
    "sel4_microkit::Infallible",
    "sel4_microkit::MessageInfo",
    "sel4_microkit::memory_region_symbol",
    "sel4_microkit::protection_domain",
];
/// `sel4*` paths only the reset module may name.
pub const RESET_ONLY: &[&str] = &["sel4::CPtrBits", "sel4::sys::seL4_ARM_SMCContext", "sel4::with_ipc_buffer_mut"];

#[derive(Debug, PartialEq, Eq)]
pub struct Finding {
    pub id: &'static str,
    pub file: String,
    pub line: usize,
    pub what: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}:{}: {}", self.id, self.file, self.line, self.what)
    }
}

/// Every finding over the crate's files, given as (crate-relative path,
/// source).
pub fn check_crate(files: &[(String, String)]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut resets = 0;
    for (path, src) in files {
        let is_reset = path == RESET_MODULE;
        match syn::parse_file(src) {
            Ok(file) => {
                let mut v = Visitor { file: path, is_reset, out: &mut out, resets: 0 };
                v.visit_file(&file);
                if is_reset {
                    resets = v.resets;
                }
            }
            Err(e) => out.push(Finding {
                id: "S8",
                file: path.clone(),
                line: e.span().start().line,
                what: format!("does not parse: {e}"),
            }),
        }
    }
    if !files.iter().any(|(p, _)| p == RESET_MODULE) {
        out.push(Finding { id: "S7", file: RESET_MODULE.into(), line: 0, what: "no reset module".into() });
    } else if resets == 0 && !out.iter().any(|f| f.id == "S8" && f.file == RESET_MODULE) {
        out.push(Finding {
            id: "S7",
            file: RESET_MODULE.into(),
            line: 0,
            what: format!("no SYSTEM_RESET ({SYSTEM_RESET:#x}) literal"),
        });
    }
    out
}

struct Visitor<'a> {
    file: &'a str,
    is_reset: bool,
    out: &'a mut Vec<Finding>,
    resets: usize,
}

impl Visitor<'_> {
    fn push(&mut self, id: &'static str, span: Span, what: String) {
        self.out.push(Finding { id, file: self.file.into(), line: span.start().line, what });
    }

    fn outside_reset(&mut self, id: &'static str, span: Span, what: &str) {
        if !self.is_reset {
            self.push(id, span, format!("{what} outside the reset module"));
        }
    }

    fn sel4_path(&mut self, segments: &[String], span: Span) {
        let Some(root) = segments.first() else { return };
        if !root.starts_with("sel4") {
            return;
        }
        let path = segments.join("::");
        // A listed item's associated items (`Type::default`) come with it.
        let on = |list: &[&str]| list.iter().any(|l| path == *l || path.starts_with(&format!("{l}::")));
        let listed = on(ANYWHERE) || (self.is_reset && on(RESET_ONLY));
        if !listed {
            self.push("S2", span, format!("`{path}` is not on the supervisor's list"));
        }
    }

    fn use_tree(&mut self, prefix: &mut Vec<String>, tree: &syn::UseTree) {
        match tree {
            syn::UseTree::Path(p) => {
                prefix.push(p.ident.to_string());
                self.use_tree(prefix, &p.tree);
                prefix.pop();
            }
            syn::UseTree::Name(n) => self.use_leaf(prefix, n.ident.to_string(), n.ident.span()),
            syn::UseTree::Rename(r) => self.use_leaf(prefix, r.ident.to_string(), r.ident.span()),
            syn::UseTree::Glob(g) => self.use_leaf(prefix, "*".into(), g.star_token.span),
            syn::UseTree::Group(g) => {
                for t in &g.items {
                    self.use_tree(prefix, t);
                }
            }
        }
    }

    fn use_leaf(&mut self, prefix: &[String], leaf: String, span: Span) {
        let mut segments = prefix.to_vec();
        // `use a::b::{self}` names `a::b`.
        if leaf != "self" {
            segments.push(leaf);
        }
        self.sel4_path(&segments, span);
    }
}

impl<'ast> Visit<'ast> for Visitor<'_> {
    fn visit_item_use(&mut self, i: &'ast syn::ItemUse) {
        self.use_tree(&mut Vec::new(), &i.tree);
        visit::visit_item_use(self, i);
    }

    fn visit_path(&mut self, p: &'ast syn::Path) {
        let segments: Vec<String> = p.segments.iter().map(|s| s.ident.to_string()).collect();
        let span = p.segments.first().map_or_else(Span::call_site, |s| s.ident.span());
        self.sel4_path(&segments, span);
        visit::visit_path(self, p);
    }

    fn visit_ident(&mut self, i: &'ast proc_macro2::Ident) {
        let name = i.to_string();
        if name == "tcb" || name.starts_with("tcb_") || name == "Tcb" {
            self.outside_reset("S3", i.span(), &format!("TCB name `{name}`"));
        }
        if matches!(name.as_str(), "from_bits" | "from_cptr" | "CPtr") {
            self.outside_reset("S4", i.span(), &format!("raw capability name `{name}`"));
        }
        if name.to_ascii_lowercase().contains("smc") {
            self.outside_reset("S5", i.span(), &format!("SMC name `{name}`"));
        }
    }

    fn visit_expr_unsafe(&mut self, e: &'ast syn::ExprUnsafe) {
        self.outside_reset("S1", e.unsafe_token.span, "`unsafe` block");
        visit::visit_expr_unsafe(self, e);
    }

    fn visit_signature(&mut self, s: &'ast syn::Signature) {
        if let Some(u) = s.unsafety {
            self.outside_reset("S1", u.span, "`unsafe fn`");
        }
        visit::visit_signature(self, s);
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        if let Some(u) = i.unsafety {
            self.outside_reset("S1", u.span, "`unsafe impl`");
        }
        visit::visit_item_impl(self, i);
    }

    fn visit_item_trait(&mut self, i: &'ast syn::ItemTrait) {
        if let Some(u) = i.unsafety {
            self.outside_reset("S1", u.span, "`unsafe trait`");
        }
        visit::visit_item_trait(self, i);
    }

    fn visit_item_foreign_mod(&mut self, i: &'ast syn::ItemForeignMod) {
        self.outside_reset("S1", i.abi.extern_token.span, "`extern` block");
        visit::visit_item_foreign_mod(self, i);
    }

    fn visit_lit_int(&mut self, l: &'ast syn::LitInt) {
        let Ok(v) = l.base10_parse::<u64>() else { return };
        // SMCCC: bit 31 set (fast call) in a 32-bit function ID.
        if v <= u64::from(u32::MAX) && v & (1 << 31) != 0 {
            if v == SYSTEM_RESET {
                if self.is_reset {
                    self.resets += 1;
                }
            } else {
                self.push("S6", l.span(), format!("{v:#x} is an SMCCC function ID other than SYSTEM_RESET"));
            }
        }
    }
}

#[cfg(test)]
mod tests;
