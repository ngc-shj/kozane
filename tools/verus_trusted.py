#!/usr/bin/env python3
"""Source checks behind the Verus gate (M4 plan C1) and check-pins P12.

One scanner, shared by both callers, so the two never disagree on what a
trusted construct is, or on how many there are (R2: T-N11; R48):

- trusted constructs, anywhere in a crate's sources, each bound to the
  item it covers (an attribute: the next item; a call: the enclosing fn):
  - a `verifier::<x>`/`verifier(<x>)` token for one of TRUSTED in an
    attribute's token stream (so `cfg_attr(...)` spellings count), and a
    hand-written `verus::internal(..)`;
  - the `assume_specification` item;
  - `assume(`, `assume_(`, `admit(`, `assume_new(` and
    `assume_new_fallback(` calls, path-qualified or not, except Kani's own
    `kani::assume(`;
  - a `cfg`/`cfg_attr`/`cfg!` naming a `verus_*` cfg, except on a `use`
    item: Verus builds with `verus_keep_ghost` and the PDs without, so a
    cfg split lets the shipped body differ from the verified one;
  - `#[path = ..]` and `include!`, which bring in code this scan does not
    read (`include_bytes!`/`include_str!` are data);
- `verus!` block spans, with any delimiter;
- every fn definition, qualified by its `impl` type (`Type::fn`), inside or
  outside `verus!`, with its `ensures` conjuncts;
- required functions (`Type::fn`, a bare name for a free fn, or `*::f` for
  every fn named `f`): every definition of each must be inside `verus!`
  with an `ensures`.

The allowlist is compared as a multiset of (file, construct, item), so a
second construct in an allowlisted file is not covered by the first.

Usage:
  verus_trusted.py check <crate> <crate-dir> <trusted.toml> <required.toml>
      Prints `VERUS-ENSURES <n>` and exits 1 on any mismatch.
  verus_trusted.py scan <path>...
      Prints each trusted construct found as `file:line: construct item`.
"""

import collections
import pathlib
import re
import sys
import tomllib

TRUSTED = (
    "external_body",
    "external_fn_specification",
    "external_type_specification",
    "external_trait_specification",
    "external_trait_extension",
    "external",
    "assume_specification",
    "assume_termination",
    "exec_allows_no_decreases_clause",
)
# A TRUSTED name anywhere in an attribute that names `verifier` or
# `verus_verify` (the attribute macro that rewrites to `verifier::<x>`), or
# a macro metavariable in that position.
ATTR_TRUSTED = re.compile(r"\b(" + "|".join(TRUSTED) + r")\b")
ATTR_VERUS = re.compile(r"\b(verifier|verus_verify)\b")
ATTR_META = re.compile(r"\bverifier\s*(?:::|\()\s*\$")
INTERNAL_TOKEN = re.compile(r"\bverus\s*::\s*internal\b")
# The builtins that assume, as identifiers wherever they occur (a call, a
# `use .. as`, an ident handed to a macro): `admit`, `assume_` (what
# `assume(` expands to), `assume_new(_fallback)`. `assume(` itself is
# flagged everywhere except Kani's own `kani::assume(` outside verus!.
ASSUME_IDENT = re.compile(r"(?<![A-Za-z0-9_])(admit|assume_|assume_new|assume_new_fallback)(?![A-Za-z0-9_])")
ASSUME_CALL = re.compile(r"(?<![A-Za-z0-9_.])((?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*)assume\s*\(")
# Something else named `kani` would make `kani::assume(` mean anything.
KANI_SHADOW = re.compile(r"\bmod\s+kani\b|\bas\s+kani\b")
# ... and something else named `verus`, which the macro-invocation rule and
# the verus! block detection trust.
VERUS_SHADOW = re.compile(r"\bmacro_rules\s*!\s*(?:r#)?verus\b|\bmacro\s+(?:r#)?verus\b|\bas\s+(?:r#)?verus\b")
ITEM_TOKEN = re.compile(r"(?<![A-Za-z0-9_])assume_specification\b")
# cfg predicates: only these names are allowed (the Verus build and the PD
# build agree on them); anything else (`verus_*`, `debug_assertions`,
# `target_*`, features) can make the shipped body differ from the verified.
CFG_ALLOWED = {"test", "kani", "not", "all", "any"}
CFG_ATTR = re.compile(r"\s*(cfg|cfg_attr)\s*\(")
# `#`, `!` and `[` are separate tokens to rustc, with whitespace (or a
# comment, blanked to spaces) allowed between them.
CFG_MACRO = re.compile(r"\bcfg\s*!\s*[\(\[\{]")
# Outside an attribute, `cfg`, `cfg_attr` and `include` may appear only as
# an allowed `cfg!(..)`: any other use (a `use core::cfg as k` alias, an
# `include ! (..)`) is flagged.
CFG_OR_INCLUDE = re.compile(r"\b(cfg_attr|cfg|include)\b")
# Build-environment reads, as identifiers (`use core::option_env as oe`,
# `m!(env)`) as much as calls.
ENV_IDENT = re.compile(r"\b(option_env|env)\b")
# The one exempt cfg: an outer `#[cfg(verus_keep_ghost)]` on a `use vstd::..`
# (the lemma imports the verified code needs).
# ... importing only proof lemmas (`lemma_*`/`group_*`, which exec code
# cannot call), with no `as` and no glob, so the two builds cannot resolve
# one name to two functions.
VSTD_USE = re.compile(r"\s*use\s+vstd::(?:\w+::)*(?:(?:lemma|group)_\w+|\{\s*(?:lemma|group)_\w+"
                      r"(?:\s*,\s*(?:lemma|group)_\w+)*\s*,?\s*\})\s*;")
CFG_ANY = re.compile(r"\bcfg(_attr)?\s*\(")
ITEM_HEAD = re.compile(r"\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:(?:const|unsafe|async|default|open|closed|spec|proof|exec"
                       r"|tracked|ghost|extern(?:\s+\"[^\"]*\")?)\s+)*")
VERUS_VERIFY = re.compile(r"\bverus_verify\b")
EXTERNAL = re.compile(r"\bexternal\b")
PATH_ATTR = re.compile(r"\bpath\s*=")
# `include_bytes!`/`include_str!` bring in data, not code.
INCLUDE = re.compile(r"\binclude\s*!\s*[\(\[\{]")
VERUS_BLOCK = re.compile(r"\bverus\s*!\s*([\{\(\[])")
CLOSER = {"{": "}", "(": ")", "[": "]"}
RAW_STRING = re.compile(r"(?<![A-Za-z0-9_])[bc]?r(#*)\"")
# rustc skips `_` inside `\u{..}`.
CHAR_LITERAL = re.compile(r"b?'(?:\\u\{[0-9a-fA-F_]+\}|\\x[0-9a-fA-F]{2}|\\.|[^\\'\n])'")
FN_DEF = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")
ITEM = re.compile(r"\b(fn|struct|enum|union|trait|type|const|static|mod|use|impl|assume_specification)\b"
                  r"(?:\s*<[^>]*>)?\s*([A-Za-z_][A-Za-z0-9_]*)?")
IMPL_START = re.compile(r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?impl\b")


# Left where a comment or literal never closes; trusted_in refuses it, so a
# stray quote cannot blank the rest of a file from the scan.
UNTERMINATED = "UNTERM"


def strip_comments(text: str) -> str:
    """Comments and string literals replaced by spaces, newlines kept, so
    offsets and line numbers are unchanged. Block comments nest, as rustc's
    do; strings take the `b`/`c` prefixes and raw strings `r`/`br`/`cr` with
    any number of `#`. An unterminated one becomes UNTERMINATED."""
    out = []
    i, n = 0, len(text)
    # rustc drops a first line `#!..` (after an optional BOM) that does not
    # open an inner attribute: blank it too, or a quote in it would desync.
    start = 1 if text.startswith("\ufeff") else 0
    if text.startswith("#!", start):
        rest = re.sub(r"/\*.*?\*/|//[^\n]*", lambda m: " " * len(m.group(0)), text[start + 2:], flags=re.S)
        if not rest.lstrip().startswith("["):
            j = text.find("\n")
            j = n if j < 0 else j
            out.append(" " * j)
            i = j

    def blank(a: int, b: int, closed: bool):
        piece = re.sub(r"[^\n]", " ", text[a:b])
        if not closed:
            piece = UNTERMINATED + piece[len(UNTERMINATED):] if len(piece) >= len(UNTERMINATED) else UNTERMINATED
        out.append(piece)

    def ident_before(k: int) -> bool:
        return k > 0 and re.match(r"[A-Za-z0-9_]", text[k - 1]) is not None

    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j, depth == 0)
            i = j
        elif (m := RAW_STRING.match(text, i)) and not ident_before(i):
            close = '"' + m.group(1)
            j = text.find(close, m.end())
            blank(i, n if j < 0 else j + len(close), j >= 0)
            i = n if j < 0 else j + len(close)
        elif (m := CHAR_LITERAL.match(text, i)) and not ident_before(i):
            out.append(" " * (m.end() - i))
            i = m.end()
        elif text[i] == '"' or (text[i] in "bc" and text.startswith('"', i + 1) and not ident_before(i)):
            j = i + (2 if text[i] != '"' else 1)
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            blank(i, min(j + 1, n), j < n)
            i = min(j + 1, n)
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def attributes(code: str):
    """(offset, end, token stream, inner) of every `#[...]` / `#![...]`
    attribute."""
    for m in re.finditer(r"#\s*(!?)\s*\[", code):
        depth, j = 1, m.end()
        while j < len(code) and depth:
            depth += {"[": 1, "]": -1}.get(code[j], 0)
            j += 1
        yield m.start(), j, code[m.end():j - 1], bool(m.group(1))


def line_of(code: str, offset: int) -> int:
    return code.count("\n", 0, offset) + 1


def balanced(code: str, open_at: int) -> int:
    """The offset just past the bracket matching the one at `open_at`."""
    opener = code[open_at]
    closer = CLOSER[opener]
    depth, j = 0, open_at
    while j < len(code):
        if code[j] == opener:
            depth += 1
        elif code[j] == closer:
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return len(code)


def verus_blocks(code: str):
    """(start, end) offsets of each `verus!` body, whatever its delimiter."""
    for m in VERUS_BLOCK.finditer(code):
        end = balanced(code, m.end() - 1)
        yield m.end(), end - 1


def impl_spans(code: str):
    """(start, end, type name) of each `impl` block: the last path segment of
    the implementing type (the one after `for` in a trait impl)."""
    out = []
    for m in IMPL_START.finditer(code):
        j, angle, paren = m.end(), 0, 0
        while j < len(code):
            c = code[j]
            if c == "<":
                angle += 1
            elif c == ">" and code[j - 1] != "-":
                angle -= 1
            elif c in "([":
                paren += 1
            elif c in ")]":
                paren -= 1
            elif c in "{;" and angle <= 0 and paren <= 0:
                break
            j += 1
        if j >= len(code) or code[j] != "{":
            continue
        header = re.split(r"\bwhere\b", code[m.end():j])[0].strip()
        if header.startswith("<"):
            depth, k = 0, 0
            for k, c in enumerate(header):
                depth += {"<": 1, ">": -1}.get(c, 0)
                if depth == 0:
                    break
            header = header[k + 1:].strip()
        target = re.split(r"\bfor\b", header)[-1].strip()
        target = re.sub(r"^[&\s]*(?:mut\s+)?|\s*<.*$", "", target, flags=re.S)
        out.append((j, balanced(code, j), target.split("::")[-1].strip()))
    return out


def spec_header(code: str, start: int):
    """The text between a fn's signature start and its body's `{`, at paren
    and bracket depth 0."""
    depth, j = 0, start
    while j < len(code):
        c = code[j]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "{" and depth == 0:
            return code[start:j]
        elif c == ";" and depth == 0:
            return code[start:j]
        j += 1
    return code[start:]


def ensures_conjuncts(header: str) -> int:
    m = re.search(r"\bensures\b", header)
    if not m:
        return 0
    rest = header[m.end():]
    stop = re.search(r"\b(decreases|returns|opens_invariants|no_unwind)\b", rest)
    rest = rest[:stop.start()] if stop else rest
    depth, parts, cur = 0, 0, ""
    for c in rest:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            parts += bool(cur.strip())
            cur = ""
        else:
            cur += c
    return parts + bool(cur.strip())


def definitions(code: str):
    """(qualified name, offset, inside verus!, ensures conjuncts, body end)
    of every fn definition."""
    blocks = list(verus_blocks(code))
    impls = impl_spans(code)
    out = []
    for m in FN_DEF.finditer(code):
        at = m.start()
        owner = [t for s, e, t in impls if s < at < e]
        name = f"{owner[-1]}::{m.group(1)}" if owner else m.group(1)
        inside = any(s <= at < e for s, e in blocks)
        header = spec_header(code, at)
        body = at + len(header)
        stop = balanced(code, body) if body < len(code) and code[body] == "{" else body
        out.append((name, at, inside, ensures_conjuncts(header) if inside else 0, stop))
    return out


def item_after(code: str, offset: int, impls) -> str:
    """The item an outer attribute ending at `offset` decorates: its name
    (`Type::fn` for a method), `use`, or `impl <Type>`. Later attributes
    and the qualifiers before the item keyword are skipped; anything else
    is "?" (still counted, so it cannot hide a construct)."""
    at = offset
    while True:
        m = re.match(r"\s*#\s*!?\s*\[", code[at:])
        if not m:
            break
        at = balanced(code, at + m.end() - 1)
    at = ITEM_HEAD.match(code, at).end()
    m = ITEM.match(code, at)
    if not m:
        return "?"
    if m.group(1) == "impl":
        owner = [t for s, e, t in impls if s > m.start()]
        return f"impl {owner[0]}" if owner else "impl"
    if m.group(1) == "use":
        return "use"
    name = m.group(2) or m.group(1)
    owner = [t for s, e, t in impls if s < m.start() < e]
    return f"{owner[-1]}::{name}" if owner and m.group(1) == "fn" else name


def enclosing_fn(defs, offset: int) -> str:
    """The innermost fn whose definition spans `offset`."""
    spans = [d for d in defs if d[1] <= offset < d[4]]
    return spans[-1][0] if spans else "<file>"


def cfg_names(predicate: str) -> set:
    return set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", predicate)) - CFG_ALLOWED


def cfg_problems(body: str) -> set:
    """The disallowed names in every cfg predicate in an attribute body:
    each `cfg(..)` and each `cfg_attr(<predicate>, ..)` at any depth,
    since cfg_attr can produce a cfg. An unbalanced one is unparsable."""
    names = set()
    for m in CFG_ANY.finditer(body):
        close = balanced(body, m.end() - 1)
        if close > len(body) or body[close - 1] != ")":
            names.add("<unparsable>")
            continue
        inner = body[m.end():close - 1]
        if m.group(1):
            depth, k = 0, len(inner)
            for k, c in enumerate(inner):
                depth += {"(": 1, ")": -1}.get(c, 0)
                if c == "," and depth == 0:
                    break
            inner = inner[:k]
        names |= cfg_names(inner)
    return names


def trusted_in(path: pathlib.Path, test_only: bool = False):
    """(line, construct, item) of every trusted construct in `path`, one per
    occurrence (two on one line are two). `test_only`: the file is reached
    only through a `#[cfg(test)]` module declaration."""
    code = strip_comments(path.read_text())
    defs = definitions(code)
    impls = impl_spans(code)
    blocks = list(verus_blocks(code))
    found = {}
    spans = []

    def add(offset: int, construct: str, item: str):
        found[(offset, construct)] = (line_of(code, offset), construct, item)

    for off, end, body, inner in attributes(code):
        item = enclosing_fn(defs, off) if inner else item_after(code, end, impls)
        spans.append((off, end, item))
        if body.lstrip().startswith("$"):
            add(off, "attribute from a macro metavariable", item)
        if ATTR_META.search(body):
            add(off, "verifier::$meta", item)
        if INTERNAL_TOKEN.search(body):
            add(off, "verus::internal", item)
        for t in EXTERNAL.finditer(body):
            add(off + 2 + int(inner) + t.start(), "external", item)
        names = cfg_problems(body)
        exempt = (not inner and re.fullmatch(r"\s*cfg\s*\(\s*verus_keep_ghost\s*\)\s*", body)
                  and VSTD_USE.match(code, end))
        if names and not exempt:
            add(off, f"cfg({' '.join(sorted(names))})", item)
        if PATH_ATTR.search(body):
            add(off, "path", item)

    def owner_of(offset: int) -> str:
        for a, b, item in spans:
            if a <= offset < b:
                return item
        return enclosing_fn(defs, offset)

    # Every TRUSTED name, as an identifier wherever it occurs: in an
    # attribute, a macro argument (`m!(verifier::external_body; ..)`), or a
    # `use` alias. `external` alone is an ordinary word and counts only
    # inside an attribute (above).
    for m in ATTR_TRUSTED.finditer(code):
        if m.group(1) != "external":
            add(m.start(), m.group(1), owner_of(m.start()))
    for m in VERUS_VERIFY.finditer(code):
        if not any(a <= m.start() < b for a, b, _ in spans):
            add(m.start(), "verus_verify outside an attribute", owner_of(m.start()))
    for m in re.finditer(rf"\b{UNTERMINATED}\b", code):
        add(m.start(), "unterminated literal or comment", owner_of(m.start()))
    macros = set()
    for m in CFG_MACRO.finditer(code):
        macros.add(m.start())
        close = balanced(code, m.end() - 1)
        names = cfg_names(code[m.end():close - 1]) if close <= len(code) else {"<unparsable>"}
        if names:
            add(m.start(), f"cfg({' '.join(sorted(names))})", enclosing_fn(defs, m.start()))
    # A trusted construct inside a macro definition is counted once but
    # expands as often as the macro is invoked: refuse it there (N3).
    bodies = []
    for m in re.finditer(r"\bmacro_rules\s*!\s*(?:r#)?[A-Za-z_][A-Za-z0-9_]*\s*([\{\(\[])|\bmacro\s+(?:r#)?[A-Za-z_][A-Za-z0-9_]*", code):
        open_at = m.start(1) if m.group(1) else code.find("{", m.end())
        if open_at >= 0:
            bodies.append((open_at, balanced(code, open_at)))
    for (offset, construct), (line, _, item) in list(found.items()):
        if construct in TRUSTED or construct in ("assume_specification", "verifier::$meta"):
            if any(a <= offset < b for a, b in bodies):
                add(offset, f"{construct} inside a macro definition", item)
    # Build-environment reads split the two builds as a cfg does (Cargo sets
    # CARGO_PRIMARY_PACKAGE under `-p`, not for a PD's dependency): refused
    # outside test-only files.
    for m in ENV_IDENT.finditer(code):
        if not test_only:
            add(m.start(), f"{m.group(1)} outside test code", owner_of(m.start()))
    # A verified library has no use for a shebang; rustc's rule for one
    # (nested comments, doc comments) is not worth mirroring.
    if re.match(r"\ufeff?#!(?!\s*\[)", path.read_text()):
        add(0, "shebang line", "<file>")
    # A trusted construct may sit in a verus! body, not in another macro's
    # arguments, which the macro may repeat.
    for m in re.finditer(r"\b((?:r#)?[A-Za-z_][A-Za-z0-9_]*)\s*!\s*([\(\[\{])", code):
        if m.group(1) in ("verus", "macro_rules"):
            continue
        a, b = m.end() - 1, balanced(code, m.end() - 1)
        for (offset, construct), (line, _, item) in list(found.items()):
            if a <= offset < b and (construct in TRUSTED or construct == "assume_specification"):
                add(offset, f"{construct} inside a {m.group(1)}! invocation", item)
    for m in CFG_OR_INCLUDE.finditer(code):
        if any(a <= m.start() < b for a, b, _ in spans) or m.start() in macros:
            continue
        add(m.start(), f"{m.group(1)} outside an attribute", owner_of(m.start()))
    for m in ASSUME_IDENT.finditer(code):
        add(m.start(), m.group(1) + "(", owner_of(m.start()))
    for m in ASSUME_CALL.finditer(code):
        at = m.start()
        inside = any(s <= at < e for s, e in blocks)
        if re.sub(r"\s", "", m.group(1)) == "kani::" and not inside:
            continue
        add(at, "assume(", owner_of(at))
    for m in KANI_SHADOW.finditer(code):
        add(m.start(), "kani shadowed", owner_of(m.start()))
    for m in VERUS_SHADOW.finditer(code):
        add(m.start(), "verus shadowed", owner_of(m.start()))
    for m in ITEM_TOKEN.finditer(code):
        add(m.start(), "assume_specification", item_after(code, m.end(), impls))
    for m in INCLUDE.finditer(code):
        add(m.start(), "include!", owner_of(m.start()))
    return sorted(found.values())


def manifest_problems(crate_dir: pathlib.Path) -> list:
    """What would make cargo compile sources this scan does not read: a
    `[lib] path`, a build script."""
    out = []
    path = crate_dir / "Cargo.toml"
    try:
        doc = tomllib.loads(path.read_text())
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        return [f"Cargo.toml: unreadable ({e}); cannot tell what cargo compiles"]
    if "path" in doc.get("lib", {}):
        out.append("Cargo.toml: [lib] path moves the compiled sources out of src/")
    if "build" in doc.get("package", {}) or (crate_dir / "build.rs").exists():
        out.append("Cargo.toml: a build script can emit cfgs and code the scan does not read")
    allowed = [(crate_dir / d).resolve() for d in ("src", "tests", "examples", "benches")]
    for table in ("bin", "example", "test", "bench"):
        for t in doc.get(table, []):
            if "path" not in t:
                continue
            target = (crate_dir / str(t["path"])).resolve()
            if not any(target.is_relative_to(d) for d in allowed):
                out.append(f"Cargo.toml: [[{table}]] path {t['path']} is outside the crate's source dirs")
    return out


def rs_files(crate_dir: pathlib.Path):
    return sorted(p for p in (crate_dir / "src").rglob("*.rs"))


def test_only_files(crate_dir: pathlib.Path) -> set:
    """The files of modules the crate root declares only under
    `#[cfg(test)]` (`#[cfg(test)] mod tests;`)."""
    out = set()
    for root in ("src/lib.rs", "src/main.rs"):
        path = crate_dir / root
        if not path.is_file():
            continue
        code = strip_comments(path.read_text())
        tested = set(re.findall(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*mod\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*;", code))
        every = re.findall(r"\bmod\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*;", code)
        for name in tested:
            # Only when every declaration of it is the cfg(test) one: a
            # `#[cfg(not(test))] mod tests;` beside it would ship the file.
            if every.count(name) != 1:
                continue
            for cand in (crate_dir / "src" / f"{name}.rs", crate_dir / "src" / name / "mod.rs"):
                if cand.is_file():
                    out.add(cand)
    return out


def trusted_mismatches(crate: str, crate_dir: pathlib.Path, entries: list) -> list:
    """The one comparison both callers make: the crate's trusted constructs,
    as a multiset of (file, construct, item), against its allowlist entries
    (each `count` times, default 1). Messages start with `<file>:<line>:` or
    `<file>:`."""
    errors = []
    allowed = collections.Counter()
    for e in entries:
        if e.get("crate") != crate:
            continue
        if not e.get("deviation") or not e.get("item"):
            errors.append(f"{e.get('file')}: allowlist entry {e} needs an item and a deviation-log reference")
            continue
        count = e.get("count", 1)
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            errors.append(f"{e.get('file')}: allowlist entry {e} has count {count!r}; it must be an integer >= 1")
            continue
        allowed[(e["file"], e["construct"], e["item"])] += count
    errors += manifest_problems(crate_dir)
    seen = collections.Counter()
    lines = collections.defaultdict(list)
    blocks = 0
    tests = test_only_files(crate_dir)
    for f in rs_files(crate_dir):
        rel = str(f.relative_to(crate_dir))
        blocks += len(list(verus_blocks(strip_comments(f.read_text()))))
        for line, construct, item in trusted_in(f, f in tests):
            seen[(rel, construct, item)] += 1
            lines[(rel, construct, item)].append(line)
    if blocks == 0:
        errors.append(f"src: no verus! block; nothing in {crate} is verified")
    for key in sorted(set(seen) | set(allowed)):
        rel, construct, item = key
        if seen[key] > allowed[key]:
            for line in lines[key][allowed[key]:]:
                errors.append(f"{rel}:{line}: trusted construct `{construct}` on `{item}` not in the allowlist")
        elif seen[key] < allowed[key]:
            errors.append(f"{rel}: allowlisted `{construct}` on `{item}` found {seen[key]} of "
                          f"{allowed[key]} times (stale entry)")
    return errors


def check(crate: str, crate_dir: pathlib.Path, trusted_toml: pathlib.Path, required_toml: pathlib.Path) -> int:
    entries = tomllib.loads(trusted_toml.read_text()).get("trusted", [])
    errors = trusted_mismatches(crate, crate_dir, entries)
    defs = []
    for f in rs_files(crate_dir):
        rel = str(f.relative_to(crate_dir))
        code = strip_comments(f.read_text())
        defs += [(rel, line_of(code, d[1]), *d[:4]) for d in definitions(code)]
    ensures = sum(d[5] for d in defs)
    required = tomllib.loads(required_toml.read_text()).get("crates", {}).get(crate, {}).get("functions", [])
    if not required:
        errors.append(f"no required functions listed for {crate}")
    for name in required:
        # `*::f`: every definition of a method or free fn named `f`, so a new
        # one joins the requirement without a list edit (R42).
        if name.startswith("*::"):
            sites = [d for d in defs if d[2].split("::")[-1] == name[3:]]
        else:
            sites = [d for d in defs if d[2] == name]
        if not sites:
            errors.append(f"required function `{name}` is not defined (a method is listed as `Type::fn`)")
        for rel, line, _, _, inside, n in sites:
            if not inside:
                errors.append(f"{rel}:{line}: required function `{name}` is not defined inside verus!")
            elif n == 0:
                errors.append(f"{rel}:{line}: required function `{name}` has no ensures")
    for e in errors:
        print(f"verus-trusted: {e}", file=sys.stderr)
    print(f"VERUS-ENSURES {ensures}")
    return 1 if errors or ensures == 0 else 0


def main(argv) -> int:
    if len(argv) >= 2 and argv[1] == "scan":
        hits = 0
        for p in argv[2:]:
            for line, construct, item in trusted_in(pathlib.Path(p)):
                print(f"{p}:{line}: {construct} {item}")
                hits += 1
        return 0 if hits == 0 else 1
    if len(argv) == 4 and argv[1] == "allowed":
        # How many constructs the policy allows the crate (the gate's
        # --no-cheating decision: 0 means the flag), by the same parse.
        entries = tomllib.loads(pathlib.Path(argv[3]).read_text()).get("trusted", [])
        print(sum(e.get("count", 1) for e in entries if e.get("crate") == argv[2]
                  and isinstance(e.get("count", 1), int) and e.get("count", 1) >= 1))
        return 0
    if len(argv) == 6 and argv[1] == "check":
        return check(argv[2], pathlib.Path(argv[3]), pathlib.Path(argv[4]), pathlib.Path(argv[5]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
