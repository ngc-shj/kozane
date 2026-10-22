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
ATTR_TOKEN = re.compile(r"verifier\s*(?:::\s*|\(\s*)(" + "|".join(TRUSTED) + r")\b")
INTERNAL_TOKEN = re.compile(r"\bverus\s*::\s*internal\b")
# `assume(` expands to `verus_builtin::assume_(`; `Tracked::assume_new()`
# makes a tracked value from nothing. A qualifier does not exempt a call,
# except Kani's own `kani::assume(` (its proof harnesses sit outside verus!).
CALL_TOKEN = re.compile(r"(?<![A-Za-z0-9_.])((?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*)"
                        r"(assume_new_fallback|assume_new|assume_|assume|admit)\s*\(")
ITEM_TOKEN = re.compile(r"(?<![A-Za-z0-9_])assume_specification\b")
VERUS_CFG = re.compile(r"\bverus_[A-Za-z0-9_]+")
CFG_MACRO = re.compile(r"\bcfg!\s*\(")
# `include_bytes!`/`include_str!` bring in data, not code.
INCLUDE = re.compile(r"\binclude!\s*[\(\[\{]")
VERUS_BLOCK = re.compile(r"\bverus!\s*([\{\(\[])")
CLOSER = {"{": "}", "(": ")", "[": "]"}
RAW_STRING = re.compile(r"(?<![A-Za-z0-9_])b?r(#*)\"")
CHAR_LITERAL = re.compile(r"b?'(?:\\u\{[0-9a-fA-F]{1,6}\}|\\x[0-9a-fA-F]{2}|\\.|[^\\'\n])'")
FN_DEF = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")
ITEM = re.compile(r"\b(fn|struct|enum|union|trait|type|const|static|mod|use|impl|assume_specification)\b"
                  r"(?:\s*<[^>]*>)?\s*([A-Za-z_][A-Za-z0-9_]*)?")
IMPL_START = re.compile(r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?impl\b")


def strip_comments(text: str) -> str:
    """Comments and string literals replaced by spaces, newlines kept, so
    offsets and line numbers are unchanged."""
    out = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif (m := RAW_STRING.match(text, i)) and (i == 0 or not re.match(r"[A-Za-z0-9_]", text[i - 1])):
            close = '"' + m.group(1)
            j = text.find(close, m.end())
            j = n if j < 0 else j + len(close)
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif (m := CHAR_LITERAL.match(text, i)) and (i == 0 or not re.match(r"[A-Za-z0-9_]", text[i - 1])):
            out.append(" " * (m.end() - i))
            i = m.end()
        elif text[i] == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def attributes(code: str):
    """(offset, token stream) of every `#[...]` / `#![...]` attribute."""
    for m in re.finditer(r"#!?\[", code):
        depth, j = 1, m.end()
        while j < len(code) and depth:
            depth += {"[": 1, "]": -1}.get(code[j], 0)
            j += 1
        yield m.start(), j, code[m.end():j - 1]


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
    """(qualified name, offset, inside verus!, ensures conjuncts) of every
    fn definition."""
    blocks = list(verus_blocks(code))
    impls = impl_spans(code)
    out = []
    for m in FN_DEF.finditer(code):
        at = m.start()
        owner = [t for s, e, t in impls if s < at < e]
        name = f"{owner[-1]}::{m.group(1)}" if owner else m.group(1)
        inside = any(s <= at < e for s, e in blocks)
        out.append((name, at, inside, ensures_conjuncts(spec_header(code, at)) if inside else 0))
    return out


def item_after(code: str, offset: int) -> str:
    m = ITEM.search(code, offset)
    if not m:
        return "?"
    return m.group(1) if m.group(1) in ("use", "impl") else (m.group(2) or m.group(1))


def enclosing_fn(defs, offset: int) -> str:
    before = [d for d in defs if d[1] < offset]
    return before[-1][0] if before else "<file>"


def trusted_in(path: pathlib.Path):
    """(line, construct, item) of every trusted construct in `path`."""
    code = strip_comments(path.read_text())
    defs = definitions(code)
    found = set()
    for off, end, body in attributes(code):
        item = item_after(code, end)
        for t in ATTR_TOKEN.finditer(body):
            found.add((line_of(code, off), t.group(1), item))
        if INTERNAL_TOKEN.search(body):
            found.add((line_of(code, off), "verus::internal", item))
        if re.match(r"\s*(cfg|cfg_attr)\b", body) and VERUS_CFG.search(body) and item != "use":
            found.add((line_of(code, off), "cfg(verus_*)", item))
        if re.match(r"\s*path\s*=", body):
            found.add((line_of(code, off), "path", item))
    for m in CFG_MACRO.finditer(code):
        if VERUS_CFG.search(code, m.end(), balanced(code, m.end() - 1)):
            found.add((line_of(code, m.start()), "cfg(verus_*)", enclosing_fn(defs, m.start())))
    for m in CALL_TOKEN.finditer(code):
        path = re.sub(r"\s", "", m.group(1))
        if (path, m.group(2)) == ("kani::", "assume"):
            continue
        found.add((line_of(code, m.start()), m.group(2) + "(", enclosing_fn(defs, m.start())))
    for m in ITEM_TOKEN.finditer(code):
        found.add((line_of(code, m.start()), "assume_specification", item_after(code, m.end())))
    for m in INCLUDE.finditer(code):
        found.add((line_of(code, m.start()), "include!", enclosing_fn(defs, m.start())))
    return sorted(found)


def rs_files(crate_dir: pathlib.Path):
    return sorted(p for p in (crate_dir / "src").rglob("*.rs"))


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
        allowed[(e["file"], e["construct"], e["item"])] += int(e.get("count", 1))
    seen = collections.Counter()
    lines = collections.defaultdict(list)
    blocks = 0
    for f in rs_files(crate_dir):
        rel = str(f.relative_to(crate_dir))
        blocks += len(list(verus_blocks(strip_comments(f.read_text()))))
        for line, construct, item in trusted_in(f):
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
        defs += [(rel, line_of(code, at), *d) for d, at in ((d, d[1]) for d in definitions(code))]
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
    if len(argv) == 6 and argv[1] == "check":
        return check(argv[2], pathlib.Path(argv[3]), pathlib.Path(argv[4]), pathlib.Path(argv[5]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
