#!/usr/bin/env python3
"""Source checks behind the Verus gate (M4 plan C1) and check-pins P12.

One scanner, shared by both callers, so the two never disagree on what a
trusted construct is (R2: T-N11):

- trusted constructs: a `verifier::<x>` or `verifier(<x>)` token for one of
  TRUSTED anywhere in an attribute's token stream (so `cfg_attr(...)`
  spellings count), plus `assume(` and `admit(` calls;
- `verus!{}` block spans;
- `ensures` conjuncts inside those blocks (top-level comma-separated
  clauses up to the function body);
- required functions: each must be defined inside a `verus!` block and
  carry an `ensures`.

Usage:
  verus_trusted.py check <crate> <crate-dir> <trusted.toml> <required.toml>
      Prints `VERUS-ENSURES <n>` and exits 1 on any mismatch.
  verus_trusted.py scan <path>...
      Prints each trusted construct found as `file:line: construct`.
"""

import pathlib
import re
import sys
import tomllib

TRUSTED = (
    "external_body",
    "external_fn_specification",
    "external_type_specification",
    "external",
    "assume_specification",
    "exec_allows_no_decreases_clause",
)
ATTR_TOKEN = re.compile(r"verifier\s*(?:::\s*|\(\s*)(" + "|".join(TRUSTED) + r")\b")
# Verus's own `assume(`/`admit(`, inside verus! only; a path-qualified call
# such as Kani's `kani::assume(` is a different function.
CALL_TOKEN = re.compile(r"(?<![A-Za-z0-9_:])(assume|admit)\s*\(")
FN_DEF = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")


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
        yield m.start(), code[m.end():j - 1]


def line_of(code: str, offset: int) -> int:
    return code.count("\n", 0, offset) + 1


def trusted_in(path: pathlib.Path):
    code = strip_comments(path.read_text())
    found = []
    for off, body in attributes(code):
        for t in ATTR_TOKEN.finditer(body):
            found.append((line_of(code, off), t.group(1)))
    for s, e in verus_blocks(code):
        for m in CALL_TOKEN.finditer(code, s, e):
            found.append((line_of(code, m.start()), m.group(1) + "("))
    return sorted(found)


def verus_blocks(code: str):
    """(start, end) offsets of each `verus! { ... }` body."""
    for m in re.finditer(r"\bverus!\s*\{", code):
        depth, j = 1, m.end()
        while j < len(code) and depth:
            depth += {"{": 1, "}": -1}.get(code[j], 0)
            j += 1
        yield m.end(), j - 1


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


def functions_in_verus(code: str):
    """{name: ensures conjunct count} for every fn defined inside verus!."""
    out = {}
    for s, e in verus_blocks(code):
        block = code[s:e]
        for m in FN_DEF.finditer(block):
            header = spec_header(block, m.start())
            out[m.group(1)] = max(out.get(m.group(1), 0), ensures_conjuncts(header))
    return out


def rs_files(crate_dir: pathlib.Path):
    return sorted(p for p in (crate_dir / "src").rglob("*.rs"))


def check(crate: str, crate_dir: pathlib.Path, trusted_toml: pathlib.Path, required_toml: pathlib.Path) -> int:
    errors = []
    allowed = {
        (e["file"], e["construct"]) for e in tomllib.loads(trusted_toml.read_text()).get("trusted", [])
        if e.get("crate") == crate
    }
    for e in tomllib.loads(trusted_toml.read_text()).get("trusted", []):
        if not e.get("deviation"):
            errors.append(f"trusted allowlist entry without a deviation-log reference: {e}")
    seen = set()
    fns = {}
    ensures = 0
    for f in rs_files(crate_dir):
        rel = str(f.relative_to(crate_dir))
        for line, construct in trusted_in(f):
            seen.add((rel, construct))
            if (rel, construct) not in allowed:
                errors.append(f"{rel}:{line}: trusted construct `{construct}` not in the allowlist")
        code = strip_comments(f.read_text())
        for name, n in functions_in_verus(code).items():
            fns[name] = max(fns.get(name, 0), n)
            ensures += n
    for rel, construct in sorted(allowed - seen):
        errors.append(f"allowlisted `{construct}` in {rel} no longer present (stale entry)")
    required = tomllib.loads(required_toml.read_text()).get("crates", {}).get(crate, {}).get("functions", [])
    if not required:
        errors.append(f"no required functions listed for {crate}")
    for name in required:
        if name not in fns:
            errors.append(f"required function `{name}` is not defined inside verus!")
        elif fns[name] == 0:
            errors.append(f"required function `{name}` has no ensures")
    for e in errors:
        print(f"verus-trusted: {e}", file=sys.stderr)
    print(f"VERUS-ENSURES {ensures}")
    return 1 if errors or ensures == 0 else 0


def main(argv) -> int:
    if len(argv) >= 2 and argv[1] == "scan":
        hits = 0
        for p in argv[2:]:
            for line, construct in trusted_in(pathlib.Path(p)):
                print(f"{p}:{line}: {construct}")
                hits += 1
        return 0 if hits == 0 else 1
    if len(argv) == 6 and argv[1] == "check":
        return check(argv[2], pathlib.Path(argv[3]), pathlib.Path(argv[4]), pathlib.Path(argv[5]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
