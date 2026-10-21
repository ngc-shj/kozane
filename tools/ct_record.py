#!/usr/bin/env python3
"""The C9 pass record's key (M4 plan C9 "Pass record").

`make ct` (tools/ct-gate) writes `build/ct/pass-<key>` only when both modes
pass; tools/package checks it. Both derive the key here: the sha256 over
the harness binary, policy/ct-declassify.toml, the C8 vector files and
`valgrind --version`, so a record written for any other combination of
those is not found.

The record is a plain file under build/: whoever can write the tree can
forge it, the same bypass class as editing policy/waivers.toml (R49 (b)).

  tools/ct_record.py key   --harness <bin> [--root <dir>] [--valgrind <bin>]
  tools/ct_record.py check --harness <bin> [--root <dir>] [--valgrind <bin>]
"""

import argparse
import hashlib
import pathlib
import subprocess
import sys

POLICY = "policy/ct-declassify.toml"
VECTORS = "crates/mce460896/tests/vectors"
# The lines package requires in a record.
REQUIRED = ("CT-CASES", "CT-MARKED-BYTES", "RESIDUE-CASES")


def valgrind_version(valgrind: str = "valgrind") -> str:
    return subprocess.run([valgrind, "--version"], capture_output=True, text=True, check=True).stdout.strip()


def record_key(root: pathlib.Path, harness: pathlib.Path, vg_version: str) -> str:
    vectors = sorted((root / VECTORS).glob("*.txt"))
    if not vectors:
        raise FileNotFoundError(f"no vector files in {root / VECTORS}")
    h = hashlib.sha256()

    def part(name: str, data: bytes):
        h.update(name.encode() + b"\0" + hashlib.sha256(data).hexdigest().encode() + b"\n")

    part("harness", harness.read_bytes())
    part(POLICY, (root / POLICY).read_bytes())
    for p in vectors:
        part(p.relative_to(root).as_posix(), p.read_bytes())
    part("valgrind --version", vg_version.encode())
    return h.hexdigest()


def record_path(root: pathlib.Path, key: str) -> pathlib.Path:
    return root / "build/ct" / f"pass-{key}"


def check_record(root: pathlib.Path, harness: pathlib.Path, vg_version: str) -> list:
    """The reasons the current inputs have no valid record (empty if they do)."""
    path = record_path(root, record_key(root, harness, vg_version))
    if not path.is_file():
        return [f"no C9 pass record {path.relative_to(root)} for this harness, policy, vectors and valgrind"]
    keys = {line.split(" ", 1)[0] for line in path.read_text().splitlines() if " " in line}
    return [f"{path.relative_to(root)}: no {k} line" for k in REQUIRED if k not in keys]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["key", "check"])
    ap.add_argument("--harness", required=True, type=pathlib.Path)
    ap.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parent.parent)
    ap.add_argument("--valgrind", default="valgrind")
    a = ap.parse_args()
    version = valgrind_version(a.valgrind)
    if a.cmd == "key":
        print(record_key(a.root, a.harness, version))
        return 0
    why = check_record(a.root, a.harness, version)
    for w in why:
        print(f"ct_record: {w}")
    return 1 if why else 0


if __name__ == "__main__":
    sys.exit(main())
