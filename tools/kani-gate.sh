#!/usr/bin/env bash
# Runs `cargo kani` and fails unless every harness verified AND every
# kani::cover! was satisfied. Kani 0.68 has no --fail-uncoverable, and by
# default an unsatisfiable cover still lets the harness pass (plan C2, T14).
# Prints "KANI-HARNESSES <n>" for the count manifest.
#
# A pass is cached under build/kani-cache keyed by a hash of every input that
# can change the result (sources of the crate and its path dependencies,
# Cargo.lock, toolchain files, the
# Kani version, this script, and the arguments). Proofs are deterministic, so
# an identical key means an identical result; any change re-runs the proof.
set -euo pipefail
shopt -s inherit_errexit

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
# Resolves the full dependency graph with --locked (cargo kani has no
# --locked), and lists the crate under proof plus its path dependencies.
dirs=$(cargo metadata --locked --format-version 1 | python3 -c '
import json, os, sys
meta = json.load(sys.stdin)
ws = set(meta["workspace_members"])
pkgs = {p["name"]: p for p in meta["packages"] if p["id"] in ws}
args, todo, seen = sys.argv[1:], [], set()
for i, a in enumerate(args):
    if a == "-p" and i + 1 < len(args):
        todo.append(args[i + 1])
while todo:
    n = todo.pop()
    if n in seen or n not in pkgs:
        continue
    seen.add(n)
    print(os.path.relpath(os.path.dirname(pkgs[n]["manifest_path"])))
    todo += [d["name"] for d in pkgs[n]["dependencies"] if d.get("path")]
' "$@")
if [ -z "$dirs" ]; then
    echo "kani-gate: no source directories for: $*" >&2
    exit 1
fi
sources=$(for d in $dirs; do
    find "$d" -type f \( -name '*.rs' -o -name 'Cargo.toml' \) -print0 | sort -z | xargs -0 sha256sum
done)
version=$(cargo kani --version)
key=$(printf '%s\n' "$@" "$version" "$sources" \
    "$(sha256sum Cargo.toml Cargo.lock rust-toolchain.toml .cargo/config.toml tools/kani-gate.sh)" \
    | sha256sum | cut -d' ' -f1)
cache="$root/build/kani-cache/$key"
if [ -f "$cache" ]; then
    echo "kani-gate: cached pass ($key)"
    cat "$cache"
    exit 0
fi

log=$(mktemp)
trap 'rm -f "$log"' EXIT

if ! cargo kani "$@" >"$log" 2>&1; then
    cat "$log"
    echo "kani-gate: cargo kani failed" >&2
    exit 1
fi

grep -E '^Checking harness|cover properties satisfied|^Complete' "$log" || true

# "** M of N cover properties satisfied" must have M == N for every harness.
unsatisfied=$(awk '/^Checking harness/ { h = $3 }
    /\*\* [0-9]+ of [0-9]+ cover properties satisfied/ && $2 != $4 { print h, $0 }' "$log")
if [ -n "$unsatisfied" ]; then
    echo "kani-gate: unsatisfied cover properties:" >&2
    echo "$unsatisfied" >&2
    exit 1
fi

harnesses=$(sed -nE 's/^Complete - ([0-9]+) successfully verified harnesses, 0 failures.*/\1/p' "$log")
if [ -z "$harnesses" ] || [ "$harnesses" -eq 0 ]; then
    echo "kani-gate: no harness verified" >&2
    exit 1
fi
mkdir -p "$(dirname "$cache")"
echo "KANI-HARNESSES $harnesses" | tee "$cache"
