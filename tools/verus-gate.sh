#!/usr/bin/env bash
# Runs `cargo verus verify` on one crate (M4 plan C1) and fails unless:
# Verus exited 0; the crate's own summary line (not vstd's, which comes
# first) reports n > 0 verified and 0 errors; the crate's trusted constructs
# equal policy/verus-trusted.toml; and every function policy/verus-required.toml
# lists is inside verus! with an ensures. Prints `VERUS-VERIFIED <n>` and
# `VERUS-ENSURES <n>` for the count manifest.
#
# A pass is cached under build/verus-cache, keyed like kani-gate's, plus the
# Verus and Z3 versions and both policy files.
set -euo pipefail
shopt -s inherit_errexit

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
if [ $# -ne 2 ] || [ "$1" != "-p" ]; then
    echo "usage: verus-gate.sh -p <crate>" >&2
    exit 2
fi
crate=$2

export PATH=/opt/verus:$PATH RUSTUP_TOOLCHAIN=${VERUS_RUST:-1.98.1} VERUS_Z3_PATH=/opt/verus/z3

meta=$(cargo metadata --locked --format-version 1)
dirs=$(printf '%s' "$meta" | python3 -c '
import json, os, sys
meta = json.load(sys.stdin)
ws = set(meta["workspace_members"])
pkgs = {p["name"]: p for p in meta["packages"] if p["id"] in ws}
todo, seen = [sys.argv[1]], set()
while todo:
    n = todo.pop()
    if n in seen or n not in pkgs:
        continue
    seen.add(n)
    print(os.path.relpath(os.path.dirname(pkgs[n]["manifest_path"])))
    todo += [d["name"] for d in pkgs[n]["dependencies"] if d.get("path")]
' "$crate")
crate_dir=$(printf '%s\n' "$dirs" | head -1)
if [ -z "$crate_dir" ]; then
    echo "verus-gate: no workspace crate named $crate" >&2
    exit 1
fi

sources=$(for d in $dirs; do
    find "$d" -type f \( -name '*.rs' -o -name 'Cargo.toml' \) -print0 | sort -z | xargs -0 sha256sum
done)
key=$(printf '%s\n' "$crate" "$(verus --version 2>&1)" "$(/opt/verus/z3 --version)" "$sources" \
    "$(sha256sum Cargo.toml Cargo.lock tools/verus-gate.sh tools/verus_trusted.py \
        policy/verus-trusted.toml policy/verus-required.toml)" \
    | sha256sum | cut -d' ' -f1)
cache="$root/build/verus-cache/$key"
if [ -f "$cache" ]; then
    echo "verus-gate: cached pass ($key)"
    cat "$cache"
    exit 0
fi

# The source checks first: they are cheap and need no solver.
if ! scan=$(python3 tools/verus_trusted.py check "$crate" "$crate_dir" \
        policy/verus-trusted.toml policy/verus-required.toml); then
    echo "verus-gate: source checks failed for $crate" >&2
    exit 1
fi
ensures=$(printf '%s\n' "$scan" | sed -nE 's/^VERUS-ENSURES ([0-9]+)$/\1/p')

log=$(mktemp)
trap 'rm -f "$log"' EXIT
# One SMT or cbmc run at a time on this machine, shared with kani-gate (the
# same lock file for every checkout and copy): the host has frozen under two
# concurrent proof runs.
exec 9>"${SECUREOS_PROOF_LOCK:-/tmp/secureos-proof.lock}"
flock 9

# Cargo skips a crate it considers fresh, and then no summary is printed:
# the crate's own artifacts are always cleaned so it is re-verified.
cargo clean -p "$crate" --target-dir build/target-verus >/dev/null 2>&1 || true
if ! cargo verus verify -p "$crate" --locked --offline --target-dir build/target-verus >"$log" 2>&1; then
    cat "$log"
    echo "verus-gate: cargo verus verify failed for $crate" >&2
    exit 1
fi

# The summary that follows `Checking <crate> v…` is the crate's own.
summary=$(awk -v c="$crate" '$1 == "Checking" && $2 == c { mine = 1; next }
    $1 == "Checking" { mine = 0 }
    mine && /^verification results::/ { print; exit }' "$log")
verified=$(printf '%s' "$summary" | sed -nE 's/^verification results:: ([0-9]+) verified, 0 errors$/\1/p')
if [ -z "$verified" ] || [ "$verified" -eq 0 ]; then
    cat "$log"
    echo "verus-gate: no clean summary for $crate (got: ${summary:-none})" >&2
    exit 1
fi

mkdir -p "$(dirname "$cache")"
printf 'VERUS-VERIFIED %s\nVERUS-ENSURES %s\n' "$verified" "$ensures" | tee "$cache"
