"""tools/mir-gate's comparison and member derivation on synthetic inputs
(M5 plan C4). The end-to-end splits are check-selftest's mir-* cases.

Usage: python3 tests/tools/test_mir_gate.py
Prints "MIR-GATE-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import importlib.machinery
import importlib.util
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader("mir_gate", str(ROOT / "tools/mir-gate"))
spec = importlib.util.spec_from_loader("mir_gate", loader)
mg = importlib.util.module_from_spec(spec)
loader.exec_module(mg)

BODY = "fn f() -> u32 {\n    let mut _0: u32;\n    bb0: {\n        _0 = const 1_u32;\n        return;\n    }\n}\n"


def files(base: pathlib.Path, entries: dict):
    for name, text in entries.items():
        (base / name).parent.mkdir(parents=True, exist_ok=True)
        (base / name).write_text(text)


def meta(pds_deps: dict) -> dict:
    """A cargo-metadata shape: package ids are their names."""
    names = set(pds_deps) | {d for ds in pds_deps.values() for d in ds}
    return {"packages": [{"id": n, "name": n} for n in sorted(names)],
            "resolve": {"nodes": [{"id": n, "deps": [{"pkg": d} for d in pds_deps.get(n, [])]} for n in sorted(names)]}}


# (name, shipped files, proof files, crates, expected matched, needle or None)
COMPARE = [
    ("equal MIR matches", {"wire.a.mir": BODY}, {"wire.b.mir": BODY}, ["wire"], 1, None),
    ("a changed constant is refused", {"wire.a.mir": BODY.replace("1_u32", "2_u32")}, {"wire.b.mir": BODY},
     ["wire"], 0, "wire: shipped MIR differs from the proof build"),
    ("every shipped variant must match", {"wire.a.mir": BODY, "wire.c.mir": BODY + "\n"}, {"wire.b.mir": BODY},
     ["wire"], 0, "wire: shipped MIR differs from the proof build (wire.c.mir)"),
    ("a member with no shipped MIR is refused", {}, {"wire.b.mir": BODY}, ["wire"], 0,
     "wire: no shipped MIR was captured"),
    ("a member with no proof MIR is refused", {"wire.a.mir": BODY}, {}, ["wire"], 0,
     "wire: expected one proof MIR, captured 0"),
    ("two proof variants are refused", {"wire.a.mir": BODY}, {"wire.b.mir": BODY, "wire.d.mir": BODY}, ["wire"], 0,
     "wire: expected one proof MIR, captured 2"),
    ("a hyphenated crate is found by its library name", {"wg_wire.a.mir": BODY}, {"wg_wire.b.mir": BODY},
     ["wg-wire"], 1, None),
    # M7 plan C9: a member shipped with and without a feature.
    ("each shipped variant matches its own proof variant", {"wire.a.mir": BODY, "wire.c.mir": BODY + "\n"},
     {"wire.b.mir": BODY, "wire.d.mir": BODY + "\n"}, ["wire"], 1, None, {"wire": [["--features", "x"]]}),
    ("a shipped variant matching no proof variant is refused", {"wire.a.mir": BODY, "wire.c.mir": BODY + "\n\n"},
     {"wire.b.mir": BODY, "wire.d.mir": BODY + "\n"}, ["wire"], 0,
     "wire: shipped MIR differs from the proof build (wire.c.mir)", {"wire": [["--features", "x"]]}),
    ("a declared variant whose proof build is missing is refused", {"wire.a.mir": BODY}, {"wire.b.mir": BODY},
     ["wire"], 0, "wire: expected 2 proof MIR, captured 1", {"wire": [["--features", "x"]]}),
]

# (name, pd dependency graph, verus, kani, pds, expected members)
MEMBERS = [
    ("a kani crate no PD links is not a member", {"pd-a": ["wire"], "laws": ["inner-core"]},
     ["ring"], ["wire", "inner-core"], ["a"], ["ring", "wire"]),
    ("a transitively linked kani crate is a member", {"pd-a": ["ingress-core"], "ingress-core": ["wire"]},
     [], ["wire"], ["a"], ["wire"]),
]


def main() -> int:
    failures = cases = 0
    for name, shipped, proof, crates, want, needle, *variants in COMPARE:
        cases += 1
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            files(base / "shipped", shipped)
            files(base / "proof", proof)
            (base / "shipped").mkdir(exist_ok=True)
            (base / "proof").mkdir(exist_ok=True)
            errors, matched = mg.compare(base / "shipped", base / "proof", crates, *variants)
        ok = matched == want and (not errors if needle is None else any(needle in e for e in errors))
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: matched={matched} errors={errors}")
    for name, graph, verus, kani, pds, want in MEMBERS:
        cases += 1
        got = mg.members(verus, kani, pds, meta(graph))
        ok = got == want
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {got}")
    print(f"MIR-GATE-FIXTURES {cases}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
