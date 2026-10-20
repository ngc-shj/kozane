"""tools/audit-gate must pass a clean, fully excepted report and refuse each
kind of failure with its own message (M3a external review, item 3; its
follow-up review's Major). A fake `cargo-audit` on PATH prints a canned
`--json` report, so the cases run without the real advisory database. Like
the real tool, the fake reads `audit.toml` from $CARGO_HOME, $HOME/.cargo
and the working directory's `.cargo/`, and drops the ids it ignores, so the
isolation case fails if the gate lets such a file be read.

Usage: python3 tests/tools/test_audit_gate.py
Prints "AUDIT-GATE-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/audit-gate"

PASTE = {"kind": "unmaintained", "package": {"name": "paste", "version": "1.0.15"},
         "advisory": {"id": "RUSTSEC-2024-0436", "title": "paste - no longer maintained"}}
IGNORE_PASTE = '[[ignore]]\nid = "RUSTSEC-2024-0436"\ncrate = "paste"\nreason = "build-time only"\nowner = "M4"\n'
VULN = {"package": {"name": "libcrux-x", "version": "0.0.1"},
        "advisory": {"id": "RUSTSEC-2099-0001", "title": "bad"}}


CLEAN_SETTINGS = {"target_arch": [], "target_os": [], "severity": None, "ignore": [],
                  "informational_warnings": ["unmaintained", "unsound", "notice"]}


def report(vulns=(), warnings=(), advisories=1338, crates=222, settings=None, count=None):
    return {"database": {"advisory-count": advisories}, "lockfile": {"dependency-count": crates},
            "settings": CLEAN_SETTINGS if settings is None else settings,
            "vulnerabilities": {"found": bool(vulns), "count": len(vulns) if count is None else count,
                                "list": list(vulns)},
            "warnings": {"unmaintained": list(warnings)} if warnings else {}}


HOSTILE = '[advisories]\nignore = ["RUSTSEC-2099-0001"]\n'


# (name, canned report or raw stdout, ignore file text, expected message or None for accept)
CASES = [
    ("a clean report with every warning excepted passes", report(warnings=[PASTE]), IGNORE_PASTE, None),
    ("a vulnerability fails even if its id is excepted", report(vulns=[VULN], warnings=[PASTE]),
     IGNORE_PASTE + IGNORE_PASTE.replace("RUSTSEC-2024-0436", "RUSTSEC-2099-0001").replace("paste", "libcrux-x"),
     "vulnerability RUSTSEC-2099-0001 in libcrux-x"),
    ("an unexcepted warning fails", report(warnings=[PASTE]), "",
     "unmaintained warning RUSTSEC-2024-0436 for paste 1.0.15 is not excepted"),
    ("an exception for another crate does not cover the warning", report(warnings=[PASTE]),
     IGNORE_PASTE.replace('crate = "paste"', 'crate = "other"'), "is not excepted"),
    ("a stale exception fails", report(), IGNORE_PASTE, "exception RUSTSEC-2024-0436 matches no reported warning"),
    ("an empty database fails", report(advisories=0), "", "examined nothing"),
    ("a lock with no crates fails", report(crates=0), "", "examined nothing"),
    ("no JSON from cargo audit fails", "error: database not found", "", "cargo audit produced no report"),
    ("an exception without a reason fails", report(warnings=[PASTE]),
     IGNORE_PASTE.replace('reason = "build-time only"\n', ""), "must have exactly the non-empty string keys"),
    # Settings that would hide an advisory, as an audit.toml the gate failed
    # to keep out would produce them.
    ("a report without settings fails", {**report(), "settings": None}, "", "the report has no settings"),
    ("ignored advisories in the settings fail", report(settings={**CLEAN_SETTINGS, "ignore": ["RUSTSEC-2099-0001"]}),
     "", "ran with ignored advisories"),
    ("a severity threshold fails", report(settings={**CLEAN_SETTINGS, "severity": "high"}), "",
     "ran with a severity threshold"),
    ("a target OS filter fails", report(settings={**CLEAN_SETTINGS, "target_os": ["windows"]}), "",
     "ran with a target_os filter"),
    ("a target arch filter fails", report(settings={**CLEAN_SETTINGS, "target_arch": ["x86"]}), "",
     "ran with a target_arch filter"),
    ("disabled unsound warnings fail",
     report(settings={**CLEAN_SETTINGS, "informational_warnings": ["unmaintained", "notice"]}), "",
     "ran without the warnings"),
    ("a count that disagrees with the list fails", report(count=1), "", "inconsistent report"),
    # The isolation itself: a hostile audit.toml in every place cargo-audit
    # reads one would hide the vulnerability; the gate must not let it.
    ("an audit.toml in HOME, CARGO_HOME or the working directory is not read", report(vulns=[VULN]), "",
     "vulnerability RUSTSEC-2099-0001 in libcrux-x", "hostile"),
]


FAKE = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, tomllib
out = pathlib.Path(sys.argv[0]).with_name("report.json").read_text()
try:
    report = json.loads(out)
except json.JSONDecodeError:
    print(out)
    sys.exit(1)
ignored = []
for p in (os.environ.get("CARGO_HOME", ""), os.path.join(os.environ.get("HOME", ""), ".cargo"), ".cargo"):
    f = pathlib.Path(p, "audit.toml")
    if p and f.is_file():
        ignored += tomllib.loads(f.read_text()).get("advisories", {}).get("ignore", [])
if ignored:
    v = report["vulnerabilities"]
    v["list"] = [x for x in v["list"] if x["advisory"]["id"] not in ignored]
    v["count"], v["found"] = len(v["list"]), bool(v["list"])
    report["settings"]["ignore"] = ignored
print(json.dumps(report))
'''


def run_case(out, ignore_text: str, mode: str = "") -> str:
    with tempfile.TemporaryDirectory(prefix="test-audit-gate-") as d:
        d = pathlib.Path(d)
        (d / "report.json").write_text(out if isinstance(out, str) else json.dumps(out))
        fake = d / "cargo-audit"
        fake.write_text(FAKE)
        fake.chmod(0o755)
        (d / "ignore.toml").write_text(ignore_text)
        env = {**os.environ, "PATH": f"{d}:{os.environ['PATH']}"}
        cwd = d
        if mode == "hostile":
            for sub in ("home/.cargo", "cargo-home", "cwd/.cargo"):
                (d / sub).mkdir(parents=True)
            for f in ("home/.cargo/audit.toml", "cargo-home/audit.toml", "cwd/.cargo/audit.toml"):
                (d / f).write_text(HOSTILE)
            env.update(HOME=str(d / "home"), CARGO_HOME=str(d / "cargo-home"))
            cwd = d / "cwd"
        r = subprocess.run([sys.executable, str(TOOL), "--db", str(d), "--lock", str(d / "Cargo.lock"),
                            "--ignore", str(d / "ignore.toml")], capture_output=True, text=True, env=env, cwd=cwd)
        return r.returncode, r.stdout + r.stderr


def main() -> int:
    failures = 0
    for name, out, ignore_text, want, *mode in CASES:
        code, text = run_case(out, ignore_text, *mode)
        ok = (code == 0 and "AUDIT-ADVISORIES 1338" in text) if want is None else (code != 0 and want in text)
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: exit={code} {text.strip()[-160:]!r}")
    print(f"AUDIT-GATE-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
