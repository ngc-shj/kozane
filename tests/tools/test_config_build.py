"""The configuration is validated by crates/config/build.rs: an invalid
file must fail the build itself, not only the validator's unit tests (plan
C15, code review T4).

Usage: python3 tests/tools/test_config_build.py   (in the dev container)
Prints "CONFIG-BUILD-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
# Case files live in a temporary directory: point the committed key paths
# (relative to config/) at the repository.
BASE = (ROOT / "config/gateway.toml").read_text().replace('rp_pub_path = "keys/', f'rp_pub_path = "{ROOT}/config/keys/') \
    .replace('tls_cert = "keys/', f'tls_cert = "{ROOT}/config/keys/')
RP_PUBLIC_KEY_LEN = 524160
GATEWAY_RP_HASH = re.search(r'rp_hash = "([0-9a-f]{64})"', BASE).group(1)
# M8 plan D4, C7: what used to be the configuration's peer, now refused.
PEER = ('[[peers]]\nwg_pub = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="\nrp_pub_path = "short.pk"\n'
        f'rp_hash = "{GATEWAY_RP_HASH}"\nallowed_ips = ["10.200.0.2/32"]\n')
SHORT_HASH = hashlib.blake2s(bytes([7]) * (RP_PUBLIC_KEY_LEN - 1)).hexdigest()


CASES = [
    ("committed config builds", None, BASE),
    ("a [[peers]] table fails the build", "unknown field `peers`", BASE + "\n" + PEER),
    ("unknown field fails the build", "unknown field", BASE.replace("[gateway]", "[gateway]\nmtu = 1400")),
    ("McEliece key one byte short fails the build", "524159 bytes, expected 524160",
     re.sub(r'rp_pub_path = "[^"]*"', 'rp_pub_path = "short.pk"', BASE, count=1).replace(GATEWAY_RP_HASH, SHORT_HASH)),
    ("neighbor outside the inside network fails the build", "outside inside_prefix",
     BASE + '\n[[neighbors]]\nip = "10.98.0.5"\nmac = "02:00:00:00:98:05"\n'),
    ("rp_port equal to listen_port fails the build", "rp_port must differ",
     BASE.replace("rp_port = 51819", "rp_port = 51820")),
    # M6 plan C11: the certificate must carry tls_public.
    ("certificate without tls_public fails the build", "does not hold tls_public",
     re.sub(r'tls_public = "04[0-9a-f]{2}', 'tls_public = "0400', BASE)),
]


def build(cfg: pathlib.Path, target: pathlib.Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "KOZANE_CONFIG": str(cfg)}
    return subprocess.run(["cargo", "build", "--locked", "-q", "-p", "config", "--target-dir", str(target)],
                          cwd=ROOT, env=env, capture_output=True, text=True)


def main() -> int:
    if not shutil.which("cargo"):
        print("test_config_build: cargo not found")
        return 1
    failures = 0
    target = ROOT / "build/config-fixture-target"
    with tempfile.TemporaryDirectory(prefix="config-build-") as d:
        (pathlib.Path(d) / "short.pk").write_bytes(bytes([7]) * (RP_PUBLIC_KEY_LEN - 1))
        for i, (name, want, text) in enumerate(CASES):
            cfg = pathlib.Path(d) / f"case{i}.toml"
            cfg.write_text(text)
            r = build(cfg, target)
            if want is None:
                ok = r.returncode == 0
            else:
                ok = r.returncode != 0 and want in r.stderr
            failures += not ok
            print(f"{'ok  ' if ok else 'FAIL'} {name}: exit={r.returncode}")
            if not ok:
                print(r.stderr[-1500:])
        # S7: the pre-rename variable alone stops the build, by name.
        env = {k: v for k, v in os.environ.items() if k != "KOZANE_CONFIG"}
        env["SECUREOS_CONFIG"] = str(pathlib.Path(d) / "case0.toml")
        r = subprocess.run(["cargo", "build", "--locked", "-q", "-p", "config", "--target-dir", str(target)],
                           cwd=ROOT, env=env, capture_output=True, text=True)
        ok = r.returncode != 0 and "SECUREOS_CONFIG is set but KOZANE_CONFIG is not" in r.stderr
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} a stale SECUREOS_CONFIG alone fails the build: exit={r.returncode}")
        if not ok:
            print(r.stderr[-1500:])
    print(f"CONFIG-BUILD-FIXTURES {len(CASES) + 1}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
