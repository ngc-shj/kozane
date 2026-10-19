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
BASE = (ROOT / "config/gateway.toml").read_text().replace('rp_pub_path = "keys/', f'rp_pub_path = "{ROOT}/config/keys/')
PEER = re.search(r"\[\[peers\]\]\nwg_pub = .*\nrp_pub_path = .*\nrp_hash = .*\nallowed_ips = \[[^\]]*\]\n", BASE).group(0)
RP_PUBLIC_KEY_LEN = 524160


def peer(n: int) -> str:
    # Distinct, valid keys: WireGuard base64 of [n; 32] and a McEliece-sized
    # file of n bytes (written by write_rp_keys), named relative to the case.
    import base64
    key = base64.b64encode(bytes([n]) * 32).decode()
    rp_hash = hashlib.blake2s(bytes([n]) * RP_PUBLIC_KEY_LEN).hexdigest()
    return (f'[[peers]]\nwg_pub = "{key}"\nrp_pub_path = "rp-{n}.pk"\nrp_hash = "{rp_hash}"\n'
            f'allowed_ips = ["10.200.{n}.0/24"]\n')


def write_rp_keys(d: pathlib.Path) -> None:
    for n in range(1, 10):
        (d / f"rp-{n}.pk").write_bytes(bytes([n]) * RP_PUBLIC_KEY_LEN)


CASES = [
    ("committed config builds", None, BASE),
    ("overlapping allowed IPs fail the build", "overlap", BASE + peer(7).replace("10.200.7.0/24", "10.200.0.0/16")),
    ("allowed IPs covering a neighbor fail the build", "cover neighbor", BASE.replace("10.200.0.2/32", "10.99.0.2/32")),
    ("allowed IPs overlapping the inside network fail the build", "overlap inside_prefix",
     BASE.replace("10.200.0.2/32", "10.99.0.128/25")),
    ("one peer over the deployable limit fails the build", "need 1..=8 peers",
     BASE.replace(PEER, "") + "".join(peer(i) for i in range(1, 10))),
    ("unknown field fails the build", "unknown field", BASE.replace("[gateway]", "[gateway]\nmtu = 1400")),
    ("McEliece key one byte short fails the build", "524159 bytes, expected 524160",
     BASE + peer(7).replace("rp-7.pk", "short.pk").replace(
         hashlib.blake2s(bytes([7]) * RP_PUBLIC_KEY_LEN).hexdigest(),
         hashlib.blake2s(bytes([7]) * (RP_PUBLIC_KEY_LEN - 1)).hexdigest())),
    ("duplicate McEliece key fails the build", "duplicate rp_pub", BASE + peer(7) + peer(8).replace("rp-8.pk", "rp-7.pk")
     .replace(hashlib.blake2s(bytes([8]) * RP_PUBLIC_KEY_LEN).hexdigest(),
              hashlib.blake2s(bytes([7]) * RP_PUBLIC_KEY_LEN).hexdigest())),
    ("rp_port equal to listen_port fails the build", "rp_port must differ",
     BASE.replace("rp_port = 51819", "rp_port = 51820")),
]


def build(cfg: pathlib.Path, target: pathlib.Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "SECUREOS_CONFIG": str(cfg)}
    return subprocess.run(["cargo", "build", "--locked", "-q", "-p", "config", "--target-dir", str(target)],
                          cwd=ROOT, env=env, capture_output=True, text=True)


def main() -> int:
    if not shutil.which("cargo"):
        print("test_config_build: cargo not found")
        return 1
    failures = 0
    target = ROOT / "build/config-fixture-target"
    with tempfile.TemporaryDirectory(prefix="config-build-") as d:
        write_rp_keys(pathlib.Path(d))
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
    print(f"CONFIG-BUILD-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
