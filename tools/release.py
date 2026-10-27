#!/usr/bin/env python3
"""Signed releases and their verification (M5 plan C13, C12).

  release.py make --keys DIR --pkg DIR --out DIR [--version V] [--allow-dirty]
  release.py verify --pub DIR --release DIR [--envelope FILE --kind key|pq|tls] [--allow-dirty]

`make` writes OUT/{manifest, manifest.sig, published.img, boot.desc,
flash.bin}. The manifest's image, descriptor and firmware digests and its
PCRs 0-8 come from the files it ships, the PCRs through tools/measure.py (the
one host model of TF-A's and the boot command's measurements, M7 plan C4),
and must agree with the package's own pcrs. A tree with
uncommitted changes to tracked files is refused: the commit a release names
must be the tree it was built from.

`verify` checks both signatures (tools/release), then recomputes every digest
and PCRs 0-8 from the shipped files and compares them with the signed
fields; with --envelope it also checks that the envelope (of --kind: `key`'s,
`pqkey`'s or `tlskey`'s) has a sealed object that enforces the signed PCRs
(`mksecrets check-envelope`, the PDs' own parser).

Control class: fail-closed verification gate; a missing file, a failing tool
or any disagreement is a refusal.
"""

import argparse
import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import measure  # noqa: E402

RELEASE_BIN = ROOT / "build/release/target/release/release"


class Refused(Exception):
    pass


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tool(*args, capture=True) -> str:
    r = subprocess.run([str(RELEASE_BIN), *args], cwd=ROOT, capture_output=capture, text=True)
    if r.returncode != 0:
        raise Refused((r.stderr or r.stdout or "").strip() or f"tools/release {args[0]} failed")
    return r.stdout


def git(*args) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()


def versions() -> dict:
    verus = (pathlib.Path("/opt/verus/SOURCE").read_text().strip() if pathlib.Path("/opt/verus/SOURCE").exists()
             else "absent")
    kani = subprocess.run(["cargo", "kani", "--version"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    return {"verus": verus, "kani": kani.split()[-1] if kani else "absent"}


def make(a) -> None:
    pkg, out = pathlib.Path(a.pkg), pathlib.Path(a.out)
    if out.exists():
        raise Refused(f"{out} already exists")
    image, desc, firmware = pkg / "published.img", pkg / "boot.desc", pkg / "flash.bin"
    try:
        pcrs = [p.hex() for p in measure.expected_pcrs(firmware.read_bytes(), desc.read_bytes(), image.read_bytes())]
    except measure.DescriptorError as e:
        raise Refused(str(e))
    if (pkg / "pcrs").read_text().split() != pcrs:
        raise Refused("the package's pcrs differ from tools/measure.py's")
    placeholder = measure.check_placeholder(image.read_bytes(), desc.read_bytes()) \
        + measure.check_not_fault_inject(image.read_bytes())
    if placeholder:
        raise Refused("; ".join(placeholder))
    dirty = bool(git("status", "--porcelain", "--untracked-files=no"))
    if dirty and not a.allow_dirty:
        raise Refused("the tree has uncommitted changes; a release must name the commit it was built from")
    fields = {
        "version": a.version,
        # A dirty tree is never named by its HEAD alone (S4); verify refuses
        # it unless asked to accept it.
        "commit": git("rev-parse", "HEAD") + ("-dirty" if dirty else ""),
        # The dev image is identified by its pinned recipe: its digest is not
        # visible from inside the container.
        "dev_image": "dockerfile-sha256:" + sha256(ROOT / "docker/Dockerfile"),
        "loader_img_sha256": sha256(image),
        "boot_desc_sha256": sha256(desc),
        "firmware_sha256": sha256(firmware),
        "pcrs": ",".join(pcrs),
        "cargo_lock_sha256": sha256(ROOT / "Cargo.lock"),
        **versions(),
    }
    manifest = tool("render", *(f"{k}={v}" for k, v in fields.items()))
    # Built in a staging directory beside OUT and renamed into place only
    # once signed and complete (F1): a failure leaves no OUT to block the
    # retry, and no reader ever sees a half-written release. The commit
    # point is the rename, after the signature is written.
    staging = pathlib.Path(tempfile.mkdtemp(prefix=f".{out.name}.release-", dir=out.parent))
    try:
        (staging / "manifest").write_text(manifest)
        tool("sign", "--keys", a.keys, "--manifest", str(staging / "manifest"), "--out", str(staging / "manifest.sig"))
        shutil.copyfile(image, staging / "published.img")
        shutil.copyfile(desc, staging / "boot.desc")
        shutil.copyfile(firmware, staging / "flash.bin")
        staging.chmod(0o755)
        os.rename(staging, out)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    print(f"release: wrote {out}")


def verify(a) -> None:
    rel = pathlib.Path(a.release)
    printed = tool("verify", "--pub", a.pub, "--manifest", str(rel / "manifest"), "--sig", str(rel / "manifest.sig"))
    fields = dict(line.split("=", 1) for line in printed.splitlines() if "=" in line)
    image, desc, firmware = rel / "published.img", rel / "boot.desc", rel / "flash.bin"
    if fields.get("commit", "").endswith("-dirty") and not a.allow_dirty:
        raise Refused(f"the release was built from a dirty tree ({fields['commit']})")
    placeholder = measure.check_placeholder(image.read_bytes(), desc.read_bytes()) \
        + measure.check_not_fault_inject(image.read_bytes())
    if placeholder:
        raise Refused("; ".join(placeholder))
    try:
        pcrs = measure.expected_pcrs(firmware.read_bytes(), desc.read_bytes(), image.read_bytes())
    except measure.DescriptorError as e:
        raise Refused(str(e))
    want = {
        "loader_img_sha256": sha256(image),
        "boot_desc_sha256": sha256(desc),
        "firmware_sha256": sha256(firmware),
        "pcrs": ",".join(p.hex() for p in pcrs),
    }
    for key, value in want.items():
        if fields.get(key) != value:
            raise Refused(f"{key}: the shipped files give {value}, the signed manifest says {fields.get(key)}")
    if a.envelope:
        r = subprocess.run(["cargo", "run", "--locked", "-q", "-p", "mksecrets", "--", "check-envelope",
                            "--kind", a.kind, "--envelope", a.envelope, "--pcrs", fields["pcrs"]],
                           cwd=ROOT, capture_output=True, text=True)
        if r.returncode != 0:
            raise Refused(r.stderr.strip() or "mksecrets check-envelope failed")
    print("release: verified" + (" (envelope sealed to its PCRs 0-8)" if a.envelope else ""))


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("make")
    m.add_argument("--keys", required=True)
    m.add_argument("--pkg", required=True)
    m.add_argument("--out", required=True)
    m.add_argument("--version", default="m5-dev")
    m.add_argument("--allow-dirty", action="store_true")
    v = sub.add_parser("verify")
    v.add_argument("--pub", required=True)
    v.add_argument("--release", required=True)
    v.add_argument("--envelope")
    v.add_argument("--kind", choices=("key", "pq", "tls"))
    v.add_argument("--allow-dirty", action="store_true")
    a = ap.parse_args()
    if a.cmd == "verify" and bool(a.envelope) != bool(a.kind):
        ap.error("--envelope and --kind go together")
    try:
        (make if a.cmd == "make" else verify)(a)
    except (Refused, measure.DescriptorError, OSError) as e:
        print(f"release: refused: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
