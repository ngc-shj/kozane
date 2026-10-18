#!/usr/bin/env python3
"""Derives docker/seccomp-userns.json from Docker's default seccomp profile.

The only change: `unshare(CLONE_NEWUSER|CLONE_NEWNET)` is allowed without
CAP_SYS_ADMIN (exactly those flags), so integration
tests can create an unprivileged user + network namespace and run QEMU and
wireguard-go there with NET_ADMIN over that empty namespace only. The build
container itself keeps no NET_ADMIN (M2 plan, security review S5).

Usage: docker/make-seccomp.py          (downloads the pinned profile, checks sha256)
       docker/make-seccomp.py --check  (offline: the committed profile is the
                                        pinned one plus exactly our entry)
"""

import hashlib
import json
import pathlib
import sys
import urllib.request

COMMIT = "4b8214fc4971e06172938a1f1554ccff6647ee80"
URL = f"https://raw.githubusercontent.com/moby/profiles/{COMMIT}/seccomp/default.json"
SHA256 = "6416b47770785a41ac59073cdc77d9fe98517df2799dc83ef207e622de3053f6"
OUT = pathlib.Path(__file__).with_name("seccomp-userns.json")
CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
# sha256 of json.dumps(<pinned profile>, sort_keys=True), for --check.
CANONICAL_SHA256 = "2ebf3bdba229d3d972cfc3721001306de96cc5113a14b29cb510c2edd91ca84a"
# Exactly CLONE_NEWUSER | CLONE_NEWNET (what `unshare -rn` passes); any
# other flag combination stays denied (M2 review S10).
ENTRY = {
    "names": ["unshare"],
    "action": "SCMP_ACT_ALLOW",
    "args": [{"index": 0, "value": CLONE_NEWUSER | CLONE_NEWNET, "op": "SCMP_CMP_EQ"}],
}


def canonical_sha256(profile: dict) -> str:
    return hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest()


def check(text: str) -> list:
    profile = json.loads(text)
    syscalls = profile.get("syscalls") or [None]
    if syscalls[-1] != ENTRY:
        return ["seccomp: last rule is not the exact unshare(CLONE_NEWUSER|CLONE_NEWNET) entry"]
    profile["syscalls"] = syscalls[:-1]
    if canonical_sha256(profile) != CANONICAL_SHA256:
        return ["seccomp: profile differs from the pinned Docker default beyond the unshare entry"]
    return []


def main() -> None:
    if sys.argv[1:] == ["--check"]:
        errors = check(OUT.read_text())
        print("\n".join(errors) or "SECCOMP-PROFILE ok")
        raise SystemExit(1 if errors else 0)
    raw = urllib.request.urlopen(URL).read()
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise SystemExit("profile hash mismatch")
    profile = json.loads(raw)
    if canonical_sha256(profile) != CANONICAL_SHA256:
        raise SystemExit("CANONICAL_SHA256 is stale for the pinned profile")
    profile["syscalls"].append(ENTRY)
    OUT.write_text(json.dumps(profile, indent=1) + "\n")


if __name__ == "__main__":
    main()
