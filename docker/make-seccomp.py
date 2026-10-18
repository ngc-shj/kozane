#!/usr/bin/env python3
"""Derives docker/seccomp-userns.json from Docker's default seccomp profile.

The only change: `unshare(CLONE_NEWUSER|CLONE_NEWNET)` is allowed without
CAP_SYS_ADMIN (exactly those flags), so integration
tests can create an unprivileged user + network namespace and run QEMU and
wireguard-go there with NET_ADMIN over that empty namespace only. The build
container itself keeps no NET_ADMIN (M2 plan, security review S5).

Usage: docker/make-seccomp.py   (downloads the pinned profile, checks sha256)
"""

import hashlib
import json
import pathlib
import urllib.request

COMMIT = "4b8214fc4971e06172938a1f1554ccff6647ee80"
URL = f"https://raw.githubusercontent.com/moby/profiles/{COMMIT}/seccomp/default.json"
SHA256 = "6416b47770785a41ac59073cdc77d9fe98517df2799dc83ef207e622de3053f6"
OUT = pathlib.Path(__file__).with_name("seccomp-userns.json")
CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000


def main() -> None:
    raw = urllib.request.urlopen(URL).read()
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise SystemExit("profile hash mismatch")
    profile = json.loads(raw)
    # Exactly CLONE_NEWUSER | CLONE_NEWNET (what `unshare -rn` passes); any
    # other flag combination stays denied (M2 review S10).
    profile["syscalls"].append({
        "names": ["unshare"],
        "action": "SCMP_ACT_ALLOW",
        "args": [{"index": 0, "value": CLONE_NEWUSER | CLONE_NEWNET, "op": "SCMP_CMP_EQ"}],
    })
    OUT.write_text(json.dumps(profile, indent=1) + "\n")


if __name__ == "__main__":
    main()
