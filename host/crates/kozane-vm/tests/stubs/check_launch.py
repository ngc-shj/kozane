"""I4.1 (M9 plan C4): what the stand-ins recorded under one `kozane-vm`
run, against `tools/vm.py`'s own rendering. Every fd is identified by what
the stand-in found behind it, not by the launcher's layout, and the argv
expected is `vm.machine("kvm", ..., launcher=True)` and
`vm.swtpm(..., launcher=True)` with those fds.

Usage: python3 check_launch.py <repo> <root prefix>
Prints one line per failed check, each starting `vm-launcher:`, and exits
non-zero if there is any.
"""

import fcntl
import hashlib
import json
import os
import socket
import sys

REPO, ROOT = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.join(REPO, "tools"))
import vm  # noqa: E402

# The node's media in the harness's order and where QEMU loads each, as
# vm.py renders them.
MEDIA = vm.LAUNCHER_MEDIA
ADDRS = dict(zip(MEDIA, vm.launcher_addrs(), strict=True))
SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW
CAP_SETS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")

failures = []


def fail(msg):
    failures.append(msg)


def path(*parts):
    return os.path.join(ROOT, *parts)


def sha256(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def record(name):
    try:
        with open(path("stubs", f"{name}.json")) as f:
            return json.load(f)
    except OSError:
        fail(f"vm-launcher: {name} never started")
        return None


def only(fds, what, pred):
    found = [int(n) for n, i in fds.items() if pred(i)]
    if len(found) != 1:
        fail(f"vm-launcher: {len(found)} fds hold {what}")
        return -1
    return found[0]


def connected_unix(i):
    return i["kind"] == "socket" and i["family"] == socket.AF_UNIX and i["connected"]


def child(rec, name):
    if rec["status"].get("NoNewPrivs") != "1":
        fail(f"vm-launcher: {name} without no_new_privs")
    held = [k for k in CAP_SETS if int(rec["status"].get(k, "1"), 16) != 0]
    if held:
        fail(f"vm-launcher: {name} holds capabilities in {held}")
    # The seams map every service user to the current uid: root of the test's
    # user namespace.
    if set(rec["uid"]) != {0} or set(rec["gid"]) != {0}:
        fail(f"vm-launcher: {name} runs as uid {rec['uid']} gid {rec['gid']}, not the mapped user")
    # Python itself may add LC_CTYPE (PEP 538); nothing else may arrive.
    if set(rec["env"]) - {"LC_CTYPE"}:
        fail(f"vm-launcher: {name} inherited environment {rec['env']}")


qemu = record("qemu")
swtpm = record("swtpm")
pin = dict(line.split("=", 1) for line in open(path("etc/kozane/firmware.pin")).read().splitlines())

if qemu:
    fds = qemu["fds"]
    child(qemu, "qemu")
    fw = only(fds, "u-boot.bin", lambda i: i["kind"] == "memfd" and i["name"] == "u-boot.bin")
    if fw >= 0:
        info = fds[str(fw)]
        if info["seals"] & SEALS != SEALS:
            fail(f"vm-launcher: firmware fd not sealed (seals {info['seals']:#x})")
        if info["sha256"] != pin["firmware_sha256"]:
            fail(f"vm-launcher: unpinned firmware ran ({info['sha256']} != {pin['firmware_sha256']})")
    media = []
    for name in MEDIA:
        fd = only(fds, name, lambda i, n=name: i["kind"] == "memfd" and i["name"] == n)
        if fd < 0:
            continue
        info = fds[str(fd)]
        if info["seals"] & SEALS != SEALS:
            fail(f"vm-launcher: {name} fd not sealed")
        if info["sha256"] != sha256(path("var/lib/kozane/node", name)):
            fail(f"vm-launcher: {name} fd holds other bytes")
        media.append((f"/dev/fd/{fd}", ADDRS[name]))
    tpm = only(fds, "a connected AF_UNIX socket", connected_unix)
    if not qemu["tpm_roundtrip"]:
        fail("vm-launcher: the TPM fd does not reach swtpm")
    taps = {}
    for want in ("kozane-out", "kozane-in"):
        taps[want] = only(fds, f"tap {want}", lambda i, w=want: i["kind"] == "tap" and i["name"] == w
                          and i["flags"] & 0x0002 and i["flags"] & 0x1000)
    if len(fds) != 4 + len(MEDIA):
        fail(f"vm-launcher: qemu holds {sorted(fds)}, not exactly its {4 + len(MEDIA)} fds")
    if not failures:
        want = vm.machine("kvm", f"/dev/fd/{fw}", tpm, (taps["kozane-out"], taps["kozane-in"]), media=media,
                          launcher=True)
        if qemu["argv"] != want:
            fail(f"vm-launcher: argv differs:\n  recorded {qemu['argv']}\n  vm.py    {want}")

if swtpm:
    fds = swtpm["fds"]
    child(swtpm, "swtpm")
    key_path = os.path.realpath(path("etc/kozane/swtpm.key"))
    key = only(fds, "the swtpm key", lambda i: i["kind"] == "file" and i["path"] == key_path)
    ctrl = only(fds, "swtpm's ctrl socket", connected_unix)
    if len(fds) != 2:
        fail(f"vm-launcher: swtpm holds {sorted(fds)}, not exactly its 2 fds")
    if key >= 0 and ctrl >= 0:
        want = vm.swtpm(path("var/lib/kozane/swtpm"), key, ctrl, launcher=True)
        if swtpm["argv"] != want:
            fail(f"vm-launcher: swtpm argv differs:\n  recorded {swtpm['argv']}\n  vm.py    {want}")

for f in failures:
    print(f)
print("vm-launcher: checked" if not failures else f"vm-launcher: {len(failures)} failures")
sys.exit(1 if failures else 0)
