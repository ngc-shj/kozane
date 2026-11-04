"""What a launcher child holds (M9 plan C4, I4.1): every open fd above
stderr, classified, plus its credentials, capability sets and environment.
Shared by the QEMU and swtpm stand-ins; the launcher starts them with an
empty environment, so they find this module next to themselves."""

import fcntl
import hashlib
import os
import socket
import stat
import struct

TUNGETIFF = 0x800454D2


def fd_info(fd: int):
    try:
        target = os.readlink(f"/proc/self/fd/{fd}")
        st = os.fstat(fd)
    except OSError:
        return None  # the fd listdir itself held
    if target.startswith("/memfd:"):
        data = os.pread(fd, st.st_size, 0)
        return {"kind": "memfd", "name": target[len("/memfd:"):].removesuffix(" (deleted)"),
                "seals": fcntl.fcntl(fd, fcntl.F_GET_SEALS), "sha256": hashlib.sha256(data).hexdigest()}
    if stat.S_ISSOCK(st.st_mode):
        s = socket.socket(fileno=os.dup(fd))
        try:
            try:
                s.getpeername()
                connected = True
            except OSError:
                connected = False
            return {"kind": "socket", "family": int(s.family), "type": int(s.type), "connected": connected}
        finally:
            s.close()
    if target == "/dev/net/tun":
        name, flags = struct.unpack("16sh22x", fcntl.ioctl(fd, TUNGETIFF, bytes(40)))
        return {"kind": "tap", "name": name.rstrip(b"\0").decode(), "flags": flags}
    if stat.S_ISREG(st.st_mode):
        return {"kind": "file", "path": target}
    return {"kind": "other", "target": target}


def inventory(argv: list) -> dict:
    fds = {}
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        if fd > 2:
            info = fd_info(fd)
            if info is not None:
                fds[str(fd)] = info
    status = {}
    with open("/proc/self/status") as f:
        for line in f:
            key, _, value = line.partition(":")
            if key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"):
                status[key] = value.strip()
    return {"argv": argv, "uid": os.getresuid(), "gid": os.getresgid(), "fds": fds, "status": status,
            "env": sorted(os.environ)}
