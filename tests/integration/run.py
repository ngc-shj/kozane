"""Builds a dev deployment and exercises it end to end (plan C18).

Usage: run.py            (from `make test`)

Generates fresh keys with tools/mksecrets into a temporary directory
(removed on every exit path), builds the image against that configuration
and packages it, then re-runs itself inside `unshare -rn` (no NET_ADMIN in
the container; architecture R5) for six boots:

  1. raw frames: the outside NIC on a `-netdev dgram` socket; ARP, one frame
     per wire::DropReason, a coalesced flood, ARP as the liveness barrier;
  2. WireGuard: the outside NIC on user-net with hostfwds to 51820 and the
     Rosenpass port, the inside NIC on a dgram socket played by a Python
     inside host; wireguard-go is the interop oracle, tests/integration/wg.py
     sends what wireguard-go will not. Every negative case asserts a
     positive audit line and then a liveness barrier (a ping through
     wireguard-go). Also the M3 cases: the MCE-COST quiet window, L8 pair,
     expiry, rotation, pq->hs link residue, and a reboot (system_reset);
  3. cookie-a and 4. cookie-b (M2.5 plan C6), each a fresh boot so audit
     totals start at zero: the outside NIC on a tap in the netns, which
     plays the router (10.0.2.2) for Python sockets and wireguard-go and
     carries spoofed frames injected with AF_PACKET. cookie-a runs the
     Rosenpass 0.2.3 interop and mac/bucket pairs, the passive keepalive
     case, then the paired cookie case under a below-capacity flood;
     cookie-b the cookie-under-flood case;
  5. peer binding (M3 plan C7): a deployment whose peer records pair each
     WireGuard key with the other peer's Rosenpass key;
  6. a blob whose public key does not match the configuration: `key`
     prints the mismatch and halts.

Since M3 (L8) hs refuses every WireGuard initiation without a fresh
Rosenpass PSK, so each WireGuard peer first runs upstream rosenpass (the VE9
oracle in the dev image) and its key_out is the PresharedKey. Boots 1 and 6
run no Rosenpass.

Missing prerequisites fail the run; nothing is skipped.
"""

import base64
import bisect
import contextlib
import ctypes
import errno
import hashlib
import json
import math
import os
import re
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tomllib

import pexpect

BOOT_TIMEOUT_S = 60
REPLY_TIMEOUT_S = 5
LINE_TIMEOUT_S = 10

GW_MAC = bytes.fromhex("525400123456")
GW_IP = bytes([10, 0, 2, 15])
PEER_MAC = bytes.fromhex("52550a000202")
PEER_IP = bytes([10, 0, 2, 2])
WG_PORT = 51820
INSIDE_MAC = bytes.fromhex("525400123457")
INSIDE_IP = bytes([10, 99, 0, 1])
HOST_MAC = bytes.fromhex("0200000099" "02")
HOST_IP = bytes([10, 99, 0, 2])
BCAST = b"\xff" * 6

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))


class Fail(Exception):
    pass


# ---------------------------------------------------------------- frames


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def eth(dst: bytes, src: bytes, ethertype: int, body: bytes) -> bytes:
    return dst + src + struct.pack("!H", ethertype) + body


def arp(op: int, sha: bytes, spa: bytes, tha: bytes, tpa: bytes, dst=BCAST) -> bytes:
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + sha + spa + tha + tpa
    return eth(dst, sha, 0x0806, body)


def ipv4_udp(src_ip, dst_ip, sport, dport, payload, dst_mac=GW_MAC, src_mac=PEER_MAC) -> bytes:
    udp_len = 8 + len(payload)
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 17, udp_len)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload
    c = csum(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", c) + udp[8:]
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, 20 + udp_len, 0, 0x4000, 64, 17, 0) + src_ip + dst_ip
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return eth(dst_mac, src_mac, 0x0800, hdr + udp)


def fix_ip_csum(f: bytearray) -> bytearray:
    f[24:26] = b"\0\0"
    f[24:26] = struct.pack("!H", csum(bytes(f[14:34])))
    return f


def udp_frame(payload=b"abcd") -> bytearray:
    return bytearray(ipv4_udp(PEER_IP, GW_IP, 40000, WG_PORT, payload))


def frame_for(reason: str) -> bytes:
    """One frame per wire::DropReason (mirrors crates/wire tests::frame_for)."""
    f = udp_frame()
    if reason == "TooShort":
        return bytes(f[:13])
    if reason == "TooLong":
        return bytes(f + b"\0" * (1515 - len(f)))
    if reason == "EthBadSrc":
        f[6] |= 1
    elif reason == "UnknownEtherType":
        f[12] = 0x86
    elif reason == "ArpMalformed":
        f = bytearray(arp(1, PEER_MAC, PEER_IP, b"\0" * 6, GW_IP))
        f[14 + 7] = 3
    elif reason == "ArpBadSender":
        f = bytearray(arp(1, PEER_MAC, PEER_IP, b"\0" * 6, GW_IP))
        f[14 + 8] |= 1
    elif reason == "Ipv4Version":
        f[14] = 0x65
    elif reason == "Ipv4Options":
        f[14] = 0x46
    elif reason == "Ipv4Fragment":
        f[14 + 6] = 0x20
    elif reason == "Ipv4BadLength":
        f[14 + 2] = 0x10
    elif reason == "Ipv4BadChecksum":
        f[14 + 8] ^= 1
    elif reason == "Ipv4BadSrc":
        f[14 + 12] = 224
        fix_ip_csum(f)
    elif reason == "NotUdp":
        f[14 + 9] = 6
        fix_ip_csum(f)
    elif reason == "UdpBadLength":
        f[14 + 20 + 5] -= 1
    elif reason == "UdpBadChecksum":
        f[-1] ^= 1
    else:
        raise Fail(f"no frame for {reason}")
    return bytes(f)


# Must list every wire::DropReason; checked against the Rust source below.
DROP_REASONS = [
    "TooShort", "TooLong", "EthBadSrc", "UnknownEtherType", "ArpMalformed",
    "ArpBadSender", "Ipv4Version", "Ipv4Options", "Ipv4Fragment", "Ipv4BadLength",
    "Ipv4BadChecksum", "Ipv4BadSrc", "NotUdp", "UdpBadLength", "UdpBadChecksum",
]
# Produced by forwarding (wire::forward_ipv4), not by any outside frame.
FORWARD_ONLY = ["TtlExpired"]


def check_reason_list_matches_rust():
    src = open(os.path.join(os.path.dirname(__file__), "../../crates/wire/src/lib.rs")).read()
    block = src[src.index("pub enum DropReason {"):]
    block = block[: block.index("}")]
    rust = re.findall(r"^\s+(\w+) = \d+,", block, re.M)
    if rust != DROP_REASONS + FORWARD_ONLY:
        raise Fail(f"DROP_REASONS out of sync with wire: {rust}")
    # The enum and DropReason::ALL are two lists since M4 (C5) took away the
    # macro that declared both; a variant missing from ALL is invisible to
    # the audit PD's decoder.
    all_block = src[src.index("pub const ALL: &'static [DropReason] = &["):]
    all_block = all_block[: all_block.index("];")]
    listed = re.findall(r"DropReason::(\w+),", all_block)
    if listed != rust:
        raise Fail(f"DropReason::ALL out of sync with the enum: {listed}")


# ---------------------------------------------------------------- harness


# QEMU's serial console ends lines with "\r\r\n".
READY_LINE = re.compile(r"(eth_out|eth_in|ingress|inner|data|hs|audit|pq): ready\r*\n")


def start_without_stop_signals(thread: threading.Thread):
    """Starts a helper thread with the stop signals blocked; it inherits the
    mask, so process-directed signals reach only the main thread, where
    `signals_held` can hold them during a teardown."""
    old = signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
    try:
        thread.start()
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old)


def guard_thread_starts():
    """From here on, starting a thread through `threading` while the stop
    signals are unblocked raises: such a thread would let a stop signal
    through mid-teardown (F-R5-1). Checked at start time; a thread target
    that unblocks signals itself, or raw `_thread`, is not covered (none do)."""
    original = threading.Thread.start

    def start(self):
        if not STOP_SIGNALS <= signal.pthread_sigmask(signal.SIG_BLOCK, set()):
            raise RuntimeError("thread started with stop signals unblocked; use start_without_stop_signals")
        original(self)

    threading.Thread.start = start


class Console:
    """QEMU serial output, drained by a thread so QEMU never blocks on a
    full pty. Waits search the text after a cursor."""

    def __init__(self, child: pexpect.spawn):
        self.child = child
        self.text = ""
        # Arrival time of each chunk, by the text length after it.
        self.ends = []
        self.times = []
        self.lock = threading.Lock()
        self.alive = True
        start_without_stop_signals(threading.Thread(target=self._drain, daemon=True))

    def _drain(self):
        while self.alive:
            try:
                s = self.child.read_nonblocking(4096, timeout=0.2)
            except pexpect.TIMEOUT:
                continue
            except (pexpect.EOF, OSError, ValueError):
                self.alive = False
                return
            sys.stdout.write(s)
            sys.stdout.flush()
            with self.lock:
                self.text += s
                self.ends.append(len(self.text))
                self.times.append(time.monotonic())

    def mark(self) -> int:
        with self.lock:
            return len(self.text)

    def wait_for(self, pattern: str, since: int = 0, timeout: float = LINE_TIMEOUT_S,
                 strip_ready: bool = False) -> re.Match:
        """`strip_ready` removes other PDs' "<pd>: ready" lines first: during
        boot a PD that exhausts its budget mid-line is preempted, and another
        PD's line lands inside it (characters are printed one by one). The
        match's offsets index the searched copy, not `self.text`."""
        rx = re.compile(pattern)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                text = self.text[since:]
            if strip_ready:
                # Keep the ready line being waited for.
                text = READY_LINE.sub(lambda r: r.group(0) if f"{r.group(1)}: ready" in pattern else "", text)
            m = rx.search(text)
            if m:
                return m
            if not self.alive:
                raise Fail(f"QEMU exited while waiting for {pattern!r}")
            time.sleep(0.05)
        raise Fail(f"timed out waiting for {pattern!r}")

    def count(self, pattern: str, since: int = 0) -> list:
        with self.lock:
            return re.findall(pattern, self.text[since:])

    def time_at(self, offset: int) -> float:
        """When the text up to `offset` had been read (monotonic)."""
        with self.lock:
            i = bisect.bisect_left(self.ends, offset)
            if i == len(self.ends):
                raise Fail(f"console offset {offset} not read yet")
            return self.times[i]


_handed_out = set()


def free_udp_port() -> int:
    """A currently free port never handed out before in this run (a port
    released by bind/close can be offered again by the next call)."""
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        if port not in _handed_out:
            _handed_out.add(port)
            return port


def boot(loader: str, outside: str, inside: str, monitor: str = "") -> tuple:
    cmd = [
        "-machine", "virt,virtualization=on", "-cpu", "neoverse-n2", "-m", "size=2G",
        "-serial", "mon:stdio", "-nographic",
        "-device", f"loader,file={loader},addr=0x70000000,cpu-num=0",
        "-device", f"virtio-net-device,netdev=n0,mac={GW_MAC.hex(':')},bus=virtio-mmio-bus.31",
        "-netdev", outside,
        "-device", f"virtio-net-device,netdev=n1,mac={INSIDE_MAC.hex(':')},bus=virtio-mmio-bus.23",
        "-netdev", inside,
    ]
    if monitor:
        cmd += ["-monitor", f"unix:{monitor},server,nowait"]
    # pexpect makes the child a session leader, so kill() takes the group.
    child = pexpect.spawn(DIE_WITH_PARENT[0], DIE_WITH_PARENT[1:] + ["qemu-system-aarch64"] + cmd,
                          encoding="utf-8", timeout=BOOT_TIMEOUT_S)
    return child, Console(child)


def kill(child: pexpect.spawn):
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.close(force=True)


class Monitor:
    """QEMU human monitor over a unix socket (physical memory reads)."""

    def __init__(self, path: str):
        deadline = time.monotonic() + 10
        while True:
            try:
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(path)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise Fail("QEMU monitor socket did not appear")
                time.sleep(0.05)
        self.sock.settimeout(LINE_TIMEOUT_S)
        self._read_until(b"(qemu) ")

    def _read_until(self, marker: bytes) -> bytes:
        buf = b""
        while not buf.endswith(marker):
            chunk = self.sock.recv(4096)
            if not chunk:
                raise Fail("QEMU monitor closed")
            buf += chunk
        return buf

    def command(self, line: str) -> str:
        self.sock.sendall(f"{line}\n".encode())
        return self._read_until(b"(qemu) ").decode(errors="replace")

    def pmem(self, addr: int, size: int, path: str) -> bytes:
        # HMP parses an unquoted absolute path as part of the preceding
        # integer expression (`/tmp/...` starts with division). JSON string
        # quoting is accepted by HMP and also handles unusual path bytes.
        # A stale snapshot from an earlier call must never be read back.
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        # The dump holds guest RAM, secrets region included: it is removed on
        # every path, the monitor I/O's failures too (M3b plan T4).
        # A full-RAM dump takes longer than a monitor line.
        self.sock.settimeout(max(LINE_TIMEOUT_S, size >> 26))
        try:
            self.sock.sendall(f"pmemsave {addr:#x} {size:#x} {json.dumps(path)}\n".encode())
            reply = self._read_until(b"(qemu) ")
            if not os.path.exists(path):
                detail = reply.decode(errors="replace").strip()
                raise Fail(f"pmemsave did not create {path}: {detail}")
            with open(path, "rb") as f:
                data = f.read()
        finally:
            self.sock.settimeout(LINE_TIMEOUT_S)
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)
        if len(data) != size:
            raise Fail(f"pmemsave returned {len(data)} of {size} bytes")
        return data


# Guest RAM scanned for residue. Which frames back which region at run time
# is not knowable from the Microkit report, so the whole window is read and
# a positive control (a session key that data or hs memory must hold) proves
# it covers PD memory.
OBJECT_RAM = (0x6000_0000, 0x0200_0000)


def wait_absent(mon: Monitor, needle: bytes, control: bytes, scratch: str, timeout: float = 5.0,
                what: str = "install message", control_what: str = "live session key"):
    """Polls until `needle` occurs nowhere in OBJECT_RAM while `control`
    does, in the same snapshot (bounded: the 1 Hz timer retries the reclaim
    if a wakeup was missed). A missing control fails: the scan would prove
    nothing."""
    base, size = OBJECT_RAM
    deadline = time.monotonic() + timeout
    while True:
        ram = mon.pmem(base, size, scratch)
        if ram.find(control) < 0:
            raise Fail(f"scan window does not cover PD memory: {control_what} not found")
        at = ram.find(needle)
        if at < 0:
            return
        if time.monotonic() > deadline:
            raise Fail(f"{what} still in guest RAM at {base + at:#x}")
        time.sleep(0.2)


# All of guest RAM (`-m size=2G` from the virt machine's RAM base), for the
# OSK residue scan (M3b plan C7, VE12).
GUEST_RAM = (0x4000_0000, 0x8000_0000)


def scan_absent(mon: Monitor, needle: bytes, control: bytes, scratch: str, what: str, control_what: str):
    """`needle` occurs nowhere in all of guest RAM while `control` does, in
    one snapshot; one retry after hs's 1 Hz tick. Prints how often the
    control occurs (recorded, not asserted: a copy outside hs's table is a
    finding to fix, M3b T7)."""
    base, size = GUEST_RAM
    for attempt in range(2):
        ram = mon.pmem(base, size, scratch)
        copies = ram.count(control)
        if copies == 0:
            raise Fail(f"guest RAM scan: {control_what} not found; the scan proves nothing")
        at = ram.find(needle)
        del ram
        if at < 0:
            print(f"\nguest RAM scan: {control_what} occurs {copies} time(s)", flush=True)
            return
        if attempt == 0:
            time.sleep(1.5)
    raise Fail(f"{what} still in guest RAM at {base + at:#x}")


def install_len_from_rust() -> int:
    src = open(os.path.join(ROOT, "crates/msgs/src/lib.rs")).read()
    m = re.search(r"pub const INSTALL_LEN: usize = ([0-9 +]+);", src)
    if not m:
        raise Fail("INSTALL_LEN not found in crates/msgs/src/lib.rs")
    return sum(int(x) for x in m.group(1).split("+"))


def pack_install(peer: int, local: int, remote: int, send: bytes, recv: bytes) -> bytes:
    return struct.pack("<HII", peer, local, remote) + send + recv


def check_install_layout_matches_rust():
    """The needle's packing must equal msgs::Install::encode on the golden
    inputs of crates/msgs/src/tests.rs, not merely have its length."""
    src = open(os.path.join(ROOT, "crates/msgs/src/tests.rs")).read()
    m = re.search(r'INSTALL_GOLDEN_HEX: &str = "([0-9a-f]+)"', src)
    if not m:
        raise Fail("INSTALL_GOLDEN_HEX not found in crates/msgs/src/tests.rs")
    mine = pack_install(0x0102, 0x03040506, 0x0708090A, b"\x11" * 32, b"\x22" * 32)
    if mine.hex() != m.group(1):
        raise Fail("install layout in run.py differs from msgs::Install::encode")


def install_bytes(peer: int, i) -> bytes:
    """The `msgs::Install` hs sent for initiator `i`'s session: our index is
    the receiver of its transport packets, its sender index is our remote,
    and our send/recv keys are its recv/send keys."""
    check_install_layout_matches_rust()
    b = pack_install(peer, i.receiver, i.sender, i.recv_key, i.send_key)
    if len(b) != install_len_from_rust():
        raise Fail(f"install layout drifted: {len(b)} bytes vs msgs::INSTALL_LEN")
    return b


def psk_install_bytes(peer: int, osk: bytes) -> bytes:
    """The `msgs::PskInstall` pq sent hs for `peer`: the peer index, then the
    OSK (the client's key_out)."""
    src = open(os.path.join(ROOT, "crates/msgs/src/lib.rs")).read()
    # Since M4 (C3) encode is verified against this spec function, so the
    # spec's body is the layout to compare with.
    if "pub open spec fn spec_encode_psk_install(peer: u16, osk: Seq<u8>) -> Seq<u8>\n" \
            "    recommends\n        osk.len() == 32,\n{\n    u16_to_le(peer) + osk\n}" not in src:
        raise Fail("PskInstall::encode in crates/msgs/src/lib.rs no longer writes peer then osk")
    m = re.search(r"pub const PSK_INSTALL_LEN: usize = ([0-9 +]+);", src)
    b = struct.pack("<H", peer) + osk
    if not m or len(b) != sum(int(x) for x in m.group(1).split("+")):
        raise Fail("PskInstall layout drifted from msgs::PSK_INSTALL_LEN")
    return b


def dgram(name: str, local: int, remote: int) -> str:
    return (f"dgram,id={name},local.type=inet,local.host=127.0.0.1,local.port={local},"
            f"remote.type=inet,remote.host=127.0.0.1,remote.port={remote}")


class Wire:
    """Host end of a dgram netdev."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        _handed_out.add(self.port)  # held open; never offered to QEMU
        self.qemu_port = free_udp_port()
        self.sock.settimeout(REPLY_TIMEOUT_S)

    def netdev(self, name: str) -> str:
        return dgram(name, self.qemu_port, self.port)

    def send(self, frame: bytes):
        self.sock.sendto(frame, ("127.0.0.1", self.qemu_port))

    def recv_matching(self, pred, timeout=REPLY_TIMEOUT_S) -> bytes:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.sock.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                data, _ = self.sock.recvfrom(2048)
            except socket.timeout:
                break
            if pred(data):
                return data
        raise Fail("no matching reply")


# ---------------------------------------------------------------- boot 1


def is_arp_reply(d: bytes) -> bool:
    return d[12:14] == b"\x08\x06" and d[20:22] == b"\x00\x02"


def arp_roundtrip(w: Wire, timeout=REPLY_TIMEOUT_S):
    """ARP request for our IP -> the exact reply (also the liveness barrier:
    rings are FIFO, so the reply proves everything sent before was handled)."""
    w.send(arp(1, PEER_MAC, PEER_IP, b"\0" * 6, GW_IP))
    r = w.recv_matching(is_arp_reply, timeout)
    if r[:42] != arp(2, GW_MAC, GW_IP, PEER_MAC, PEER_IP, dst=PEER_MAC):
        raise Fail(f"bad ARP reply {r.hex()}")


def wait_arp_ready(w: Wire, con: Console):
    deadline = time.monotonic() + BOOT_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            arp_roundtrip(w, timeout=1)
            return
        except Fail:
            if not con.alive:
                raise Fail("QEMU exited during boot")
    raise Fail("no ARP reply after boot")


FLOOD_BATCH = 32


def test_raw(loader: str):
    w = Wire()
    child, con = boot(loader, w.netdev("n0"), dgram("n1", free_udp_port(), free_udp_port()))
    try:
        wait_arp_ready(w, con)
        con.wait_for(r"audit: src=ingress ArpReplied total=1 lost=0")
        for reason in DROP_REASONS:
            w.send(frame_for(reason))
            con.wait_for(rf"audit: src=ingress FrameDropped\({reason}\) total=1 lost=0")
        # Non-WireGuard UDP on the listen port is not a WireGuard message.
        w.send(ipv4_udp(PEER_IP, GW_IP, 40000, WG_PORT, b"hello"))
        con.wait_for(r"audit: src=ingress WgBadMessage total=1 lost=0")
        flood(w, con, "Ipv4BadChecksum", k=640)
        arp_roundtrip(w)
    finally:
        try:
            with signals_held():
                kill(child)
        except SystemExit:
            kill(child)
            raise


def flood(w: Wire, con: Console, reason: str, k: int):
    """k more frames of one reason in batches, each followed by an ARP round
    trip (FIFO rings: the reply proves the batch was consumed). Then exactly
    the coalesced lines 65, 129, ... with lost == 0."""
    mark = con.mark()
    frame = frame_for(reason)
    for start in range(0, k, FLOOD_BATCH):
        for _ in range(min(FLOOD_BATCH, k - start)):
            w.send(frame)
        arp_roundtrip(w)
    want = list(range(65, k + 2, 64))
    con.wait_for(rf"FrameDropped\({reason}\) total={want[-1]} ", since=mark)
    got = con.count(rf"audit: src=ingress FrameDropped\({reason}\) total=(\d+) lost=(\d+)", since=mark)
    if [int(t) for t, _ in got] != want or any(int(l) for _, l in got):
        raise Fail(f"flood lines {got}, want totals {want} lost=0")


# ---------------------------------------------------------------- boot 2


def ip_hdr(src: bytes, dst: bytes, proto: int, payload_len: int) -> bytes:
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, 20 + payload_len, 0, 0x4000, 64, proto, 0) + src + dst
    return hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]


def icmp_echo(src: bytes, dst: bytes, kind: int, ident: int, seq: int, data: bytes) -> bytes:
    icmp = struct.pack("!BBHHH", kind, 0, 0, ident, seq) + data
    icmp = icmp[:2] + struct.pack("!H", csum(icmp)) + icmp[4:]
    return ip_hdr(src, dst, 1, len(icmp)) + icmp


class InsideHost(threading.Thread):
    """10.99.0.2 on the inside NIC: answers ICMP echo from the tunnel and
    records every IPv4 datagram it receives."""

    def __init__(self, w: Wire):
        super().__init__(daemon=True)
        self.w = w
        self.received = []
        self.stop = False

    def run(self):
        self.w.sock.settimeout(0.2)
        while not self.stop:
            try:
                f, _ = self.w.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(f) < 34 or f[12:14] != b"\x08\x00" or f[:6] != HOST_MAC:
                continue
            ip = f[14:]
            self.received.append(ip)
            if ip[9] == 1 and ip[20] == 8 and ip[16:20] == HOST_IP:
                ident, seq = struct.unpack("!HH", ip[24:28])
                reply = icmp_echo(HOST_IP, ip[12:16], 0, ident, seq, ip[28:])
                self.w.send(eth(INSIDE_MAC, HOST_MAC, 0x0800, reply))


def b64(s: str) -> bytes:
    return base64.b64decode(s)


def conf_value(text: str, key: str) -> str:
    return re.search(rf"^{key} = (\S+)$", text, re.M).group(1)


def sh(*args, **kw):
    return subprocess.run(list(args), check=True, capture_output=True, text=True, **kw)


class WgGo:
    """wireguard-go in the test netns. Its UAPI socket directory is shared
    by every netns in the container, so the interface name is per run.
    Its PresharedKey is the Rosenpass OSK: a watcher applies each new
    key_out of `rp` with `wg set … preshared-key` (M3 plan C7)."""

    def __init__(self, conf: str, address: str, inside_prefix: str, rp: "Rosenpass"):
        self.inside_prefix = inside_prefix
        self.rp = rp
        self.gw_pub = conf_value(open(conf).read(), "PublicKey")
        self.psk_file = os.path.join(os.path.dirname(conf), "wg-go.psk")
        self.applied = None
        self.error = None
        self.stopped = False
        self.watcher = None
        self.dev = dev = f"wgt{os.getpid() % 100000}"
        self.proc = subprocess.Popen(DIE_WITH_PARENT + ["wireguard-go", "-f", dev], stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, env={**os.environ, "LOG_LEVEL": "error"})
        try:
            self._configure(conf, address)
            self.watcher = threading.Thread(target=self._watch, daemon=True)
            start_without_stop_signals(self.watcher)
        except BaseException:
            self.close()
            raise

    def _configure(self, conf: str, address: str):
        dev = self.dev
        deadline = time.monotonic() + 10
        while subprocess.run(["ip", "link", "show", dev], capture_output=True).returncode:
            if time.monotonic() > deadline or self.proc.poll() is not None:
                raise Fail(f"wireguard-go did not create {dev}")
            time.sleep(0.05)
        sh("wg", "setconf", dev, conf)
        psk = self.rp.osk()
        if psk is None:
            raise Fail("wireguard-go started before its rosenpass wrote key_out")
        self._set_psk(psk)
        sh("ip", "addr", "add", address, "dev", dev)
        sh("ip", "link", "set", dev, "up")
        sh("ip", "route", "add", self.inside_prefix, "dev", dev)

    def _set_psk(self, psk: bytes):
        # A copy of the validated key: key_out itself may be mid-rewrite.
        with open(os.open(self.psk_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.write(base64.b64encode(psk).decode())
        sh("wg", "set", self.dev, "peer", self.gw_pub, "preshared-key", self.psk_file)
        self.applied = psk

    def _watch(self):
        while not self.stopped:
            psk = self.rp.osk()
            if psk is not None and psk != self.applied:
                try:
                    self._set_psk(psk)
                except (subprocess.CalledProcessError, OSError) as e:
                    self.error = e
                    return
            time.sleep(0.2)

    def wait_applied(self, psk: bytes, timeout: float = 5.0):
        deadline = time.monotonic() + timeout
        while self.applied != psk:
            if self.error is not None:
                raise Fail(f"key_out watcher failed: {self.error}")
            if time.monotonic() > deadline:
                raise Fail("key_out watcher did not apply the new key to wireguard-go")
            time.sleep(0.1)
        shown = sh("wg", "show", self.dev, "preshared-keys").stdout.split()
        if len(shown) < 2 or b64(shown[1]) != psk:
            raise Fail("wireguard-go's preshared key differs from key_out")

    def latest_handshake(self) -> int:
        out = sh("wg", "show", self.dev, "latest-handshakes").stdout.split()
        return int(out[1]) if len(out) >= 2 else 0

    def close(self):
        self.stopped = True
        if self.watcher is not None:
            self.watcher.join(timeout=5)
        self.proc.kill()
        self.proc.wait()
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.psk_file)
        subprocess.run(["ip", "link", "del", self.dev], capture_output=True)
        # The socket outlives a killed daemon.
        try:
            os.unlink(f"/var/run/wireguard/{self.dev}.sock")
        except FileNotFoundError:
            pass


def ping(tries: int) -> None:
    for _ in range(tries):
        if subprocess.run(["ping", "-c", "1", "-W", "2", "10.99.0.2"], capture_output=True).returncode == 0:
            return
    raise Fail("no ping reply through the tunnel")


# ---------------------------------------------------------------- rosenpass (M3 plan C7)

RP_PORT = 51819
RP_MASTER = "/opt/rosenpass-master/rosenpass"
RP_023 = "/opt/rosenpass-023/rosenpass"
PQKEY_CORE = "crates/pqkey-core/src/lib.rs"
# A client's start until its PSK is installed at hs. On TCG at pq's budget
# one InitHello costs about 8 s (MCE-COST), and ingress also admits the
# client's early retransmissions, which pq answers in turn before it reaches
# the InitConf: about 45 s measured for one client. The rest covers another
# client's exchange queued in front of it.
RP_EXCHANGE_S = 240.0
PSK_RETRY_S = 2.0              # between Python-peer handshakes waiting for an install
COST_SLACK = 0.25              # quiet window: high-water <= PQ_HANDSHAKE_COST_NS x (1 + this)
EXPIRY_ALLOW_S = 10.0          # expiry allow side: this long before REJECT_AFTER_TIME
EXPIRY_SLACK_S = 5.0           # expiry stale side: hs's 1 Hz tick plus scheduling
ROTATION_PING_LOSS = 2         # pings lost while the client's rosenpass restarts
ROTATION_RESTARTS = 4           # rotation: restarts tried to find a provably-Live pair
PING_LOOP_S = 1.0
RP_RESET_TRIES = 10            # reboot: replays of the capture until hs has booted
PEER2_IP = bytes([10, 200, 0, 4])


class Rosenpass:
    """Upstream rosenpass as peer `peer`'s initiator, run from the bundle
    mksecrets wrote, aimed at `endpoint`. A start removes the old key_out,
    so every key read afterwards comes from this run."""

    def __init__(self, deploy: str, peer: int, endpoint: str, binary: str = RP_MASTER, listen_port: int = 0):
        self.deploy, self.peer, self.binary = deploy, peer, binary
        self.listen_port = listen_port
        self.key_out = os.path.join(deploy, f"peer-{peer}.osk")
        text = open(os.path.join(deploy, f"peer-{peer}.rosenpass.toml")).read()
        text, n = re.subn(r'^endpoint = ".*"$', f'endpoint = "{endpoint}"', text, flags=re.M)
        if n != 1:
            raise Fail(f"peer-{peer}.rosenpass.toml: expected one endpoint line, found {n}")
        if listen_port:
            # A fixed source port, so the gateway sees one endpoint for this
            # client across restarts (the cookie and proven state are per
            # endpoint, M3b).
            text, n = re.subn(r"^listen = \[\]$", f'listen = ["{ip_str(PEER_IP)}:{listen_port}"]', text, flags=re.M)
            if n != 1:
                raise Fail(f"peer-{peer}.rosenpass.toml: expected one empty listen line, found {n}")
        self.conf = os.path.join(deploy, f"rp-{peer}.toml")
        with open(os.open(self.conf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.write(text)
        self.proc = None
        self.start()

    def start(self):
        self.stop()
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.key_out)
        # The bundle's paths are relative to its directory.
        self.proc = subprocess.Popen(DIE_WITH_PARENT + [self.binary, "exchange-config", self.conf], cwd=self.deploy,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def osk(self):
        """The current key_out, or None (not written yet, or mid-write)."""
        try:
            text = open(self.key_out).read().strip()
            key = base64.b64decode(text, validate=True)
        except (FileNotFoundError, ValueError):
            return None
        return key if len(key) == 32 else None

    def written_at(self) -> float:
        """key_out's mtime on the monotonic clock. The client writes it on the
        RespHello, before its InitConf: no later than pq's install."""
        return time.monotonic() - (time.time() - os.stat(self.key_out).st_mtime)

    def wait_key(self, deadline: float, other_than=None) -> bytes:
        while True:
            key = self.osk()
            if key is not None and key != other_than:
                return key
            if self.proc.poll() is not None:
                raise Fail(f"rosenpass for peer {self.peer} exited with {self.proc.returncode}")
            if time.monotonic() > deadline:
                raise Fail(f"rosenpass for peer {self.peer}: no new key_out within {RP_EXCHANGE_S:.0f} s")
            time.sleep(0.1)

    def stop(self):
        if self.proc is not None:
            self.proc.kill()
            self.proc.wait()
            self.proc = None

    close = stop


def exported(con: Console, rp: Rosenpass, since: int, what: str = "") -> bytes:
    """Waits for `rp`'s key_out and the boot's first RpPskExported (later
    ones coalesce, so only a boot's first export is ever printed)."""
    deadline = time.monotonic() + RP_EXCHANGE_S
    try:
        key = rp.wait_key(deadline)
        con.wait_for(r"audit: src=pq RpPskExported total=1 ", since=since,
                     timeout=max(0.0, deadline - time.monotonic()))
    except Fail as e:
        raise Fail(f"{what}{e}") from e
    return key


def check_quiet_cost(con: Console, start: int, end: int):
    """MCE-COST quiet window [R4-T-Q3, R5-T-R3]: the last RpCostHighWater
    emitted in [start, end) against PQ_HANDSHAKE_COST_NS plus COST_SLACK;
    none emitted in it fails."""
    with con.lock:
        text = con.text[start:end]
    costs = [int(us) for us in re.findall(r"audit: src=pq RpCostHighWater us=(\d+) ", text)]
    if not costs:
        raise Fail("MCE-COST: no RpCostHighWater in the quiet window")
    limit_us = rust_const(PQKEY_CORE, "PQ_HANDSHAKE_COST_NS") / 1000 * (1 + COST_SLACK)
    print(f"\nMCE-COST quiet window: RpCostHighWater {costs} us, limit {limit_us:.0f} us", flush=True)
    if costs[-1] > limit_us:
        raise Fail(f"MCE-COST: handshake cost {costs[-1]} us above PQ_HANDSHAKE_COST_NS plus "
                   f"{COST_SLACK:.0%} ({limit_us:.0f} us)")


def wait_response(sock: socket.socket, i, timeout: float):
    """The next handshake response to initiator `i` on `sock` before
    `timeout`, or None; datagrams for earlier initiators are skipped."""
    until = time.monotonic() + timeout
    while (left := until - time.monotonic()) > 0:
        sock.settimeout(left)
        try:
            d = sock.recv(2048)
        except socket.timeout:
            return None
        if len(d) == 92 and d[0] == 2 and struct.unpack("<I", d[8:12])[0] == i.sender:
            return d
    return None


class Pinger(threading.Thread):
    """Pings the inside host through wireguard-go once per PING_LOOP_S,
    counting the misses."""

    def __init__(self):
        super().__init__(daemon=True)
        self.sent = self.lost = 0
        self.stop = False

    def run(self):
        while not self.stop:
            t = time.monotonic()
            ok = subprocess.run(["ping", "-c", "1", "-W", "1", "10.99.0.2"], capture_output=True).returncode == 0
            self.sent += 1
            self.lost += not ok
            time.sleep(max(0.0, t + PING_LOOP_S - time.monotonic()))


def test_wireguard(loader: str, deploy: str, passed: list):
    inside = Wire()
    hostfwd = free_udp_port()
    rp_fwd = free_udp_port()
    host = InsideHost(inside)
    monitor = os.path.join(deploy, "monitor.sock")
    child, con = boot(loader, f"user,id=n0,net=10.0.2.0/24,hostfwd=udp:127.0.0.1:{hostfwd}-:{WG_PORT},"
                              f"hostfwd=udp:127.0.0.1:{rp_fwd}-:{RP_PORT}", inside.netdev("n1"), monitor)
    wg = None
    rps = []
    threads = []
    out = None
    try:
        start_without_stop_signals(host)
        mon = Monitor(monitor)
        scratch = os.path.join(deploy, "pmem.bin")
        cfg = tomllib.load(open(os.path.join(deploy, "gateway.toml"), "rb"))
        gw_pub = b64(cfg["gateway"]["public_key"])
        peer0 = open(os.path.join(deploy, "peer-0.conf")).read()
        peer1 = open(os.path.join(deploy, "peer-1.conf")).read()
        conf0 = os.path.join(deploy, "wg0.conf")
        with open(conf0, "w") as f:
            f.write(re.sub(r"^Endpoint = .*$", f"Endpoint = 127.0.0.1:{hostfwd}", peer0, flags=re.M))
        os.chmod(conf0, 0o600)
        rp_endpoint = f"127.0.0.1:{rp_fwd}"
        reject_s = rust_const(WG_CORE, "REJECT_AFTER_TIME_NS") / NS

        # Prelude: peer 0's Rosenpass exchange, the only traffic until its
        # export, which makes it the MCE-COST quiet window. Peer 1 is exempt:
        # it is the L8 pair's.
        con.wait_for(r"pq: ready", timeout=BOOT_TIMEOUT_S, strip_ready=True)
        prelude = con.mark()
        rp0 = Rosenpass(deploy, 0, rp_endpoint)
        rps.append(rp0)
        osk0 = exported(con, rp0, prelude, "prelude: ")
        check_quiet_cost(con, prelude, con.mark())
        passed.append("MCE-COST quiet window")
        print("\nPASS [MCE-COST: the prelude's handshake cost is within PQ_HANDSHAKE_COST_NS]")

        # Case 1: wireguard-go handshakes with key_out as its PSK (the first
        # ping triggers it; it retries every 5 s).
        wg = WgGo(conf0, "10.200.0.2/32", cfg["gateway"]["inside_prefix"], rp0)
        ping(tries=30)
        first = wg.latest_handshake()
        if not first:
            raise Fail("wg show reports no handshake")
        con.wait_for(r"audit: src=hs HandshakeOk total=1 ")
        con.wait_for(r"audit: src=data SessionPromoted total=1 ")
        # A routed hop: wireguard-go's echo request (TTL 64) reaches the
        # inside host with TTL 63.
        requests = [ip for ip in host.received if ip[9] == 1 and ip[20] == 8]
        if not requests or any(ip[8] != 63 for ip in requests):
            raise Fail(f"echo requests arrived with TTLs {[ip[8] for ip in requests]}, want 63")
        passed.append("wireguard-go handshake and ping")
        print("\nPASS [wireguard-go handshake and ping]")
        # Interop: hs mixed the OSK pq derived; the session opened with the
        # client's key_out, so the two are equal.
        if wg.applied != osk0:
            raise Fail("wireguard-go's PSK is not the prelude's key_out")
        passed.append("rosenpass interop (master)")
        print("\nPASS [rosenpass master interop: the gateway's OSK is the client's key_out]")

        def initiator(conf: str, psk: bytes, static=None):
            return wg_mod.Initiator(static or b64(conf_value(conf, "PrivateKey")), gw_pub, psk,
                                    sender=secrets.randbits(32))

        out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        out.bind(("127.0.0.1", 0))
        out.settimeout(REPLY_TIMEOUT_S)

        def installed(conf: str, rp: Rosenpass, deadline: float, key: bytes = None) -> tuple:
            """Handshakes with `rp`'s current key_out until the response
            opens: proof that pq's export reached hs (later exports are not
            printed). Returns the initiator and the initiation it sent; the
            initiator's `refused_at` is the send time of the last attempt that
            did not open (None if the first one did), a lower bound on the
            install, since hs handled that attempt without the PSK. With
            `key`, only that PSK is tried."""
            refused_at = None
            while True:
                psk = key if key is not None else rp.osk()
                if psk is not None:
                    i = initiator(conf, psk)
                    msg = i.initiation(ts_offset_s=30)
                    sent = time.monotonic()
                    out.sendto(msg, ("127.0.0.1", hostfwd))
                    # The suite's reply budget, so "no answer" means hs
                    # refused it, not that the answer was slow.
                    r = wait_response(out, i, REPLY_TIMEOUT_S)
                    if r is not None and i.consume_response(r):
                        i.psk_used = psk
                        i.refused_at = refused_at
                        return i, msg
                    refused_at = sent
                if time.monotonic() > deadline:
                    raise Fail(f"peer {rp.peer}: no handshake with its key_out was accepted within {RP_EXCHANGE_S:.0f} s")
                time.sleep(PSK_RETRY_S)

        # Case 2: peer 0's own key with a wrong PSK and a newer timestamp.
        mark = con.mark()
        bad = initiator(peer0, psk=b"\x42" * 32)
        out.sendto(bad.initiation(ts_offset_s=30), ("127.0.0.1", hostfwd))
        resp, _ = out.recvfrom(2048)
        # Allow side first: the same response opens with peer 0's real PSK,
        # so the failure below is the PSK, not a broken response.
        probe = initiator(peer0, rp0.osk())
        probe.c, probe.h, probe.e, probe.sender = bad.c, bad.h, bad.e, bad.sender
        if not probe.consume_response(resp):
            raise Fail("response does not open even with the right PSK")
        if bad.consume_response(resp):
            raise Fail("response opened with a wrong PSK")
        out.sendto(bad.transport(b""), ("127.0.0.1", hostfwd))
        con.wait_for(r"audit: src=data TransportRejected total=1 ", since=mark)
        ping(tries=3)
        if wg.latest_handshake() != first:
            raise Fail("wireguard-go had to re-handshake: the unconfirmed session displaced current")
        passed.append("wrong PSK")
        print("\nPASS [wrong PSK: response unusable, transport rejected, current kept]")

        # Case 3: unknown static key.
        mark = con.mark()
        out.sendto(initiator(peer1, b"\0" * 32, static=secrets.token_bytes(32)).initiation(), ("127.0.0.1", hostfwd))
        con.wait_for(r"audit: src=hs HandshakeUnknownPeer total=1 ", since=mark)
        ping(tries=3)
        passed.append("unknown peer")
        print("\nPASS [unknown peer rejected]")

        # Rotation without interruption. It runs before any case that
        # installs over peer 0's entry (cases 2 and 3 install nothing), and
        # after case 2, whose "no re-handshake" check must stay well inside
        # wireguard-go's REKEY_AFTER_TIME (120 s) of case 1. wireguard-go
        # pings throughout while peer 0's rosenpass restarts; every restart's
        # first key must be accepted by hs, superseding the entry, and the
        # last is applied to wireguard-go. Restarts repeat until one is
        # accepted less than REJECT_AFTER_TIME − slack after the previous
        # one was written: the previous key's install is no earlier than its
        # write and the new one's no later than its acceptance, so the
        # previous entry was provably Live. An hs that ignores supersession
        # refuses a key of that pair (or an earlier one), on every run.
        pinger = Pinger()
        threads.append(pinger)
        start_without_stop_signals(pinger)
        old = rp0.wait_key(time.monotonic() + RP_EXCHANGE_S)
        rotation_mark = con.mark()
        prev_written = None
        for n in range(1, ROTATION_RESTARTS + 1):
            rp0.start()
            new = rp0.wait_key(time.monotonic() + RP_EXCHANGE_S, other_than=old)
            written = rp0.written_at()
            try:
                installed(peer0, rp0, time.monotonic() + RP_EXCHANGE_S, key=new)
            except Fail:
                raise Fail(f"rotation: hs did not accept restart {n}'s first key") from None
            if prev_written is not None and time.monotonic() - prev_written < reject_s - EXPIRY_SLACK_S:
                break
            prev_written, old = written, new
        else:
            raise Fail(f"rotation: no two of {ROTATION_RESTARTS} restarts close enough to prove supersession; precondition broken")
        # A pair beyond REJECT_AFTER_TIME lets peer 0's entry expire between
        # installs, and a wireguard-go rekey in that window spends the boot's
        # one coalesced stale line that the expiry case needs: report it here.
        if con.count(r"audit: src=hs HandshakePskStale total=", since=rotation_mark):
            raise Fail("rotation: peer 0's entry expired between restarts (slow run); precondition broken")
        wg.wait_applied(new)
        pinger.stop = True
        pinger.join()
        print(f"\nrotation: {pinger.lost} of {pinger.sent} pings lost", flush=True)
        if pinger.lost > ROTATION_PING_LOSS or pinger.sent - pinger.lost < 1:
            raise Fail(f"rotation: {pinger.lost} of {pinger.sent} pings lost, budget {ROTATION_PING_LOSS}")
        passed.append("rotation without interruption")
        print("\nPASS [rotation: new OSK accepted and applied, pings kept flowing]")
        # C7: the superseded OSK is gone from all of guest RAM; the new one,
        # accepted just above, is the control.
        scan_absent(mon, old, new, scratch, "superseded OSK", "peer 0's current OSK")
        passed.append("superseded OSK gone from guest RAM")
        print("\nPASS [guest RAM: the superseded OSK occurs nowhere]")

        # L8 pair [T3]: peer 1 has run no Rosenpass, so hs has no PSK for it
        # and refuses (an absent PSK is never a zero one); meanwhile peer 0
        # works; then peer 1 runs Rosenpass and succeeds.
        mark = con.mark()
        nopsk = initiator(peer1, b"\0" * 32)
        out.sendto(nopsk.initiation(ts_offset_s=30), ("127.0.0.1", hostfwd))
        if wait_response(out, nopsk, REPLY_TIMEOUT_S) is not None:
            raise Fail("L8: peer 1 got a handshake response without a Rosenpass PSK")
        con.wait_for(r"audit: src=hs HandshakePskMissing total=1 ", since=mark)
        ping(tries=3)
        rp1 = Rosenpass(deploy, 1, rp_endpoint)
        rps.append(rp1)
        good, _ = installed(peer1, rp1, time.monotonic() + RP_EXCHANGE_S)
        accepted_at = time.monotonic()
        # The install is no earlier than the last refused attempt, nor than
        # key_out (written on RespHello, before the install).
        installed_after = max(good.refused_at or 0.0, rp1.written_at())
        # The install lies in [installed_after, accepted_at]. The allow probe
        # at installed_after + 170 s discriminates a PSK refused up to 10 s
        # early only if that window is narrower than EXPIRY_ALLOW_S.
        if accepted_at - installed_after >= EXPIRY_ALLOW_S:
            raise Fail(f"expiry: install bound {accepted_at - installed_after:.1f} s wide; precondition broken")
        osk1 = good.psk_used
        # No rotation for peer 1 from here: the expiry case below.
        rp1.stop()
        passed.append("L8 pair")
        print("\nPASS [L8 pair: peer 1 refused without a PSK while peer 0 works, accepted after Rosenpass]")

        # Expiry, concurrently with the cases below [R2-T-N9]: accepted near
        # REJECT_AFTER_TIME after the install's lower bound, refused once that
        # long has passed since the accepted handshake (its upper bound). The
        # bounds are PSK_RETRY_S plus one exchange apart.
        expiry = {}

        def expiry_probe():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("127.0.0.1", 0))
                try:
                    allow_at = installed_after + reject_s - EXPIRY_ALLOW_S
                    if time.monotonic() > allow_at:
                        raise Fail("expiry: the allow point passed before the probe started")
                    time.sleep(allow_at - time.monotonic())
                    i = initiator(peer1, osk1)
                    sock.sendto(i.initiation(ts_offset_s=30), ("127.0.0.1", hostfwd))
                    r = wait_response(sock, i, REPLY_TIMEOUT_S)
                    if r is None or not i.consume_response(r):
                        raise Fail(f"expiry: a handshake {reject_s - EXPIRY_ALLOW_S:.0f} s after the install was not accepted")
                    time.sleep(max(0.0, accepted_at + reject_s + EXPIRY_SLACK_S - time.monotonic()))
                    expiry["mark"] = con.mark()
                    i = initiator(peer1, osk1)
                    sock.sendto(i.initiation(ts_offset_s=30), ("127.0.0.1", hostfwd))
                    if wait_response(sock, i, REPLY_TIMEOUT_S) is not None:
                        raise Fail(f"expiry: a handshake {reject_s + EXPIRY_SLACK_S:.0f} s after the install got a response")
                finally:
                    sock.close()
            except (Fail, OSError) as e:
                expiry["error"] = e

        probe_thread = threading.Thread(target=expiry_probe, daemon=True)
        threads.append(probe_thread)
        start_without_stop_signals(probe_thread)

        # Case 4: peer 1 sends a datagram with a source outside its allowed
        # IPs (10.200.0.3/32) through the session it just made.
        mark = con.mark()
        spoofed = icmp_echo(bytes([10, 200, 0, 99]), HOST_IP, 8, 1, 1, b"spoof")
        out.sendto(good.transport(spoofed), ("127.0.0.1", hostfwd))
        con.wait_for(r"audit: src=data SpoofedSource total=1 ", since=mark)
        ping(tries=3)
        if any(ip[12:16] == bytes([10, 200, 0, 99]) for ip in host.received):
            raise Fail("spoofed datagram reached the inside host")
        # The install for peer 1 carried transport keys through the shared
        # `hd` region; once delivered, no copy of it may remain anywhere in
        # guest memory (L12), without waiting for another handshake.
        # Control: this key must be somewhere in the window (data's session,
        # or hs/data stack residue), proving the window covers PD memory; it
        # does not prove the window covers `hd` itself. That is pinned by the
        # check-selftest case `integration-residue`, which removes the
        # reclaim and requires this check to fail.
        wait_absent(mon, install_bytes(1, good), good.recv_key, scratch)
        passed.append("spoofed inner source, install scrubbed")
        print("\nPASS [spoofed inner source dropped, install scrubbed]")

        # pq->hs link residue [R2-T-N7]: the PskInstall for peer 1 (its OSK
        # is the client's key_out) is gone from guest RAM once hs took it.
        # Control: the OSK itself, live in hs's PSK table until expiry.
        wait_absent(mon, psk_install_bytes(1, osk1), osk1, scratch, what="PskInstall message",
                    control_what="peer 1's live OSK")
        passed.append("pq->hs link scrubbed")
        print("\nPASS [pq->hs link: the PskInstall is scrubbed, the OSK lives only in hs's table]")

        # Case 5: an inside datagram with TTL 1 must not be forwarded into
        # the tunnel; TTL 2 still is (the boundary).
        mark = con.mark()
        for ttl in (1, 2):
            pkt = bytearray(icmp_echo(HOST_IP, bytes([10, 200, 0, 2]), 8, 7, ttl, b"ttl"))
            pkt[8] = ttl
            pkt[10:12] = b"\0\0"
            pkt[10:12] = struct.pack("!H", csum(bytes(pkt[:20])))
            inside.send(eth(INSIDE_MAC, HOST_MAC, 0x0800, bytes(pkt)))
        con.wait_for(r"audit: src=inner FrameDropped\(TtlExpired\) total=1 ", since=mark)
        # Allow side: the TTL 2 request crossed the tunnel and wireguard-go's
        # host answered it; the TTL 1 one never got an answer.
        deadline = time.monotonic() + REPLY_TIMEOUT_S

        def replies(seq):
            return [ip for ip in list(host.received) if ip[9] == 1 and ip[20] == 0
                    and ip[12:16] == bytes([10, 200, 0, 2]) and ip[24:28] == struct.pack("!HH", 7, seq)]
        while not replies(2) and time.monotonic() < deadline:
            time.sleep(0.05)
        if not replies(2) or replies(1):
            raise Fail(f"TTL boundary: replies to seq 2 {len(replies(2))}, to seq 1 {len(replies(1))}")
        ping(tries=3)
        passed.append("ttl expiry")
        print("\nPASS [TTL 1 dropped, TTL 2 forwarded at the inside hop]")

        probe_thread.join(timeout=max(0.0, accepted_at + reject_s + EXPIRY_SLACK_S + 2 * REPLY_TIMEOUT_S
                                      - time.monotonic()))
        if probe_thread.is_alive():
            raise Fail("expiry: the probe did not finish")
        if "error" in expiry:
            raise expiry["error"]
        # Coalesced: total=1 prints once per boot, so no earlier stale refusal
        # may have used it up (e.g. peer 0's prelude PSK during rotation).
        # After the mark no other case can draw one: peer 1's only user is
        # the probe, and nothing initiates for peer 0 between the mark and
        # the join below (the pinger has stopped and cases 4 and 5 are done).
        stale = r"audit: src=hs HandshakePskStale total="
        if len(con.count(stale)) > len(con.count(stale, since=expiry["mark"])):
            raise Fail("expiry: a stale refusal before the probe used up the audit line; precondition broken")
        con.wait_for(r"audit: src=hs HandshakePskStale total=1 ", since=expiry["mark"])
        passed.append("PSK expiry")
        print("\nPASS [expiry: accepted before REJECT_AFTER_TIME, HandshakePskStale after]")
        # C7: peer 1's expired OSK is gone from all of guest RAM; peer 0's
        # key, accepted just before the scan, is the control.
        live0 = rp0.wait_key(time.monotonic() + RP_EXCHANGE_S)
        installed(peer0, rp0, time.monotonic() + RP_EXCHANGE_S, key=live0)
        scan_absent(mon, osk1, live0, scratch, "expired OSK", "peer 0's live OSK")
        passed.append("expired OSK gone from guest RAM")
        print("\nPASS [guest RAM: peer 1's expired OSK occurs nowhere]")

        # Reboot [S11]: an initiation that drew an opening response before a
        # system_reset is refused with HandshakePskMissing after it, before
        # any Rosenpass exchange.
        _, capture = installed(peer0, rp0, time.monotonic() + RP_EXCHANGE_S)
        # Nothing but the replay may initiate after the reset.
        wg.close()
        wg = None
        rp0.stop()
        mark = con.mark()
        mon.command("system_reset")
        con.wait_for(r"pq: ready", since=mark, timeout=BOOT_TIMEOUT_S, strip_ready=True)
        for _ in range(RP_RESET_TRIES):
            out.sendto(capture, ("127.0.0.1", hostfwd))
            try:
                out.settimeout(PSK_RETRY_S)
                d = out.recv(2048)
                raise Fail(f"reboot: the replayed initiation drew a {len(d)}-byte reply")
            except socket.timeout:
                pass
            if con.count(r"audit: src=hs HandshakePskMissing total=1 ", since=mark):
                break
        else:
            raise Fail("reboot: no HandshakePskMissing for the replayed initiation")
        passed.append("reboot replay refused")
        print("\nPASS [reboot: the pre-reset initiation is refused with HandshakePskMissing]")
    finally:
        try:
            with signals_held():
                host.stop = True
                for t in threads:
                    t.stop = True
                close_all(wg, out, *rps)
                kill(child)
        except SystemExit:
            host.stop = True
            close_all(wg, out, *rps)
            kill(child)
            raise


# ---------------------------------------------------------------- peer binding (M3 plan C7)


def swap_rp_records(path: str):
    """Deployment `c` [S8, R3-T-M5]: peer records 0 and 1 trade their
    Rosenpass keys, giving {wg0, rp1} and {wg1, rp0}; nothing else moves."""
    text = open(path).read()
    recs = list(re.finditer(r'^rp_pub_path = "peer-(\d+)\.rp\.pk"\nrp_hash = "[0-9a-f]+"$', text, re.M))
    if [m.group(1) for m in recs][:2] != ["0", "1"]:
        raise Fail(f"{path}: peer records 0 and 1 not found in order")
    a, b = recs[0], recs[1]
    text = text[:a.start()] + b.group(0) + text[a.end():b.start()] + a.group(0) + text[b.end():]
    with open(path, "w") as f:
        f.write(text)


def test_peer_binding(loader: str, deploy: str, passed: list):
    """Only client 0 runs, with WireGuard key wg0 and Rosenpass key rp0, on
    deployment `c`, where rp0 belongs to record 1: its PSK lands at record 1,
    so wg0 is refused, while wg1 with that PSK is accepted [R5-T-R1]. The
    correctly bound allow side is boot 2's interop."""
    hostfwd = free_udp_port()
    rp_fwd = free_udp_port()
    child, con = boot(loader, f"user,id=n0,net=10.0.2.0/24,hostfwd=udp:127.0.0.1:{hostfwd}-:{WG_PORT},"
                              f"hostfwd=udp:127.0.0.1:{rp_fwd}-:{RP_PORT}",
                      dgram("n1", free_udp_port(), free_udp_port()))
    rp = sock = None
    try:
        cfg = tomllib.load(open(os.path.join(deploy, "gateway.toml"), "rb"))
        gw_pub = b64(cfg["gateway"]["public_key"])
        con.wait_for(r"pq: ready", timeout=BOOT_TIMEOUT_S, strip_ready=True)
        mark = con.mark()
        rp = Rosenpass(deploy, 0, f"127.0.0.1:{rp_fwd}")
        # Precondition: the Rosenpass handshake completed.
        osk = exported(con, rp, mark, "peer binding precondition: ")
        rp.stop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))

        def initiation(peer: int, psk: bytes):
            conf = open(os.path.join(deploy, f"peer-{peer}.conf")).read()
            i = wg_mod.Initiator(b64(conf_value(conf, "PrivateKey")), gw_pub, psk, sender=secrets.randbits(32))
            sock.sendto(i.initiation(), ("127.0.0.1", hostfwd))
            return i

        mark = con.mark()
        if wait_response(sock, initiation(0, osk), REPLY_TIMEOUT_S) is not None:
            raise Fail("peer binding: wg0 got a handshake response with the PSK rp0 exported to record 1")
        con.wait_for(r"audit: src=hs HandshakePskMissing total=1 ", since=mark)
        i = initiation(1, osk)
        r = wait_response(sock, i, REPLY_TIMEOUT_S)
        if r is None or not i.consume_response(r):
            raise Fail("peer binding: wg1 with client 0's key_out was not accepted; the PSK did not land at record 1")
        con.wait_for(r"audit: src=hs HandshakeOk total=1 ", since=mark)
        passed.append("peer binding")
        print("\nPASS [peer binding: rp0's PSK is record 1's; wg0 refused, wg1 accepted with it]")
    finally:
        try:
            with signals_held():
                close_all(rp, sock)
                kill(child)
        except SystemExit:
            close_all(rp, sock)
            kill(child)
            raise


# ---------------------------------------------------------------- boot 3


def test_mismatched_blob(loader: str):
    child, con = boot(loader, dgram("n0", free_udp_port(), free_udp_port()),
                      dgram("n1", free_udp_port(), free_udp_port()))
    try:
        con.wait_for(r"key: secrets: gateway key does not match the configuration", timeout=BOOT_TIMEOUT_S,
                     strip_ready=True)
        con.wait_for(r"key: halted", timeout=LINE_TIMEOUT_S, strip_ready=True)
        con.wait_for(r"MON\|ERROR: faulting PD: key", timeout=LINE_TIMEOUT_S)
    finally:
        try:
            with signals_held():
                kill(child)
        except SystemExit:
            kill(child)
            raise


# ---------------------------------------------------------------- cookie boots (M2.5 plan C6)

# Every timing and band the cookie cases judge is named here, once; the
# protocol constants come from the Rust sources.
INGRESS_CORE = "crates/ingress-core/src/lib.rs"
ROSENPASS_WIRE = "crates/rosenpass-wire/src/lib.rs"
WG_CORE = "crates/wg-core/src/lib.rs"
NS = 1e9
TIMER_TICK_S = 1.0             # pd-timer notifies once per second
KEEPALIVE_SLACK_S = 3.0        # keepalive window: [KEEPALIVE_TIMEOUT, + this]
KEEPALIVE_QUIET_S = 10.0       # no second keepalive within this after the first
KEEPALIVE_DENY_S = 13.0        # no keepalive this long after an inside reply
LOAD_CLEARED_SLACK_S = 0.5     # WgLoadCleared window: [UNDER_LOAD_AFTER, + 2 ticks + this]
BAND_LOW = 1.2                 # below-capacity floods: >= BAND_LOW x arrival refill
BAND_HIGH = 0.8                #   ... and <= BAND_HIGH x C
BAND_RATE = 1.4                # x arrival refill: inside that band whenever C >= C_MIN x refill
C_MIN = 2.0                    # x arrival refill (the CF precondition)
STEP2_RATE = 3.0               # Flood step 2, over capacity: x C
STEP2_BAND = (2.5, 3.5)        #   asserted band, x C
STEP2_WARMUP_S = 1.0           #   over capacity this long before the ping starts
PROBE_RATE = 1e6               # unpaced: the injector's own ceiling
PROBE_S = 2.0
PROBE_SETTLE_S = 0.3           # audit lines still printing after the drain
DENY_SETTLE_S = 1.0            # a port-B WgMac2Accepted line must print before the count
PROBE_SATURATION = 1.5         # the probe must offer at least this x C
PRECONDITION_S = 4.0           # band flood measuring the below-capacity survival ratio
FAIL_P = 1e-3                  # chance failure allowed per retry budget
SURVIVAL_MARGIN = 0.5          # Flood step 2's survival estimate, C / rate, is scaled by this
COOKIE_WAIT_S = 1.0            # per try, for a cookie reply or a handshake response
PING_INTERVAL_S = 1.0          # Python-peer pings: one try per interval,
PING_WAIT_S = 3.0              #   each answered within this (queueing over capacity)
REKEY_ATTEMPT_S = 5.0 + 0.334  # wireguard-go: REKEY_TIMEOUT plus at most its jitter
HANDSHAKE_SLACK_S = 3.0
FLOOD_STALL_S = 0.5            # a flood that sent nothing for this long is not running
PAIRED_TRIES = 5               # below capacity (survival >= 0.87 measured): < 1e-4 to fail
SPOOF_SOURCES = 256            # > BUCKETS (64): the per-source table churns
WG_LISTEN_PORT = 51900         # wireguard-go's fixed ListenPort in boot b (sniffer filter)
PEER1_IP = bytes([10, 200, 0, 3])
TAP = "tapo0"                  # the netns is private to the run
SNIFF_RCVBUF = 8 << 20

ETH_P_ALL = 0x0003
ETH_P_ARP = 0x0806
SOL_PACKET = 263
PACKET_STATISTICS = 6
PACKET_QDISC_BYPASS = 20
PACKET_OUTGOING = 4
SO_ATTACH_FILTER = 26


def rust_const(rel: str, name: str) -> int:
    """`pub const NAME: u64 = <integer expression>;` from a Rust source."""
    src = open(os.path.join(ROOT, rel)).read()
    m = re.search(rf"pub const {name}: u\d+ = ([^;]+);", src)
    if not m:
        raise Fail(f"{name} not found in {rel}")
    expr = m.group(1).replace("NS_PER_SEC", "1_000_000_000")
    if not re.fullmatch(r"[0-9_ *+/]+", expr):
        raise Fail(f"{name} in {rel} is not a plain integer expression: {expr}")
    return int(eval(expr))  # digits and operators only, checked above


def arrival_refill() -> float:
    return NS / rust_const(INGRESS_CORE, "ARRIVAL_INTERVAL_NS")


def keepalive_window() -> tuple:
    timeout = rust_const(WG_CORE, "KEEPALIVE_TIMEOUT_NS") / NS
    return timeout, timeout + KEEPALIVE_SLACK_S


def load_cleared_window() -> tuple:
    """[UNDER_LOAD_AFTER, UNDER_LOAD_AFTER + 2 ticks + 0.5 s] after the last
    flood send: the allow side of the hysteresis. The lower end is coarse;
    the C3 boundary unit test pins the 1 s."""
    after = rust_const(INGRESS_CORE, "UNDER_LOAD_AFTER_NS") / NS
    return after, after + 2 * TIMER_TICK_S + LOAD_CLEARED_SLACK_S


def ip_str(b: bytes) -> str:
    return ".".join(map(str, b))


def tries_for(p: float) -> int:
    """Independent tries, each succeeding with probability p, so that all
    fail with probability below FAIL_P."""
    if p >= 1:
        return 1
    if p <= 0:
        raise Fail(f"survival ratio {p:.3f}: no retry budget can succeed")
    return max(1, math.ceil(math.log(FAIL_P) / math.log(1 - p)))


def close_all(*resources):
    """Closes what was opened, in order; None is skipped (teardown helper)."""
    for r in resources:
        if r is not None:
            r.close()


class Tap:
    """The outside NIC on a tap in the test netns: the kernel end plays the
    router (10.0.2.2/24 with outside_router_mac), so Python sockets and
    wireguard-go reach the gateway directly, and AF_PACKET injects spoofed
    frames."""

    def __init__(self):
        self.inject = None
        sh("ip", "tuntap", "add", "dev", TAP, "mode", "tap")
        try:
            sh("ip", "link", "set", TAP, "address", PEER_MAC.hex(":"))
            sh("ip", "addr", "add", f"{ip_str(PEER_IP)}/24", "dev", TAP)
            sh("ip", "link", "set", TAP, "up")
            # The gateway's MAC is static, so the kernel sends it no ARP.
            sh("ip", "neigh", "replace", ip_str(GW_IP), "lladdr", GW_MAC.hex(":"), "dev", TAP, "nud", "permanent")
            self.inject = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
            # Straight to the tap's queue: a frame beyond it is dropped, as on
            # a wire, rather than held in a qdisc.
            self.inject.setsockopt(SOL_PACKET, PACKET_QDISC_BYPASS, 1)
            self.inject.bind((TAP, 0))
        except BaseException:
            self.close()
            raise

    def netdev(self, name: str) -> str:
        return f"tap,id={name},ifname={TAP},script=no,downscript=no"

    def send(self, frame: bytes):
        self.inject.send(frame)

    def close(self):
        if self.inject:
            self.inject.close()
        subprocess.run(["ip", "link", "del", TAP], capture_output=True)


def arp_round_trip(tap: Tap, timeout: float):
    """ARP requests on the tap, one per 0.5 s, until the gateway answers:
    the monotonic time of the reply, or None. The rings are FIFO, so the
    reply also proves every frame queued before its request was handled."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    try:
        s.bind((TAP, ETH_P_ARP))
        s.settimeout(0.1)
        want = arp(2, GW_MAC, GW_IP, PEER_MAC, PEER_IP, dst=PEER_MAC)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                tap.send(arp(1, PEER_MAC, PEER_IP, b"\0" * 6, GW_IP))
            except OSError as e:
                # QEMU has not attached the tap yet, or its queue is full.
                if e.errno != errno.ENOBUFS:
                    raise
            until = time.monotonic() + 0.5
            while time.monotonic() < until:
                try:
                    f = s.recv(2048)
                except socket.timeout:
                    continue
                if f[:42] == want:
                    return time.monotonic()
        return None
    finally:
        s.close()


def wait_tap_ready(tap: Tap, con: Console):
    """ARP round trips on the tap until the gateway answers (boot done)."""
    if arp_round_trip(tap, BOOT_TIMEOUT_S) is None:
        raise Fail("QEMU exited during boot" if not con.alive else "no ARP reply on the tap after boot")


def udp_fields(frame: bytes):
    """(src ip, sport, dst ip, dport, payload) of an IPv4/UDP frame, or None."""
    if len(frame) < 42 or frame[12:14] != b"\x08\x00" or frame[23] != 17:
        return None
    u = 14 + (frame[14] & 0xF) * 4
    sport, dport, ulen = struct.unpack("!HHH", frame[u:u + 6])
    return frame[26:30], sport, frame[30:34], dport, frame[u + 8:u + ulen]


def udp_filter(port: int) -> bytes:
    """Classic BPF: unfragmented IPv4/UDP to or from `port`."""
    prog = [
        (0x28, 0, 0, 12),       # ldh [12]
        (0x15, 0, 9, 0x0800),   # IPv4, else drop
        (0x30, 0, 0, 23),       # ldb [23]
        (0x15, 0, 7, 17),       # UDP, else drop
        (0x28, 0, 0, 20),       # ldh [20]
        (0x45, 5, 0, 0x1FFF),   # a fragment: drop
        (0xB1, 0, 0, 14),       # x = IP header length
        (0x48, 0, 0, 14),       # ldh [x + 14]: source port
        (0x15, 3, 0, port),     # accept
        (0x48, 0, 0, 16),       # ldh [x + 16]: destination port
        (0x15, 1, 0, port),     # accept
        (0x06, 0, 0, 0),        # drop
        (0x06, 0, 0, 0x40000),  # accept
    ]
    return b"".join(struct.pack("HBBI", *i) for i in prog)


class Sniffer:
    """AF_PACKET on the tap keeping only UDP to and from one port (classic
    BPF, enlarged SO_RCVBUF). A kernel-side drop (PACKET_STATISTICS) aborts
    the case, so a lost frame never reads as an attribution failure."""

    def __init__(self, port: int):
        self.frames = []  # (monotonic, frame, outgoing)
        self.lock = threading.Lock()
        self.drops = 0
        self.alive = True
        # Protocol 0 receives nothing until the bind, after the filter.
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SNIFF_RCVBUF)
            prog = udp_filter(port)
            buf = ctypes.create_string_buffer(prog, len(prog))
            self.sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER,
                                 struct.pack("HL", len(prog) // 8, ctypes.addressof(buf)))
            self.sock.bind((TAP, ETH_P_ALL))
            self.sock.settimeout(0.2)
        except BaseException:
            self.sock.close()
            raise
        start_without_stop_signals(threading.Thread(target=self._run, daemon=True))

    def _run(self):
        while self.alive:
            try:
                f, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                self.frames.append((time.monotonic(), f, addr[2] == PACKET_OUTGOING))

    def since(self, i: int) -> list:
        with self.lock:
            return self.frames[i:]

    def check_drops(self):
        _, drops = struct.unpack("II", self.sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))
        self.drops += drops  # reading resets the kernel's counters
        if self.drops:
            raise Fail(f"sniffer dropped {self.drops} frames (PACKET_STATISTICS); attribution not judged")

    def close(self):
        self.alive = False
        self.sock.close()


class Flood:
    """Spoofed mac1-valid initiations (random body, zero mac2) from
    SPOOF_SOURCES addresses, sent on the tap at `rate` per second by a helper
    thread. `set_rate` takes effect at once and returns where the new step
    starts, so each step's achieved rate can be checked against its band."""

    def __init__(self, tap: Tap, gw_pub: bytes):
        msg = wg_mod.with_mac1(struct.pack("<I", 1) + secrets.token_bytes(112), gw_pub)
        self.frames = [ipv4_udp(bytes([172, 16, i // 200, 1 + i % 200]), GW_IP, 20000 + i, WG_PORT, msg)
                       for i in range(SPOOF_SOURCES)]
        self.tap = tap
        self.lock = threading.Lock()
        self.rate, self.base, self.t0 = 0.0, 0, time.monotonic()
        self.sent = 0
        self.last_send = 0.0
        self.error = None
        self.stopped = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        start_without_stop_signals(self.thread)

    def _run(self):
        try:
            while not self.stopped:
                with self.lock:
                    n = min(self.base + int((time.monotonic() - self.t0) * self.rate) - self.sent, 256)
                    for _ in range(n):
                        try:
                            self.tap.send(self.frames[self.sent % SPOOF_SOURCES])
                        except OSError as e:
                            # The tap's queue is full: offered and lost, as on a wire.
                            if e.errno != errno.ENOBUFS:
                                raise
                        self.sent += 1
                        self.last_send = time.monotonic()
                if n <= 0:
                    time.sleep(0.001)
        except OSError as e:
            self.error = e

    def set_rate(self, rate: float) -> tuple:
        """(frames sent, time) at the switch."""
        with self.lock:
            self.rate, self.base, self.t0 = rate, self.sent, time.monotonic()
            return self.sent, self.t0

    def snapshot(self) -> tuple:
        with self.lock:
            return self.sent, time.monotonic()

    def running(self) -> bool:
        return (self.thread.is_alive() and self.error is None
                and time.monotonic() - self.last_send < FLOOD_STALL_S)

    def close(self):
        self.stopped = True
        self.thread.join(timeout=5)


def check_band(what: str, start: tuple, end: tuple, lo: float, hi: float) -> float:
    """The harness's own send rate over [start, end] against a step's band."""
    rate = (end[0] - start[0]) / (end[1] - start[1])
    if not lo <= rate <= hi:
        raise Fail(f"{what}: flood rate {rate:.0f}/s outside its band [{lo:.0f}, {hi:.0f}]")
    return rate


def check_low_band_first(what: str, start: tuple, end: tuple, lo: float, cause: Fail):
    """On a behavioural failure: a harness that under-delivered the flood is
    reported first, chained to `cause`, since the failure then says nothing
    about the gateway [code review T4]."""
    rate = (end[0] - start[0]) / (end[1] - start[1])
    if rate < lo:
        raise Fail(f"{what}: flood rate {rate:.0f}/s below its band's lower end {lo:.0f}/s; "
                   f"the behavioural failure is not judged") from cause


def cookie_totals(con: Console) -> tuple:
    """(lower, upper) bounds on initiations ingress answered on the cookie
    path so far, from the coalesced WgCookieSent / WgCookieSuppressed lines
    (each line stands for 64)."""
    lo = hi = 0
    for event in ("WgCookieSent", "WgCookieSuppressed"):
        totals = [int(t) for t in con.count(rf"audit: src=ingress {event} total=(\d+) ")]
        if totals:
            lo += max(totals)
            hi += max(totals) + 63
    return lo, hi


def probe_capacity(con: Console, tap: Tap, flood: Flood, after_rate: float) -> tuple:
    """Per-run C [R5-T-S1]: ingress's processing rate on the cookie path,
    from a short over-capacity probe. C is what was answered from the
    probe's start until an ARP round trip proves the queues drained, over
    that time: a starved handler loop flushes audit only then. The flood
    then continues at `after_rate`, soon enough for load to hold. Returns
    (C, the probe's survival ratio)."""
    _, before = cookie_totals(con)
    start = flood.set_rate(PROBE_RATE)
    time.sleep(PROBE_S)
    end = flood.set_rate(0)
    drained = arp_round_trip(tap, LINE_TIMEOUT_S)
    if drained is None:
        raise Fail("capacity probe: no ARP reply after the probe; the queues did not drain")
    time.sleep(PROBE_SETTLE_S)
    after, _ = cookie_totals(con)
    flood.set_rate(after_rate)
    done = after - before
    c = done / (drained - start[1])
    offered = (end[0] - start[0]) / (end[1] - start[1])
    refill = arrival_refill()
    print(f"\ncapacity probe: C = {c:.0f}/s (offered {offered:.0f}/s, survival {done / (end[0] - start[0]):.3f}, "
          f"drained {drained - end[1]:.1f} s after it, arrival refill {refill:.0f}/s)", flush=True)
    if offered < PROBE_SATURATION * c:
        raise Fail(f"capacity probe offered {offered:.0f}/s, not {PROBE_SATURATION} x C = {c:.0f}/s: C not measured")
    if c < C_MIN * refill:
        raise Fail(f"C = {c:.0f}/s is below {C_MIN} x the arrival refill ({refill:.0f}/s): flood bands are empty")
    return c, done / (end[0] - start[0])


class PyPeer:
    """wg.py's initiator on its own UDP port at the tap's address: sends
    what wireguard-go will not and opens what the gateway sends back."""

    def __init__(self, conf: str, gw_pub: bytes, psk: bytes, port: int = 0):
        self.gw_pub = gw_pub
        self.init = wg_mod.Initiator(b64(conf_value(conf, "PrivateKey")), gw_pub, psk, sender=secrets.randbits(32))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind((ip_str(PEER_IP), port))
        except BaseException:
            self.sock.close()
            raise
        self.sent = []  # initiations, to open late cookie replies
        self.established = None

    def send(self, msg: bytes):
        if msg[0] == 1:
            self.sent.append(msg)
        try:
            self.sock.sendto(msg, (ip_str(GW_IP), WG_PORT))
        except OSError as e:
            # The tap's queue is full over capacity: a lost datagram, which
            # the caller's retry budget covers.
            if e.errno != errno.ENOBUFS:
                raise

    def recv(self, until: float):
        """The next datagram before monotonic `until`, or None."""
        left = until - time.monotonic()
        if left <= 0:
            return None
        self.sock.settimeout(left)
        try:
            return self.sock.recv(2048)
        except socket.timeout:
            return None

    def wait_kind(self, kinds: tuple, timeout: float):
        until = time.monotonic() + timeout
        while (d := self.recv(until)) is not None:
            if d[:1] and d[0] in kinds:
                return d
        return None

    def open_cookie(self, reply: bytes):
        """The cookie in a reply to one of our initiations, or None."""
        if struct.unpack("<I", reply[4:8])[0] != self.init.sender:
            return None
        for msg in reversed(self.sent):
            try:
                return wg_mod.open_cookie_reply(self.gw_pub, reply, msg)
            except Exception:
                continue
        return None

    def close(self):
        self.sock.close()


def opens_for(gw_pub: bytes, reply: bytes, initiation: bytes) -> bool:
    """Whether `reply` is a cookie reply to exactly `initiation`."""
    try:
        wg_mod.open_cookie_reply(gw_pub, reply, initiation)
        return True
    except Exception:
        return False


def learn_cookie(peer: PyPeer, tries: int) -> bytes:
    """Under load an initiation without mac2 must draw a cookie reply that
    opens with the public cookie key."""
    for _ in range(tries):
        peer.send(peer.init.initiation())
        r = peer.wait_kind((2, 3), COOKIE_WAIT_S)
        if r is not None and r[0] == 2:
            raise Fail("cookie attribution failed: an initiation without mac2 under load got a handshake response")
        if r is not None:
            cookie = peer.open_cookie(r)
            if cookie is None:
                raise Fail("cookie attribution failed: the cookie reply does not open with the public cookie key")
            return cookie
    raise Fail(f"cookie attribution failed: no cookie reply to {tries} initiations under load")


def cookie_handshake(peer: PyPeer, tries: int) -> bool:
    """A handshake under load through the cookie path: an initiation draws a
    cookie, a fresh one with mac2 gets the response. A cookie reply instead
    of a response (secret rotated, or the cookie was lost) is learned again."""
    cookie = None
    for _ in range(tries):
        if cookie is None:
            peer.send(peer.init.initiation())
            r = peer.wait_kind((3,), COOKIE_WAIT_S)
            cookie = r and peer.open_cookie(r)
            if cookie is None:
                continue
        peer.send(wg_mod.with_mac2(peer.init.initiation(), cookie))
        r = peer.wait_kind((2, 3), COOKIE_WAIT_S)
        if r is not None and r[0] == 2:
            if not peer.init.consume_response(r):
                raise Fail("handshake response under load does not open")
            peer.established = time.monotonic()
            return True
        cookie = r and peer.open_cookie(r)
    return False


def udp_packet(src: bytes, dst: bytes, sport: int, dport: int, data: bytes) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    return ip_hdr(src, dst, 17, len(udp)) + udp


def py_ping(peer: PyPeer, tries: int, ident: int, src: bytes = PEER1_IP) -> int:
    """ICMP echoes through the Python peer's session to the inside host, one
    per PING_INTERVAL_S, each an independent try: the sequence number of the
    first reply, or 0 once PING_WAIT_S passed after the last send."""
    seq, next_send, until = 0, time.monotonic(), None
    while True:
        if seq < tries and time.monotonic() >= next_send:
            seq += 1
            peer.send(peer.init.transport(icmp_echo(src, HOST_IP, 8, ident, seq, b"secureos")))
            next_send = time.monotonic() + PING_INTERVAL_S
            if seq == tries:
                until = time.monotonic() + PING_WAIT_S
        d = peer.recv(next_send if seq < tries else until)
        if d is None:
            if seq == tries and time.monotonic() >= until:
                return 0
            continue
        try:
            _, plain = peer.init.open_transport(d)
        except Exception:
            continue
        if len(plain) >= 28 and plain[9] == 1 and plain[20] == 0 and plain[24:26] == struct.pack("!H", ident):
            got = struct.unpack("!H", plain[26:28])[0]
            if 1 <= got <= seq:
                return got


def ping_budget(tries: int) -> float:
    return (tries - 1) * PING_INTERVAL_S + PING_WAIT_S


def keepalive_case(con: Console, peer: PyPeer):
    """Passive keepalive [C7]: allow, then deny."""
    for _ in range(3):
        peer.send(peer.init.initiation())
        r = peer.wait_kind((2,), REPLY_TIMEOUT_S)
        if r is not None:
            break
    else:
        raise Fail("keepalive: no handshake response")
    if not peer.init.consume_response(r):
        raise Fail("keepalive: handshake response does not open")
    lo, hi = keepalive_window()
    # Allow: data the inside never answers, then exactly one keepalive.
    sent = time.monotonic()
    peer.send(peer.init.transport(udp_packet(PEER1_IP, HOST_IP, 40001, 9, b"never answered")))
    got = []
    until = sent + hi + KEEPALIVE_QUIET_S
    while (d := peer.recv(until)) is not None:
        got.append((time.monotonic() - sent, d))
    if len(got) != 1 or not lo <= got[0][0] <= hi:
        raise Fail(f"keepalive: want exactly one message {lo:.0f}-{hi:.0f} s after the send, then none for "
                   f"{KEEPALIVE_QUIET_S:.0f} s; got at {[round(t, 2) for t, _ in got]} s")
    try:
        counter, plain = peer.init.open_transport(got[0][1])
    except Exception as e:
        raise Fail(f"keepalive: the message does not open with the session key: {e!r}")
    if plain or counter != 0:
        raise Fail(f"keepalive: counter {counter}, {len(plain)} plaintext bytes; want the first counter, empty")
    # Deny: an inside reply sealed first clears the debt.
    if not py_ping(peer, 3, ident=0x4b41):
        raise Fail("keepalive deny side: the inside reply did not arrive")
    until = time.monotonic() + KEEPALIVE_DENY_S
    while (d := peer.recv(until)) is not None:
        try:
            _, plain = peer.init.open_transport(d)
        except Exception:
            continue
        if not plain:
            raise Fail("keepalive deny side: a keepalive arrived after the inside reply was sealed")


def paired_case(con: Console, tap: Tap, peer_conf: str, gw_pub: bytes, psk: bytes):
    """Cookie path, paired [M10, R2-T-N7]: learn a cookie at port A, deny it
    at port B, allow it at port A, all under a below-capacity flood, then
    the hysteresis' allow side once the flood stops."""
    refill = arrival_refill()
    flood = a = b = None
    try:
        flood = Flood(tap, gw_pub)
        mark = con.mark()
        start = flood.set_rate(BAND_RATE * refill)
        try:
            try:
                m = con.wait_for(r"audit: src=ingress WgUnderLoad total=1 ", since=mark)
            except Fail:
                raise Fail("paired: WgUnderLoad total=1 did not appear under the band flood")
            loaded_at = mark + m.start()
            a, b = PyPeer(peer_conf, gw_pub, psk), PyPeer(peer_conf, gw_pub, psk)
            cookie = learn_cookie(a, PAIRED_TRIES)
            # Deny: a fresh initiation from port B with port A's cookie.
            for _ in range(PAIRED_TRIES):
                b.send(wg_mod.with_mac2(b.init.initiation(), cookie))
                r = b.wait_kind((2, 3), COOKIE_WAIT_S)
                if r is not None and r[0] == 2:
                    raise Fail("cookie deny: port B's initiation with port A's cookie got a handshake response")
                # Conclusive only for the reply to B's latest initiation: an
                # earlier try that got no reply may still be in flight
                # [code review R2-T5].
                if r is not None and opens_for(gw_pub, r, b.sent[-1]):
                    break
            else:
                raise Fail("cookie deny: no cookie reply at port B (positive signal missing)")
            # Allow: port A with its own cookie. Had the deny step been
            # accepted, total=1 would already be there; the settle lets a
            # line `audit` prints late appear before it is counted.
            time.sleep(DENY_SETTLE_S)
            if con.count(r"audit: src=ingress WgMac2Accepted total=\d+ "):
                raise Fail("WgMac2Accepted appeared before the allow step: port B's initiation was accepted")
            allow = con.mark()
            first_allow = None
            for _ in range(PAIRED_TRIES):
                first_allow = first_allow or time.monotonic()
                a.send(wg_mod.with_mac2(a.init.initiation(), cookie))
                r = a.wait_kind((2, 3), COOKIE_WAIT_S)
                if r is not None and r[0] == 2:
                    break
                cookie = (r and a.open_cookie(r)) or cookie
            else:
                raise Fail("cookie allow: no handshake response at port A")
            m = con.wait_for(r"audit: src=ingress WgMac2Accepted total=1 ", since=allow)
            # Read before port A's first allow send, the line is port B's,
            # printed late by `audit` [code review T5].
            if con.time_at(allow + m.end()) <= first_allow:
                raise Fail("WgMac2Accepted total=1 was read before port A's first allow send: "
                           "port B's initiation was accepted")
            if not a.init.consume_response(r):
                raise Fail("cookie allow: the handshake response does not open")
            if con.count(r"audit: src=ingress WgLoadCleared ", since=loaded_at):
                raise Fail("WgLoadCleared during the paired flood: load did not hold")
            if con.count(r"audit: src=ingress WgCookieSuppressed total=1 "):
                raise Fail("WgCookieSuppressed total=1 during the paired flood: the TX reserve bound below capacity")
        except Fail as e:
            check_low_band_first("paired flood", start, flood.snapshot(), BAND_LOW * refill, e)
            raise
        end = flood.set_rate(0)
        last = flood.last_send
        lo, hi = load_cleared_window()
        m = con.wait_for(r"audit: src=ingress WgLoadCleared total=1 ", since=loaded_at, timeout=hi + 1)
        after = con.time_at(loaded_at + m.end()) - last
        if not lo <= after <= hi:
            raise Fail(f"WgLoadCleared {after:.2f} s after the last flood send, outside [{lo}, {hi}] s")
        # The band's upper end needs this boot's C, measured only now so its
        # own load cannot hide an edge in the window above.
        c, _ = probe_capacity(con, tap, flood, after_rate=0)
        check_band("paired flood", start, end, BAND_LOW * refill, BAND_HIGH * c)
    finally:
        close_all(a, b, flood)


def py_installed(conf: str, gw_pub: bytes, rp: Rosenpass, deadline: float) -> PyPeer:
    """A Python peer whose handshake with `rp`'s current key_out was
    accepted: proof that pq's export reached hs (only a boot's first export
    is printed). Unloaded only: no cookie path."""
    while True:
        psk = rp.osk()
        if psk is not None:
            peer = PyPeer(conf, gw_pub, psk)
            peer.send(peer.init.initiation())
            r = peer.wait_kind((2,), PSK_RETRY_S)
            if r is not None and peer.init.consume_response(r):
                return peer
            peer.close()
        if time.monotonic() > deadline:
            raise Fail(f"peer {rp.peer}: no handshake with its key_out was accepted within {RP_EXCHANGE_S:.0f} s")
        time.sleep(PSK_RETRY_S)


def rust_usize(rel: str, name: str) -> int:
    m = re.search(rf"pub const {name}: (?:usize|u\d+) = (0x[0-9a-fA-F_]+|[0-9_]+);", open(os.path.join(ROOT, rel)).read())
    if not m:
        raise Fail(f"{name} not found in {rel}")
    return int(m.group(1), 0)


def sniffed_init_hello(sniffer: Sniffer) -> bytes:
    """The first InitHello a client sent to the Rosenpass port."""
    size = rust_usize(INGRESS_CORE, "RP_INIT_HELLO_LEN")
    kind = rust_usize(ROSENPASS_WIRE, "MSG_INIT_HELLO")
    for _, f, outgoing in sniffer.since(0):
        u = udp_fields(f)
        if u is not None and outgoing and u[3] == RP_PORT and len(u[4]) == size and u[4][0] == kind:
            return u[4]
    raise Fail("no InitHello from the client was sniffed")


def wait_rp_load_clear(con: Console, timeout: float = 0.0):
    """Until the Rosenpass cookie gate is off: as many RpLoadCleared as
    RpUnderLoad lines (both never coalesced, so their totals count every
    edge). Bounded by the hold plus a margin."""
    hold = rust_usize(INGRESS_CORE, "RP_UNDER_LOAD_AFTER_NS") / 1e9
    deadline = time.monotonic() + (timeout or hold + LINE_TIMEOUT_S)
    while True:
        entered = [int(n) for n in con.count(r"audit: src=ingress RpUnderLoad total=(\d+) ")]
        cleared = [int(n) for n in con.count(r"audit: src=ingress RpLoadCleared total=(\d+) ")]
        if max(entered, default=0) == max(cleared, default=0):
            return
        if time.monotonic() > deadline:
            raise Fail("the Rosenpass cookie gate did not clear within its hold")
        time.sleep(0.2)


def wait_rp_gate_off(con: Console):
    """Off load and past the legacy probe window (M3b deviation, trigger
    4), so an uncookied InitHello is neither cookied nor re-arms load and
    only the off-load meters decide it. The window ends at most
    RP_LEGACY_PROBE_NS after the clearance line, so after a load this waits
    that long from the clearance, plus a second."""
    wait_rp_load_clear(con)
    if con.count(r"audit: src=ingress RpLoadCleared total=\d+ "):
        time.sleep(rust_usize(INGRESS_CORE, "RP_LEGACY_PROBE_NS") / 1e9 + 1)


def rp_deny_cases(con: Console, hello: bytes, passed: list):
    """ingress's Rosenpass gates, paired [C4]: a genuine InitHello (sniffed
    from a client) with one mac byte flipped is refused as RpBadMac and
    draws no RespHello, while the genuine bytes are answered. A replay right
    after, while the global meter still holds tokens, draws no RespHello:
    only the per-source meter can refuse it. The client after this
    completes once refilled."""
    resp_hello = rust_usize(ROSENPASS_WIRE, "MSG_RESP_HELLO")
    mac_at = len(hello) - rust_usize(ROSENPASS_WIRE, "COOKIE_LEN") - rust_usize(ROSENPASS_WIRE, "MAC_LEN")
    src_interval = rust_usize(INGRESS_CORE, "RP_HELLO_SRC_INTERVAL_NS") / 1e9
    global_interval = rust_usize(INGRESS_CORE, "RP_HELLO_GLOBAL_INTERVAL_NS") / 1e9
    reserve = rust_usize(INGRESS_CORE, "RP_HELLO_PROVEN_RESERVE")
    cost = rust_usize(PQKEY_CORE, "PQ_HANDSHAKE_COST_NS") / 1e9
    # The genuine bytes travel off load as an unproven source (M3b): the
    # global meter must hold more than the proven reserve for them, plus one
    # token for the replay so only the per-source meter can refuse it. From
    # empty that is (reserve + 2) refill intervals.
    refill_wait = max(src_interval + 1, (reserve + 2) * global_interval)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def resp_hellos(window: float, first: bool = False) -> int:
        """RespHellos received within `window`; with `first`, returns at the
        first one, so the caller's next send stays inside the meter's
        interval."""
        n, until = 0, time.monotonic() + window
        while (left := until - time.monotonic()) > 0:
            s.settimeout(left)
            try:
                n += s.recv(2048)[:1] == bytes([resp_hello])
            except socket.timeout:
                break
            if first and n:
                break
        return n

    try:
        s.bind((ip_str(PEER_IP), 0))
        bad = bytearray(hello)
        bad[mac_at] ^= 1
        mark = con.mark()
        s.sendto(bytes(bad), (ip_str(GW_IP), RP_PORT))
        con.wait_for(r"audit: src=ingress RpBadMac total=1 ", since=mark)
        # The client's own InitHellos came from this source: wait out its
        # meter and refill the global one (watching for any answer to the
        # flipped bytes), so only the mac decides the genuine bytes' fate.
        if resp_hellos(refill_wait):
            raise Fail("rosenpass mac pair: the flipped-mac InitHello got a RespHello")
        # And off load, past the probe window: the client exchanges before
        # may have engaged the cookie gate, under which these cookie-less
        # bytes would only draw a CookieReply, and inside the window the
        # genuine bytes would re-arm it before their replay arrives.
        wait_rp_gate_off(con)
        # The genuine bytes and, milliseconds later, their replay: both land
        # inside the source interval the first one opens, by construction
        # (a replay at exactly that interval would be admitted again).
        s.sendto(hello, (ip_str(GW_IP), RP_PORT))
        s.sendto(hello, (ip_str(GW_IP), RP_PORT))
        if not resp_hellos(RP_EXCHANGE_S, first=True):
            raise Fail("rosenpass mac pair: the genuine InitHello got no RespHello")
        passed.append("rosenpass mac deny")
        print("\nPASS [rosenpass mac: one flipped byte refused at ingress, the genuine bytes answered]")
        # A forwarded replay would be answered one decapsulation later.
        if resp_hellos(2 * cost):
            raise Fail("rosenpass bucket: a replay within the source's interval was answered")
        passed.append("rosenpass bucket deny")
        print("\nPASS [rosenpass bucket: a replay inside the source interval drew no RespHello]")
    finally:
        s.close()


# ---------------------------------------------------------------- the Rosenpass cookie gate (M3b plan C6)

RP_HELLO, RP_RESP_HELLO, RP_CONF, RP_EMPTY, RP_COOKIE_REPLY = 0x81, 0x82, 0x83, 0x84, 0x86
# The MCE-COST spread between the maximum and the median handshake
# (16.1 - 8.5 = 7.6 s) plus pq's and hs's 1 Hz ticks, rounded up [T15].
RP_SLACK_S = 10.0
RP_BACKOFF_CAP_S = 10.0        # upstream's retransmission cap (constants.rs)
RP_MCE_MAX_S = 16.1            # MCE-COST maximum InitHello cost at pq's budget
# Fixed client ports, so each client is one endpoint to the gateway.
RP_CLIENT_PORTS = (42001, 42002, 42003)
RP_SPOOF_PORT = 42999          # the per-IP spoofer's port at the victim's address
RP_SPOOF_RATE = 1.0            # per second: keeps the victim's per-IP token at zero [T3]


def rp_frames(sniffer: Sniffer, i0: int, *, outgoing=None, sport=None, dport=None, kind=None, src=None, dst=None):
    """Sniffed Rosenpass datagrams since `i0`: (time, payload, src ip, sport,
    dst ip, dport). `outgoing` is the tap's view: True for frames sent to
    the gateway."""
    out = []
    for when, f, og in sniffer.since(i0):
        u = udp_fields(f)
        if u is None:
            continue
        sip, sp, dip, dp, p = u
        if ((outgoing is not None and og != outgoing) or (sport is not None and sp != sport)
                or (dport is not None and dp != dport) or (kind is not None and (not p or p[0] != kind))
                or (src is not None and sip != src) or (dst is not None and dip != dst)):
            continue
        out.append((when, p, sip, sp, dip, dp))
    return out


def rp_attribute_cookie(sniffer: Sniffer, i0: int, port: int, spkm: bytes, what: str):
    """The cookie path end to end for the client at `port` [T8]: a
    CookieReply to its port opens with the public cookie key and the mac of
    one of its InitHellos; a later InitHello from it carries the cookie
    field for that value; a RespHello to its port follows that InitHello.
    (RpCookieAccepted is coalesced, so within a boot only its first line is
    printed; the RespHello is the per-client proof.)"""
    hellos = rp_frames(sniffer, i0, outgoing=True, sport=port, dport=RP_PORT, kind=RP_HELLO)
    replies = rp_frames(sniffer, i0, outgoing=False, sport=RP_PORT, dport=port, kind=RP_COOKIE_REPLY)
    if not replies:
        raise Fail(f"{what}: no CookieReply reached the client's port")
    for rt, reply, *_ in replies:
        for _, hello, *_ in hellos:
            try:
                value = rp_cookie.open_cookie_reply(spkm, reply, hello)
            except Exception:
                continue
            for ht, h2, *_ in hellos:
                if ht > rt and rp_cookie.cookie_ok(h2, value):
                    # The RespHello names the initiator's sidi (sidr ||
                    # sidi after the header), so it answers this InitHello
                    # and not another initiation from the same port.
                    answered = rp_frames(sniffer, i0, outgoing=False, sport=RP_PORT, dport=port, kind=RP_RESP_HELLO)
                    if any(at > ht and r[8:12] == h2[4:8] for at, r, *_ in answered):
                        return
                    raise Fail(f"{what}: the cookied InitHello got no RespHello naming its sidi")
            raise Fail(f"{what}: the client never resent with the cookie it was given")
    raise Fail(f"{what}: no CookieReply to the client opens for one of its InitHellos")


class RpSpoof:
    """Datagrams to the Rosenpass port from (ip, port) sources, at `rate`
    per second, cycling payloads and sources, on the tap by a helper thread
    (the shape of `Flood`). A case that relies on the attack calls
    `verify` at its judgment point: an attack that stopped or fell short
    fails the case instead of passing it vacuously."""

    # Delivered datagrams below this share of the scheduled ones fail
    # `verify`.
    MIN_DELIVERED = 0.9

    def __init__(self, tap: Tap, payloads: list, sources: list, rate: float):
        self.frames = [ipv4_udp(ip, GW_IP, port, RP_PORT, payloads[i % len(payloads)])
                       for i, (ip, port) in enumerate(sources)]
        self.tap, self.rate = tap, rate
        # `due` counts scheduled sends, `sent` only those the tap took.
        self.due, self.sent, self.dropped = 0, 0, 0
        self.t0 = time.monotonic()
        self.stopped = False
        self.error = None
        self.thread = threading.Thread(target=self._run, daemon=True)
        start_without_stop_signals(self.thread)

    def _run(self):
        try:
            while not self.stopped:
                due = int((time.monotonic() - self.t0) * self.rate) - self.due
                for _ in range(min(due, 256)):
                    try:
                        self.tap.send(self.frames[self.due % len(self.frames)])
                        self.sent += 1
                    except OSError as e:
                        if e.errno != errno.ENOBUFS:
                            raise
                        self.dropped += 1
                    self.due += 1
                time.sleep(0.005)
        except BaseException as e:
            self.error = e

    def wait_delivered(self, n: int, what: str):
        """Blocks until `n` datagrams went out (or the spoofer failed), so a
        slow-rate attack is under way before what it is meant to overlap
        starts. Bounded by the time `n` sends take at the rate."""
        deadline = time.monotonic() + n / self.rate + LINE_TIMEOUT_S
        while self.sent < n:
            if self.error is not None or not self.thread.is_alive() or time.monotonic() > deadline:
                raise Fail(f"{what}: the spoofer delivered {self.sent} of the first {n} datagrams")
            time.sleep(0.05)

    def verify(self, what: str):
        """The attack is still running and delivered at its rate so far."""
        if self.error is not None:
            raise Fail(f"{what}: the spoofer failed: {self.error!r}")
        if not self.thread.is_alive():
            raise Fail(f"{what}: the spoofer stopped before the judgment")
        scheduled = int((time.monotonic() - self.t0) * self.rate)
        if scheduled == 0 or self.sent < self.MIN_DELIVERED * scheduled:
            raise Fail(f"{what}: the spoofer delivered {self.sent} of {scheduled} datagrams "
                       f"({self.dropped} dropped)")

    def close(self):
        # Teardown also calls this: it never raises (verify reports).
        self.stopped = True
        self.thread.join(timeout=5)


def spoof_ips(n: int) -> list:
    return [(bytes([172, 17, i // 250, 1 + i % 250]), 30000 + i) for i in range(n)]


def spoof_answers_bounded(con: Console, sniffer: Sniffer, i0: int, mark, spoofed, what: str, pending: int = 0):
    """Under load a spoofed InitHello reaches `pq` only as the one legacy
    probe after each clearance (M3b deviation, "trigger 4"), so the
    RespHellos to spoofed sources (`spoofed(ip, port)`), each one InitHello
    `pq` processed for a spoofer, are at most the RpLoadCleared lines since
    `mark` (never coalesced) plus `pending`, the spoofs already forwarded
    when load engaged. Returns the CookieReplies to spoofed sources."""
    answers = [f for f in rp_frames(sniffer, i0, outgoing=False, sport=RP_PORT) if spoofed(f[4], f[5])]
    resp = sum(1 for f in answers if f[1][0] == RP_RESP_HELLO)
    cleared = len(con.count(r"audit: src=ingress RpLoadCleared total=\d+ ", since=mark))
    if resp > cleared + pending:
        raise Fail(f"{what}: {resp} RespHellos to spoofed sources under load, {cleared} clearances")
    return sum(1 for f in answers if f[1][0] == RP_COOKIE_REPLY)


def no_sync_death(con: Console, what: str):
    """I9 at the integration level [T14]: the pq completion protocol never
    broke for an honest pq."""
    for line in ("RpPqSyncDead", "RpPqRecordStuck"):
        if con.count(rf"audit: src=(?:ingress|pq) {line} "):
            raise Fail(f"{what}: {line} logged with an honest pq")


def rp_exchange(rp: Rosenpass, budget: float, what: str) -> bytes:
    try:
        return rp.wait_key(time.monotonic() + budget)
    except Fail as e:
        raise Fail(f"{what}: {e}") from e


def rp_spoof_case(con, tap, sniffer, deploy, spkm, endpoint, hello, rps):
    """S-3 [T3, T10]: one victim's address spoofed once per second with a
    replay of its own InitHello. The per-IP token stays at zero, so the
    victim's next exchange needs the cookie path. Deny side: selftest
    rp-cookie-gate, the gate never holding."""
    wait_rp_load_clear(con)
    mark = con.mark()
    spoof = RpSpoof(tap, [hello], [(PEER_IP, RP_SPOOF_PORT)], RP_SPOOF_RATE)
    rps.append(spoof)
    try:
        con.wait_for(r"audit: src=ingress RpUnderLoad total=\d+ ", since=mark, timeout=10 * RP_SPOOF_RATE + LINE_TIMEOUT_S)
        engaged = con.mark()
        i0 = len(sniffer.since(0))
        victim = Rosenpass(deploy, 0, endpoint, listen_port=RP_CLIENT_PORTS[0])
        rps.append(victim)
        try:
            victim.wait_key(time.monotonic() + RP_EXCHANGE_S + RP_BACKOFF_CAP_S)
        except Fail as e:
            raise Fail("rp spoof: the victim's exchange did not complete under the spoof") from e
        spoof.verify("rp spoof")
        rp_attribute_cookie(sniffer, i0, RP_CLIENT_PORTS[0], spkm, "rp spoof")
        # The spoofs forwarded before load engaged may still be answered.
        pending = rust_usize(INGRESS_CORE, "RP_HELLO_IN_FLIGHT")
        if not spoof_answers_bounded(con, sniffer, i0, engaged, lambda ip, port: (ip, port) == (PEER_IP, RP_SPOOF_PORT),
                                     "rp spoof", pending):
            raise Fail("rp spoof: the spoofed endpoint got no CookieReply under load")
        victim.stop()
    finally:
        spoof.close()


def rp_nat_case(con, sniffer, deploy, spkm, endpoint, rps):
    """F3: two clients behind one address start together; both export, the
    second through the cookie path."""
    wait_rp_load_clear(con)
    i0 = len(sniffer.since(0))
    clients = [Rosenpass(deploy, p, endpoint, listen_port=RP_CLIENT_PORTS[p]) for p in (0, 1)]
    rps.extend(clients)
    deadline = time.monotonic() + RP_EXCHANGE_S + RP_BACKOFF_CAP_S
    for c in clients:
        try:
            c.wait_key(deadline)
        except Fail as e:
            raise Fail(f"rp nat: client {c.peer} behind the shared address did not export") from e
    cookied = [p for p in (0, 1) if rp_frames(sniffer, i0, outgoing=False, dport=RP_CLIENT_PORTS[p], kind=RP_COOKIE_REPLY)]
    if not cookied:
        raise Fail("rp nat: neither client took the cookie path; the per-IP refusal never engaged the gate")
    for p in cookied:
        rp_attribute_cookie(sniffer, i0, RP_CLIENT_PORTS[p], spkm, f"rp nat client {p}")
    for c in clients:
        c.stop()


def rp_fan_in_case(con, deploy, endpoint, rps):
    """F1, T8: three clients start together; one InitHello exceeds the cap of
    two in flight and is resent on upstream's backoff. All complete within
    three maximal handshakes, one backoff and the slack (T12). The 8-peer
    bound is derived (I4), not measured."""
    wait_rp_load_clear(con)
    start = time.monotonic()
    clients = [Rosenpass(deploy, p, endpoint, listen_port=RP_CLIENT_PORTS[p]) for p in (0, 1, 2)]
    rps.extend(clients)
    budget = 3 * RP_MCE_MAX_S + RP_BACKOFF_CAP_S + RP_SLACK_S
    for c in clients:
        try:
            c.wait_key(start + budget)
        except Fail as e:
            raise Fail(f"rp fan-in: client {c.peer} not done within {budget:.0f} s") from e
    for c in clients:
        c.stop()


def rp_global_drain_case(con, tap, sniffer, deploy, endpoint, hello, rps):
    """Spoofed InitHellos from rotating addresses at 0.2/s while a client
    exchanges, under load (engaged first by a per-IP spoof): `pq` sees no
    spoof but the legacy probe after each clearance (`RpInitHello` rises
    only by the client's exchanges and those probes, observed as
    RespHellos to spoofed addresses), the spoofs get CookieReplies, and the
    client completes."""
    wait_rp_load_clear(con)
    mark = con.mark()
    engage = RpSpoof(tap, [hello], [(PEER_IP, RP_SPOOF_PORT)], 10.0)
    rps.append(engage)
    try:
        con.wait_for(r"audit: src=ingress RpUnderLoad total=\d+ ", since=mark)
    finally:
        engage.close()
    engaged = con.mark()
    i0 = len(sniffer.since(0))
    sources = spoof_ips(64)
    spoof = RpSpoof(tap, [hello], sources, 0.2)
    rps.append(spoof)
    try:
        # At 0.2/s the first spoof is due after 5 s, and an exchange can
        # finish sooner (it does with mce460896): start the client once the
        # attack is under way, or it overlaps nothing.
        spoof.wait_delivered(1, "rp global drain")
        client = Rosenpass(deploy, 0, endpoint, listen_port=RP_CLIENT_PORTS[0])
        rps.append(client)
        rp_exchange(client, RP_EXCHANGE_S + RP_BACKOFF_CAP_S, "rp global drain")
        spoof.verify("rp global drain")
        client.stop()
    finally:
        spoof.close()
    spoofed = {ip for ip, _ in sources}
    if not spoof_answers_bounded(con, sniffer, i0, engaged, lambda ip, _: ip in spoofed, "rp global drain"):
        raise Fail("rp global drain: no spoofed source got a CookieReply")


# Free stack required below each McEliece PD's deepest use (M4 plan C8):
# the scrub writes SCRUB_DEPTH below its root wherever the root is called.
STACK_HEADROOM_MIN = 16 * 1024


def system_stack_size(pd: str) -> int:
    text = open(os.path.join(ROOT, "system/secureos.system")).read()
    m = re.search(rf'<protection_domain name="{pd}"[^>]*stack_size="(0x[0-9a-f_]+)"', text)
    if not m:
        raise Fail(f"no stack_size for {pd} in system/secureos.system")
    return int(m.group(1).replace("_", ""), 16)


def mce_const(name: str) -> int:
    """`pub const <name>: usize = <a> * 1024;` from mce460896."""
    text = open(os.path.join(ROOT, "crates/mce460896/src/lib.rs")).read()
    m = re.search(rf"pub const {name}: usize = (\d+) \* 1024;", text)
    if not m:
        raise Fail(f"{name} not found in crates/mce460896/src/lib.rs")
    return int(m.group(1)) * 1024


def stack_headroom_case(con, sizes=None, floors=None):
    """C8: pq and pqkey paint their free stack at init and print the deepest
    word used whenever it moves deeper (cpu::StackProbe); after the boot KAT
    and every exchange so far, each must leave STACK_HEADROOM_MIN free, at
    the stack_size the system file gives it.

    The probe must also have seen its own PD's scrub (pqkey's decaps,
    pq's encaps): a mark shallower than that means it is not measuring, and
    the headroom it reports is too good. Every printed line must parse: a
    line garbled by another PD's output would lose the deepest figure."""
    for pd in ("pq", "pqkey"):
        printed = con.count(rf"\b{pd}: stack high-water")
        lines = con.count(rf"\b{pd}: stack high-water (0x[0-9a-f]+) of (0x[0-9a-f]+)")
        if not lines:
            raise Fail(f"{pd}: no stack high-water line; the probe reported nothing")
        if len(printed) != len(lines):
            raise Fail(f"{pd}: {len(printed) - len(lines)} of {len(printed)} stack high-water lines garbled")
        size = (sizes or {}).get(pd) or system_stack_size(pd)
        painted = {int(n, 16) for _, n in lines}
        if painted != {size}:
            raise Fail(f"{pd}: probe painted {sorted(painted)} bytes, the system file gives {size}")
        hw = max(int(h, 16) for h, _ in lines)
        floor = (floors or {}).get(pd) or mce_const("SCRUB_DEPTH" if pd == "pqkey" else "SCRUB_DEPTH_ENCAPS")
        if hw < floor:
            raise Fail(f"{pd}: stack high-water {hw} B is below its own scrub depth {floor}; the probe is not measuring")
        print(f"\n{pd}: stack high-water {hw} B of {size} B, {size - hw} B free", flush=True)
        if size - hw < STACK_HEADROOM_MIN:
            raise Fail(f"{pd}: {size - hw} B of stack free, want at least {STACK_HEADROOM_MIN}")


def rp_conf_share_case(con, tap, deploy, endpoint, hello, conf, rps):
    """S-3, I5: a spoofed InitConf flood at the conf-global rate plus an
    InitHello flood while a client exchanges; its InitConf still lands (a
    fresh key_out opens a handshake)."""
    wait_rp_load_clear(con)
    sources = spoof_ips(128)
    confs = RpSpoof(tap, [conf], sources, 1e9 / rust_usize(INGRESS_CORE, "RP_CONF_GLOBAL_INTERVAL_NS"))
    hellos = RpSpoof(tap, [hello], sources[::-1], 2.0)
    rps.extend([confs, hellos])
    try:
        # Both floods under way before the client starts, or a fast
        # exchange overlaps nothing (the 2/s one, as in rp global drain).
        confs.wait_delivered(1, "rp conf share: InitConf flood")
        hellos.wait_delivered(1, "rp conf share: InitHello flood")
        client = Rosenpass(deploy, 0, endpoint, listen_port=RP_CLIENT_PORTS[0])
        rps.append(client)
        rp_exchange(client, RP_EXCHANGE_S + RP_BACKOFF_CAP_S, "rp conf share")
        confs.verify("rp conf share: InitConf flood")
        hellos.verify("rp conf share: InitHello flood")
        client.stop()
    finally:
        confs.close()
        hellos.close()


def rp_combined_flood_case(con, tap, gw_pub, deploy, endpoint, hello, rps):
    """S2: the WireGuard band flood plus spoofed InitHellos at a high rate
    under load; a master client still completes. Tier-2 suppressions are
    printed for the deviation log."""
    wait_rp_load_clear(con)
    mark = con.mark()
    flood = Flood(tap, gw_pub)
    rps.append(flood)
    flood.set_rate(BAND_RATE * arrival_refill())
    spoof = RpSpoof(tap, [hello], spoof_ips(256), 200.0)
    rps.append(spoof)
    try:
        client = Rosenpass(deploy, 0, endpoint, listen_port=RP_CLIENT_PORTS[0])
        rps.append(client)
        rp_exchange(client, RP_EXCHANGE_S + RP_BACKOFF_CAP_S, "rp combined flood")
        spoof.verify("rp combined flood")
        client.stop()
    finally:
        spoof.close()
        flood.close()
    suppressed = [int(n) for n in con.count(r"audit: src=ingress RpCookieSuppressed total=(\d+) ", since=mark)]
    print(f"\nrp combined flood: RpCookieSuppressed total up to {max(suppressed, default=0)} (coalesced)", flush=True)


def rp_latency_case(con, tap, gw_pub, deploy, endpoint, hello, rps):
    """Both directions: a WireGuard handshake under a Rosenpass flood, and a
    Rosenpass exchange under the WireGuard band flood, each in its budget."""
    wait_rp_load_clear(con)
    client = Rosenpass(deploy, 0, endpoint, listen_port=RP_CLIENT_PORTS[0])
    rps.append(client)
    rp_exchange(client, RP_EXCHANGE_S, "rp latency setup")
    spoof = RpSpoof(tap, [hello], spoof_ips(256), 200.0)
    rps.append(spoof)
    try:
        conf0 = open(os.path.join(deploy, "peer-0.conf")).read()
        budget = 3 * REKEY_ATTEMPT_S + HANDSHAKE_SLACK_S
        start = time.monotonic()
        peer = py_installed(conf0, gw_pub, client, start + budget)
        peer.close()
        spoof.verify("rp latency")
    except Fail as e:
        raise Fail(f"rp latency: no WireGuard handshake within {budget:.0f} s under a Rosenpass flood") from e
    finally:
        spoof.close()
        client.stop()
    wait_rp_load_clear(con)
    flood = Flood(tap, gw_pub)
    rps.append(flood)
    flood.set_rate(BAND_RATE * arrival_refill())
    try:
        client.start()
        rp_exchange(client, RP_EXCHANGE_S, "rp latency: a Rosenpass exchange under the WireGuard band flood")
        client.stop()
    finally:
        flood.close()


def rp_old_client_case(con, tap, deploy, endpoint, hello, rps):
    """VE13 [T11]: with load held (engaged by a per-IP spoof), a 0.2.3 client
    gets no RespHello; once the gate clears (RpLoadCleared since the mark)
    it completes."""
    wait_rp_load_clear(con)
    mark = con.mark()
    spoof = RpSpoof(tap, [hello], [(PEER_IP, RP_SPOOF_PORT)], 10.0)
    rps.append(spoof)
    con.wait_for(r"audit: src=ingress RpUnderLoad total=\d+ ", since=mark)
    spoof.close()
    old = Rosenpass(deploy, 2, endpoint, RP_023, listen_port=RP_CLIENT_PORTS[2])
    rps.append(old)
    hold = rust_usize(INGRESS_CORE, "RP_UNDER_LOAD_AFTER_NS") / 1e9
    con.wait_for(r"audit: src=ingress RpLoadCleared total=\d+ ", since=mark, timeout=hold + RP_SLACK_S + LINE_TIMEOUT_S)
    if old.osk() is not None:
        raise Fail("rp 0.2.3: the old client exported while the gate held")
    rp_exchange(old, RP_EXCHANGE_S, "rp 0.2.3 after load")
    old.stop()


def test_rp_gate(loader: str, deploy: str, passed: list):
    """Boot "rp gate" (M3b plan C6): the Rosenpass cookie gate under its
    attacks, each case after the previous one's load has cleared."""
    tap = Tap()
    inside = Wire()
    host = InsideHost(inside)
    try:
        child, con = boot(loader, tap.netdev("n0"), inside.netdev("n1"))
    except BaseException:
        tap.close()
        raise
    sniffer = None
    rps = []
    try:
        start_without_stop_signals(host)
        sniffer = Sniffer(RP_PORT)
        wait_tap_ready(tap, con)
        cfg = tomllib.load(open(os.path.join(deploy, "gateway.toml"), "rb"))
        gw_pub = b64(cfg["gateway"]["public_key"])
        spkm = open(os.path.join(deploy, cfg["gateway"]["rp_pub_path"]), "rb").read()
        endpoint = f"{ip_str(GW_IP)}:{RP_PORT}"
        con.wait_for(r"pq: ready", timeout=BOOT_TIMEOUT_S, strip_ready=True)
        # Prelude: one clean exchange, whose InitHello and InitConf the
        # spoofers replay (mac-valid; the mac key is public).
        prelude = Rosenpass(deploy, 0, endpoint, listen_port=RP_CLIENT_PORTS[0])
        rps.append(prelude)
        rp_exchange(prelude, RP_EXCHANGE_S, "rp gate prelude")
        prelude.stop()
        port0 = RP_CLIENT_PORTS[0]
        hello = rp_frames(sniffer, 0, outgoing=True, sport=port0, dport=RP_PORT, kind=RP_HELLO)[0][1]
        conf = rp_frames(sniffer, 0, outgoing=True, sport=port0, dport=RP_PORT, kind=RP_CONF)[0][1]
        cases = [
            ("rp spoof (S-3)", lambda: rp_spoof_case(con, tap, sniffer, deploy, spkm, endpoint, hello, rps)),
            ("rp nat (F3)", lambda: rp_nat_case(con, sniffer, deploy, spkm, endpoint, rps)),
            ("rp fan-in", lambda: rp_fan_in_case(con, deploy, endpoint, rps)),
            ("rp global drain", lambda: rp_global_drain_case(con, tap, sniffer, deploy, endpoint, hello, rps)),
            ("rp conf share", lambda: rp_conf_share_case(con, tap, deploy, endpoint, hello, conf, rps)),
            ("rp combined flood", lambda: rp_combined_flood_case(con, tap, gw_pub, deploy, endpoint, hello, rps)),
            ("rp latency", lambda: rp_latency_case(con, tap, gw_pub, deploy, endpoint, hello, rps)),
            ("rp 0.2.3 after load", lambda: rp_old_client_case(con, tap, deploy, endpoint, hello, rps)),
            # Last: the mark covers the boot KAT and every exchange above.
            ("stack headroom (C8)", lambda: stack_headroom_case(con)),
        ]
        for name, fn in cases:
            fn()
            sniffer.check_drops()
            no_sync_death(con, name)
            passed.append(name)
            print(f"\nPASS [{name}]", flush=True)
    finally:
        try:
            with signals_held():
                host.stop = True
                close_all(sniffer, *rps)
                kill(child)
                tap.close()
        except SystemExit:
            host.stop = True
            close_all(sniffer, *rps)
            kill(child)
            tap.close()
            raise


def test_cookie_a(loader: str, deploy: str, passed: list):
    """Boot "cookie-a": Rosenpass 0.2.3 interop (peer 2) and ingress's
    Rosenpass pairs, then the keepalive case and the paired cookie case
    (peer 1)."""
    tap = Tap()
    inside = Wire()
    host = InsideHost(inside)
    try:
        child, con = boot(loader, tap.netdev("n0"), inside.netdev("n1"))
    except BaseException:
        tap.close()
        raise
    py = py2 = sniffer = None
    rps = []
    try:
        start_without_stop_signals(host)
        sniffer = Sniffer(RP_PORT)
        wait_tap_ready(tap, con)
        cfg = tomllib.load(open(os.path.join(deploy, "gateway.toml"), "rb"))
        gw_pub = b64(cfg["gateway"]["public_key"])
        endpoint = f"{ip_str(GW_IP)}:{RP_PORT}"
        con.wait_for(r"pq: ready", timeout=BOOT_TIMEOUT_S, strip_ready=True)
        # 0.2.3 as its own peer, before the boot's first flood [R3-T-M6].
        mark = con.mark()
        rp2 = Rosenpass(deploy, 2, endpoint, RP_023)
        rps.append(rp2)
        osk2 = exported(con, rp2, mark, "rosenpass 0.2.3 interop: ")
        peer2 = open(os.path.join(deploy, "peer-2.conf")).read()
        py2 = py_installed(peer2, gw_pub, rp2, time.monotonic() + RP_EXCHANGE_S)
        if py2.init.psk != osk2:
            raise Fail("rosenpass 0.2.3 interop: the accepted handshake used another key than the export's")
        if not py_ping(py2, 3, ident=0x3233, src=PEER2_IP):
            raise Fail("rosenpass 0.2.3 interop: no ping reply through peer 2's session")
        rp2.stop()
        passed.append("rosenpass interop (0.2.3)")
        print("\nPASS [rosenpass 0.2.3 interop: the gateway's OSK is the client's key_out, ping through]")
        rp_deny_cases(con, sniffed_init_hello(sniffer), passed)

        # Peer 1 for the cases below; its client stops once hs has the PSK,
        # which both cases finish well within REJECT_AFTER_TIME of.
        rp1 = Rosenpass(deploy, 1, endpoint)
        rps.append(rp1)
        peer1 = open(os.path.join(deploy, "peer-1.conf")).read()
        py = py_installed(peer1, gw_pub, rp1, time.monotonic() + RP_EXCHANGE_S)
        rp1.stop()
        keepalive_case(con, py)
        passed.append("passive keepalive")
        print("\nPASS [passive keepalive: one empty message 10-13 s after unanswered data, none after a reply]")
        paired_case(con, tap, peer1, gw_pub, py.init.psk)
        passed.append("cookie path, paired")
        print("\nPASS [cookie path, paired: port B denied, port A allowed, load cleared in its window]")
    finally:
        try:
            with signals_held():
                host.stop = True
                close_all(py, py2, sniffer, *rps)
                kill(child)
                tap.close()
        except SystemExit:
            host.stop = True
            close_all(py, py2, sniffer, *rps)
            kill(child)
            tap.close()
            raise


def attribute_wireguard_go(sniffer: Sniffer, con: Console, gw_pub: bytes, deadline: float):
    """Flood step 1's attribution, judged before the ping: a cookie reply to
    wireguard-go's port answers one of its sniffed initiations and opens
    with the public cookie key; then wireguard-go sends an initiation whose
    mac2 is made from that cookie; then WgMac2Accepted total=1 appears. By
    exclusion it is wireguard-go's: nothing else in this boot has sent a
    mac2 yet."""
    inits, cookies = [], []
    mac2_at = None
    seen = 0
    while mac2_at is None:
        frames = sniffer.since(seen)
        seen += len(frames)
        for t, f, outgoing in frames:
            u = udp_fields(f)
            if u is None:
                continue
            _, sport, _, dport, p = u
            if outgoing and (sport, dport) == (WG_LISTEN_PORT, WG_PORT) and len(p) == 148 and p[0] == 1:
                if any(wg_mod.with_mac2(p, c) == p for c in cookies):
                    mac2_at = t
                    break
                inits.append(p)
            elif not outgoing and (sport, dport) == (WG_PORT, WG_LISTEN_PORT) and len(p) == 64 and p[0] == 3:
                for i in inits:
                    if i[4:8] != p[4:8]:
                        continue
                    try:
                        cookies.append(wg_mod.open_cookie_reply(gw_pub, p, i))
                        break
                    except Exception:
                        continue
        sniffer.check_drops()
        if mac2_at is None and time.monotonic() > deadline:
            if not inits:
                raise Fail("cookie attribution failed: no initiation from wireguard-go sniffed")
            if not cookies:
                raise Fail("cookie attribution failed: no cookie reply to wireguard-go's port opens for its initiations")
            raise Fail("cookie attribution failed: wireguard-go sent no initiation with a mac2 under the cookie")
        time.sleep(0.05)
    left = max(0.0, deadline - time.monotonic()) + LINE_TIMEOUT_S
    m = con.wait_for(r"audit: src=ingress WgMac2Accepted total=1 ", timeout=left)
    if con.time_at(m.end()) < mac2_at:
        raise Fail("cookie attribution failed: WgMac2Accepted total=1 came before wireguard-go's mac2 initiation")


def wg_go_conf(deploy: str) -> str:
    """Peer 0 straight at the gateway's outside address, from a fixed port."""
    conf = open(os.path.join(deploy, "peer-0.conf")).read()
    conf = re.sub(r"^Endpoint = .*$", f"Endpoint = {ip_str(GW_IP)}:{WG_PORT}", conf, flags=re.M)
    conf = conf.replace("[Interface]\n", f"[Interface]\nListenPort = {WG_LISTEN_PORT}\n", 1)
    path = os.path.join(deploy, "wg-cookie.conf")
    with open(path, "w") as f:
        f.write(conf)
    os.chmod(path, 0o600)
    return path


def flood_case(con: Console, tap: Tap, sniffer: Sniffer, deploy: str, gw_pub: bytes, cfg: dict, opened: list):
    """Cookie under flood [M1, M2, R2-S-N2, R3-F-F3, R3-T-P1]. `opened`
    collects what the caller's teardown must close."""
    refill = arrival_refill()
    flood = Flood(tap, gw_pub)
    opened.append(flood)
    band = BAND_RATE * refill
    # C first, from an over-capacity probe; the band flood follows without a
    # gap, so load holds from WgUnderLoad total=1 on.
    c, _ = probe_capacity(con, tap, flood, after_rate=band)
    try:
        con.wait_for(r"audit: src=ingress WgUnderLoad total=1 ")
    except Fail:
        raise Fail("precondition: WgUnderLoad total=1 did not appear before any peer traffic")
    lo1, hi1 = BAND_LOW * refill, BAND_HIGH * c
    # The below-capacity survival ratio, from this band flood.
    _, before = cookie_totals(con)
    pre = flood.snapshot()
    time.sleep(PRECONDITION_S)
    post = flood.snapshot()
    time.sleep(0.2)
    after, _ = cookie_totals(con)
    late = flood.snapshot()
    check_band("precondition flood", pre, post, lo1, hi1)
    # Conservative: line totals bound the counts from the safe side, and
    # what was sent while the lines settled is not credited.
    s1 = min(1.0, max(0.0, (after - before - (late[0] - post[0])) / (post[0] - pre[0])))
    attempts = 1 + tries_for(s1 * s1)
    hs_deadline = attempts * REKEY_ATTEMPT_S + HANDSHAKE_SLACK_S
    ping1 = max(3, tries_for(s1))
    # Over capacity a frame survives about C / rate. The ratio is the fixed
    # STEP2_RATE, so s2 is a constant; step 2 measures its own survival.
    rate2 = STEP2_RATE * c
    s2 = SURVIVAL_MARGIN * c / rate2
    ping2 = tries_for(s2)
    print(f"\nbudgets: below capacity survival {s1:.3f} -> wireguard-go deadline {hs_deadline:.1f} s "
          f"({attempts} attempts), {ping1} ping tries; step 2 survival {s2:.3f} -> {ping2} ping tries "
          f"({ping_budget(ping2):.0f} s)", flush=True)

    # WireGuard after a flood waits for a fresh PSK, under a named budget
    # [R3-T-M7]; Rosenpass has its own meters, so it completes under the
    # band flood. Peer 0's is the boot's first export, so it is printed.
    endpoint = f"{ip_str(GW_IP)}:{RP_PORT}"
    mark = con.mark()
    rp0 = Rosenpass(deploy, 0, endpoint)
    opened.append(rp0)
    exported(con, rp0, mark, "PSK went stale during flood: ")

    # Flood step 1, below capacity: wireguard-go (re)started on a fixed port.
    # The probe saturates ingress, where the reserve does bind, so this
    # boot's first WgCookieSuppressed is the probe's; the paired case's
    # fresh-boot total=1 check is the authoritative one. Here: no new line
    # during step 1, which is blind to as many suppressions as fit before
    # the next coalesced line [code review T3].
    suppressed = [int(n) for n in con.count(r"audit: src=ingress WgCookieSuppressed total=(\d+) ")]
    blind = 63 if suppressed else 0
    print(f"\nflood step 1: highest WgCookieSuppressed total before it {max(suppressed, default=0)}; "
          f"up to {blind} suppressions in step 1 would print no line", flush=True)
    step1 = flood.snapshot()
    step1_mark = con.mark()
    wg = WgGo(wg_go_conf(deploy), "10.200.0.2/32", cfg["gateway"]["inside_prefix"], rp0)
    opened.append(wg)
    try:
        before_hs = wg.latest_handshake()
        trigger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        trigger.sendto(b"x", (ip_str(HOST_IP), 9))
        trigger.close()
        started = time.monotonic()
        attribute_wireguard_go(sniffer, con, gw_pub, started + hs_deadline)
        print(f"\nflood step 1: wireguard-go's mac2 accepted {time.monotonic() - started:.1f} s after its start",
              flush=True)
        deadline = time.monotonic() + REKEY_ATTEMPT_S
        while wg.latest_handshake() == before_hs:
            if time.monotonic() > deadline:
                raise Fail("cookie attribution failed: wireguard-go reports no new handshake")
            time.sleep(0.1)
        if con.count(r"audit: src=ingress WgLoadCleared "):
            raise Fail("flood step 1: WgLoadCleared between WgUnderLoad and the handshake: load did not hold")
        ping(tries=ping1)
        if con.count(r"audit: src=ingress WgCookieSuppressed ", since=step1_mark):
            raise Fail("flood step 1: WgCookieSuppressed during step 1: the TX reserve bound below capacity")
    except Fail as e:
        check_low_band_first("flood step 1", step1, flood.snapshot(), lo1, e)
        raise
    check_band("flood step 1", step1, flood.snapshot(), lo1, hi1)
    sniffer.check_drops()
    print("\nPASS [cookie flood step 1: wireguard-go drew a cookie, handshook with mac2 and pinged below capacity]",
          flush=True)
    wg.close()
    opened.remove(wg)

    # The Python peer's session, made under load through the cookie path
    # right before step 2, once its fresh PSK is installed: until then hs
    # has none for peer 1 and refuses, so the handshake is retried with the
    # current key_out.
    peer1 = open(os.path.join(deploy, "peer-1.conf")).read()
    rp1 = Rosenpass(deploy, 1, endpoint)
    opened.append(rp1)
    deadline = time.monotonic() + RP_EXCHANGE_S
    py = None
    while py is None:
        psk = rp1.wait_key(deadline)
        py = PyPeer(peer1, gw_pub, psk)
        if not cookie_handshake(py, tries_for(s1 * s1) + 1):
            py.close()
            py = None
            if time.monotonic() > deadline:
                raise Fail(f"PSK went stale during flood: no handshake for peer 1 within {RP_EXCHANGE_S:.0f} s "
                           "of its rosenpass start")
    opened.append(py)
    if not py_ping(py, ping1, ident=0x4642):
        raise Fail("precondition: no Python-peer session under load through the cookie path")
    budget2 = STEP2_WARMUP_S + ping_budget(ping2)
    age = time.monotonic() - py.established
    if age + budget2 >= rust_const(WG_CORE, "REJECT_AFTER_TIME_NS") / NS:
        raise Fail(f"precondition: session age {age:.0f} s leaves no room for step 2's {budget2:.0f} s budget")

    # Flood step 2, over capacity, running until the ping assertion concludes.
    before2, _ = cookie_totals(con)
    step2 = flood.set_rate(rate2)
    time.sleep(STEP2_WARMUP_S)
    ok = py_ping(py, ping2, ident=0x4643)
    print(f"\nflood step 2: ping reply on try {ok} of {ping2}", flush=True)
    if not flood.running():
        raise Fail("flood step 2: the flood was not running when the ping assertion concluded")
    end2 = flood.set_rate(0)
    check_band("flood step 2", step2, end2, STEP2_BAND[0] * c, STEP2_BAND[1] * c)
    # Step 2's own survival, as probe_capacity counts it: what ingress
    # answered until an ARP round trip proves the queues drained, over what
    # was sent; the upper bound, so a shortfall is never overstated.
    if arp_round_trip(tap, LINE_TIMEOUT_S) is None:
        raise Fail("flood step 2: no ARP reply after the flood; the queues did not drain")
    time.sleep(PROBE_SETTLE_S)
    _, after2 = cookie_totals(con)
    s2m = (after2 - before2) / (end2[0] - step2[0])
    print(f"\nflood step 2: measured survival {s2m:.3f} (budget assumed {s2:.3f})", flush=True)
    if not ok and s2m < s2:
        raise Fail(f"flood step 2: measured survival {s2m:.3f} below the budget's assumption {s2:.3f}; "
                   f"{ping2} failed ping tries not judged")
    if not ok:
        raise Fail(f"flood step 2: no ping reply through the established session in {ping2} tries over capacity")
    sniffer.check_drops()


def test_cookie_b(loader: str, deploy: str, passed: list):
    """Boot "cookie-b": the flood case."""
    tap = Tap()
    inside = Wire()
    host = InsideHost(inside)
    try:
        child, con = boot(loader, tap.netdev("n0"), inside.netdev("n1"))
    except BaseException:
        tap.close()
        raise
    sniffer = None
    opened = []
    try:
        start_without_stop_signals(host)
        sniffer = Sniffer(WG_LISTEN_PORT)
        wait_tap_ready(tap, con)
        cfg = tomllib.load(open(os.path.join(deploy, "gateway.toml"), "rb"))
        flood_case(con, tap, sniffer, deploy, b64(cfg["gateway"]["public_key"]), cfg, opened)
        passed.append("cookie under flood")
        print("\nPASS [cookie under flood: step 1 attributed below capacity, step 2 ping over capacity]")
    finally:
        try:
            with signals_held():
                host.stop = True
                close_all(*opened, sniffer)
                kill(child)
                tap.close()
        except SystemExit:
            host.stop = True
            close_all(*opened, sniffer)
            kill(child)
            tap.close()
            raise


# ---------------------------------------------------------------- driver


ORACLE_PINS = os.path.join(os.path.dirname(__file__), "rosenpass-oracle.sha256")
ORACLE_BINS = {"/opt/rosenpass-master/rosenpass", "/opt/rosenpass-023/rosenpass"}


def check_rosenpass_oracle():
    """VE9: the upstream rosenpass binaries baked into the dev image are the
    ones the repo pins (both builds are bit-reproducible, so a mismatch means
    a stale image or a changed Dockerfile stage)."""
    pins = dict(reversed(line.split()) for line in open(ORACLE_PINS) if line.strip())
    if set(pins) != ORACLE_BINS:
        raise Fail(f"{ORACLE_PINS} must pin exactly {sorted(ORACLE_BINS)}, has {sorted(pins)}")
    for path, want in sorted(pins.items()):
        try:
            got = hashlib.sha256(open(path, "rb").read()).hexdigest()
        except FileNotFoundError:
            raise Fail(f"rebuild the image: {path} is missing (VE9 oracle)") from None
        if got != want:
            raise Fail(f"rebuild the image: {path} has sha256 {got}, the repo pins {want}")


def check_oracle_not_in_image(loader: str):
    """VE9: the oracle never enters an seL4 image. Each binary's ELF and
    program headers (its entry point and segment layout, unique to it) must
    not occur in the packaged loader. Code or tables could match by accident:
    the oracle links some of the same crates."""
    image = open(loader, "rb").read()
    for path in sorted(ORACLE_BINS):
        data = open(path, "rb").read()
        if data[:256] in image:
            raise Fail(f"{loader} contains part of {path}")


def preflight():
    check_rosenpass_oracle()
    missing = [t for t in ("unshare", "setpriv", "wireguard-go", "wg", "ip", "ping", "qemu-system-aarch64")
               if not shutil.which(t)]
    if missing:
        raise Fail(f"missing tools: {missing}")
    if not os.path.exists("/dev/net/tun"):
        raise Fail("/dev/net/tun not available")
    import cryptography  # noqa: F401  (fail, never skip)
    # The seccomp profile allows exactly CLONE_NEWUSER|CLONE_NEWNET (M2 review T14).
    if subprocess.run(["unshare", "-rn", "true"], capture_output=True).returncode != 0:
        raise Fail("unshare -rn refused (seccomp profile not applied?)")
    # CLONE_NEWUTS needs no mount step, so a refusal here is the unshare
    # syscall itself being filtered, not a later mount(2) failing.
    r = subprocess.run(["unshare", "-r", "--uts", "true"], capture_output=True, text=True)
    if r.returncode == 0 or "unshare failed" not in r.stderr:
        raise Fail(f"unshare(NEWUSER|NEWUTS) not refused by the filter: rc={r.returncode} {r.stderr.strip()}")
    # VE8: the cookie boots need a tap and AF_PACKET inside the netns.
    r = subprocess.run(["unshare", "-rn", "ip", "tuntap", "add", "dev", "tapcheck", "mode", "tap"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise Fail(f"cannot create a tap device inside unshare -rn (VE8): {r.stderr.strip()}")
    r = subprocess.run(["unshare", "-rn", sys.executable, "-c",
                        "import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0).close()"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise Fail(f"cannot open an AF_PACKET socket inside unshare -rn (VE8): {r.stderr.strip()[-300:]}")


def make(*args, env=None):
    r = subprocess.run(["make", "-C", ROOT, *args], env=env, capture_output=True, text=True)
    if r.returncode:
        raise Fail(f"make {' '.join(args)} failed:\n{r.stdout[-2000:]}{r.stderr[-2000:]}")


def build(tmp: str) -> tuple:
    """Three deployments: A (packaged normally, three peers: the third is
    the Rosenpass 0.2.3 client's), B (only its `key` blob, packaged onto
    A's image for the mismatch case) and C (two peers with their Rosenpass
    keys swapped, its own image: the peer binding case)."""
    for name, peers in (("a", "3"), ("b", "3"), ("c", "2")):
        subprocess.run(["cargo", "run", "--locked", "-q", "-p", "mksecrets", "--", "--template",
                        os.path.join(ROOT, "config/gateway.toml"), "--peers", peers, "--out",
                        os.path.join(tmp, name)], check=True, cwd=ROOT)
    swap_rp_records(os.path.join(tmp, "c/gateway.toml"))
    env = {**os.environ, "SECUREOS_CONFIG": os.path.join(tmp, "a/gateway.toml")}
    make("image", env=env)
    make("package", f"SECRETS={tmp}/a/secrets.bin", f"PQ_SECRETS={tmp}/a/pqkey-secrets.bin", f"OUT={tmp}/a/pkg",
         env=env)
    # Only `key`'s blob mismatches: pqkey keeps A's, so `key` is what halts.
    make("package", f"SECRETS={tmp}/b/secrets.bin", f"PQ_SECRETS={tmp}/a/pqkey-secrets.bin", f"OUT={tmp}/b/pkg",
         env=env)
    env_c = {**os.environ, "SECUREOS_CONFIG": os.path.join(tmp, "c/gateway.toml")}
    make("package", f"SECRETS={tmp}/c/secrets.bin", f"PQ_SECRETS={tmp}/c/pqkey-secrets.bin", f"OUT={tmp}/c/pkg",
         env=env_c)
    loaders = tuple(f"{tmp}/{name}/pkg/loader.img" for name in ("a", "b", "c"))
    for loader in loaders:
        check_oracle_not_in_image(loader)
    return loaders


def check_harness_matches_config(deploy: str):
    """Every address the harness plays or expects comes from the generated
    config (template plus mksecrets' peer addresses); fail by name before
    any boot if one moves."""
    cfg = tomllib.load(open(os.path.join(deploy, "gateway.toml"), "rb"))
    g = cfg["gateway"]
    ip = lambda b: ".".join(map(str, b))  # noqa: E731
    mac = lambda b: b.hex(":")  # noqa: E731
    expected = {
        "gateway.outside_ip": (g["outside_ip"], ip(GW_IP)),
        "gateway.outside_mac": (g["outside_mac"], mac(GW_MAC)),
        "gateway.outside_router_mac": (g["outside_router_mac"], mac(PEER_MAC)),
        "gateway.listen_port": (g["listen_port"], WG_PORT),
        "gateway.rp_port": (g["rp_port"], RP_PORT),
        "gateway.inside_ip": (g["inside_ip"], ip(INSIDE_IP)),
        "gateway.inside_mac": (g["inside_mac"], mac(INSIDE_MAC)),
        "neighbors[0].ip": (cfg["neighbors"][0]["ip"], ip(HOST_IP)),
        "neighbors[0].mac": (cfg["neighbors"][0]["mac"], mac(HOST_MAC)),
        "peers[0].allowed_ips": (cfg["peers"][0]["allowed_ips"], ["10.200.0.2/32"]),
        # Case 4 sends from 10.200.0.99 as peer 1, which must not own it.
        "peers[1].allowed_ips": (cfg["peers"][1]["allowed_ips"], ["10.200.0.3/32"]),
        # The Rosenpass 0.2.3 client's, pinged from as peer 2.
        "peers[2].allowed_ips": (cfg["peers"][2]["allowed_ips"], [ip(PEER2_IP) + "/32"]),
    }
    wrong = [f"{k}={got!r} (harness uses {want!r})" for k, (got, want) in expected.items() if got != want]
    if wrong:
        raise Fail("config/gateway.toml no longer matches the harness: " + "; ".join(wrong))


def in_netns(good: str, mismatched: str, binding: str, deploy: str) -> int:
    guard_thread_starts()
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    try:
        check_harness_matches_config(deploy)
    except Fail as e:
        print(f"\nFAIL [setup]: {e}", file=sys.stderr)
        return 1
    # Each case appends to `passed` only once its assertions held; the
    # count printed is what ran, not a constant (code review T1).
    passed = []

    def single(name, fn):
        def run():
            fn()
            passed.append(name)
        return run

    cases = [("reason list in sync", single("reason list", check_reason_list_matches_rust)),
             ("raw frames", single("raw frames", lambda: test_raw(good))),
             ("wireguard", lambda: test_wireguard(good, deploy, passed)),
             ("cookie boot a", lambda: test_cookie_a(good, deploy, passed)),
             ("cookie boot b", lambda: test_cookie_b(good, deploy, passed)),
             ("rp gate boot", lambda: test_rp_gate(good, deploy, passed)),
             ("peer binding", lambda: test_peer_binding(binding, os.path.join(os.path.dirname(deploy), "c"), passed)),
             ("mismatched blob halts key", single("mismatched blob", lambda: test_mismatched_blob(mismatched)))]
    for name, fn in cases:
        try:
            fn()
        except (Fail, pexpect.TIMEOUT, pexpect.EOF, subprocess.CalledProcessError, OSError) as e:
            print(f"\nFAIL [{name}]: {type(e).__name__}: {e}", file=sys.stderr)
            return 1
        print(f"\nPASS [{name}]")
    print(f"INTEGRATION-CASES {len(passed)}")
    return 0


# Resolved at import: preexec_fn runs between fork and exec, where importing
# (and its lock) is unsafe once other threads exist.
_LIBC = ctypes.CDLL(None, use_errno=True)
PR_SET_PDEATHSIG = 1


# Children of the (multi-threaded) netns harness get PR_SET_PDEATHSIG from
# setpriv rather than a preexec_fn, which is unsafe once threads exist. For
# wireguard-go (subprocess) that removes Python code from the fork child; for
# QEMU, pexpect still runs a little Python between fork and exec (accepted).
DIE_WITH_PARENT = ["setpriv", "--pdeathsig", "KILL", "--"]


def die_with_parent():
    """SIGKILL this process when its parent dies (PR_SET_PDEATHSIG): used by
    the netns harness on itself right after exec. Together with setpriv for
    QEMU and wireguard-go this closes the orphan race at the harness level
    (each child still has a fork-to-prctl window)."""
    if _LIBC.prctl(PR_SET_PDEATHSIG, signal.SIGKILL) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG)")


STOP_SIGNALS = {signal.SIGTERM, signal.SIGHUP, signal.SIGINT}


def ignore_signals():
    """Once the run is ending: no further signal may cut the teardown short.
    Blocked in one call first, so the per-signal loop has no window."""
    signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
    for s in STOP_SIGNALS:
        signal.signal(s, signal.SIG_IGN)


@contextlib.contextmanager
def signals_held():
    """Blocks stop signals for a teardown in the middle of the run; one that
    arrives meanwhile is delivered when the teardown has finished.

    A handler already pending can also run while this is being entered,
    before its own try: callers wrap it in `try: ... except SystemExit:`
    repeating the (idempotent) teardown, as final_teardown's caller does."""
    held = None
    try:
        old = signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
    except SystemExit as e:
        # A handler already pending ran inside the blocking call (CPython
        # runs it once the mask is set) and has ignored further signals:
        # still run the teardown, then end the run.
        held = e
        old = None
    try:
        yield
    finally:
        if old is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, old)
        if held is not None:
            raise held


def exit_on_signal(signum, _frame):
    # Turn SIGTERM/SIGHUP/SIGINT into SystemExit so `finally` blocks run: the
    # temp dir holds private keys and must go on every exit path.
    ignore_signals()
    raise SystemExit(128 + signum)


def main() -> int:
    for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(s, exit_on_signal)
    if sys.argv[1:2] == ["--netns"]:
        # Re-armed after exec (PDEATHSIG survives unshare's exec, but checking
        # the parent closes the race where it died before this point).
        die_with_parent()
        # Compare with the outer harness's own pid: under a subreaper an
        # orphan is not reparented to 1.
        if str(os.getppid()) != os.environ.get("SECUREOS_IT_PARENT"):
            print("\nFAIL [setup]: outer harness already gone", file=sys.stderr)
            return 1
        return in_netns(*sys.argv[2:6])
    tmp = tempfile.mkdtemp(prefix="secureos-it-")
    status = 1
    try:
        preflight()
        good, mismatched, binding = build(tmp)
        # `unshare` execs the child, so the Popen pid is the netns harness.
        # The outer harness has no threads, so preexec_fn is safe here.
        child = subprocess.Popen(["unshare", "-rn", sys.executable, os.path.abspath(__file__), "--netns",
                                  good, mismatched, binding, os.path.join(tmp, "a")], preexec_fn=die_with_parent,
                                 env={**os.environ, "SECUREOS_IT_PARENT": str(os.getpid())})
        try:
            status = child.wait()
        except BaseException:
            # Let the child run its own teardown (QEMU, wireguard-go, UAPI
            # socket) before the temp dir goes; kill only if it hangs. The
            # child ignores repeated signals, so forwarding cannot interrupt it.
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
                print("\nFAIL [teardown]: netns harness ignored SIGTERM; killed", file=sys.stderr)
            raise
    except Fail as e:
        print(f"\nFAIL [setup]: {e}", file=sys.stderr)
    finally:
        # A handler can also run on entry to final_teardown, before its own
        # try: hold that exit here and finish the teardown regardless.
        try:
            removed, held = final_teardown(tmp)
        except SystemExit as e:
            removed, held = final_teardown(tmp)[0], e
        if not removed:
            status = 1
        if held is not None:
            raise held
    return status


def final_teardown(tmp: str):
    """Removes the key-bearing temp dir with stop signals off. A handler
    already pending runs inside ignore_signals' blocking call and raises;
    that exit is held and returned so the removal and its report still
    happen. Returns (removed, held exit or None)."""
    held = None
    try:
        ignore_signals()
    except SystemExit as e:
        held = e
        ignore_signals()
    left = []
    shutil.rmtree(tmp, onexc=lambda _f, p, e: left.append(f"{p}: {e}"))
    if left or os.path.exists(tmp):
        # A key-bearing leftover must fail the run.
        print(f"\nFAIL [teardown]: could not remove {tmp} (holds keys): {left}", file=sys.stderr)
        return False, held
    return True, held

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wg as wg_mod  # noqa: E402
import rp_cookie  # noqa: E402  (the cookie twin, checked by tests/tools/test_rp_cookie_twin.py)

if __name__ == "__main__":
    sys.exit(main())
