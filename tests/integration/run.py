"""Builds a dev deployment and exercises it end to end (plan C18).

Usage: run.py            (from `make test`)

Generates fresh keys with tools/mksecrets into a temporary directory
(removed on every exit path), builds the image against that configuration
and packages it, then re-runs itself inside `unshare -rn` (no NET_ADMIN in
the container; architecture R5) for five boots:

  1. raw frames: the outside NIC on a `-netdev dgram` socket; ARP, one frame
     per wire::DropReason, a coalesced flood, ARP as the liveness barrier;
  2. WireGuard: the outside NIC on user-net with a hostfwd to 51820, the
     inside NIC on a dgram socket played by a Python inside host;
     wireguard-go is the interop oracle, tests/integration/wg.py sends what
     wireguard-go will not. Every negative case asserts a positive audit
     line and then a liveness barrier (a ping through wireguard-go);
  3. cookie-a and 4. cookie-b (M2.5 plan C6), each a fresh boot so audit
     totals start at zero: the outside NIC on a tap in the netns, which
     plays the router (10.0.2.2) for Python sockets and wireguard-go and
     carries spoofed frames injected with AF_PACKET. cookie-a runs the
     passive keepalive case, then the paired cookie case under a
     below-capacity flood; cookie-b the cookie-under-flood case;
  5. a blob whose public key does not match the configuration: `key`
     prints the mismatch and halts.

Missing prerequisites fail the run; nothing is skipped.
"""

import base64
import bisect
import contextlib
import ctypes
import errno
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

READY = ["eth_out: ready", "ingress: ready", "audit: ready", "inner: ready", "data: ready", "hs: ready"]
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
    block = src[src.index("drop_reasons! {"):]
    block = block[: block.index("}")]
    rust = re.findall(r"^\s+(\w+) = \d+,", block, re.M)
    if rust != DROP_REASONS + FORWARD_ONLY:
        raise Fail(f"DROP_REASONS out of sync with wire: {rust}")


# ---------------------------------------------------------------- harness


# QEMU's serial console ends lines with "\r\r\n".
READY_LINE = re.compile(r"(eth_out|eth_in|ingress|inner|data|hs|audit): ready\r*\n")


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
                text = READY_LINE.sub("", text)
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

    def pmem(self, addr: int, size: int, path: str) -> bytes:
        # HMP parses an unquoted absolute path as part of the preceding
        # integer expression (`/tmp/...` starts with division). JSON string
        # quoting is accepted by HMP and also handles unusual path bytes.
        # A stale snapshot from an earlier call must never be read back.
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        self.sock.sendall(f"pmemsave {addr:#x} {size:#x} {json.dumps(path)}\n".encode())
        reply = self._read_until(b"(qemu) ")
        if not os.path.exists(path):
            detail = reply.decode(errors="replace").strip()
            raise Fail(f"pmemsave did not create {path}: {detail}")
        try:
            with open(path, "rb") as f:
                data = f.read()
        finally:
            # The dump holds guest RAM, secrets region included.
            os.unlink(path)
        if len(data) != size:
            raise Fail(f"pmemsave returned {len(data)} of {size} bytes")
        return data


# Guest RAM scanned for residue. Which frames back which region at run time
# is not knowable from the Microkit report, so the whole window is read and
# a positive control (a session key that data or hs memory must hold) proves
# it covers PD memory.
OBJECT_RAM = (0x6000_0000, 0x0200_0000)


def wait_absent(mon: Monitor, needle: bytes, control: bytes, scratch: str, timeout: float = 5.0):
    """Polls until `needle` occurs nowhere in OBJECT_RAM while `control`
    does, in the same snapshot (bounded: the 1 Hz timer retries the reclaim
    if a wakeup was missed). A missing control fails: the scan would prove
    nothing."""
    base, size = OBJECT_RAM
    deadline = time.monotonic() + timeout
    while True:
        ram = mon.pmem(base, size, scratch)
        if ram.find(control) < 0:
            raise Fail("scan window does not cover PD memory: live session key not found")
        at = ram.find(needle)
        if at < 0:
            return
        if time.monotonic() > deadline:
            raise Fail(f"install message still in guest RAM at {base + at:#x}")
        time.sleep(0.2)


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
    by every netns in the container, so the interface name is per run."""

    def __init__(self, conf: str, address: str, inside_prefix: str):
        self.inside_prefix = inside_prefix
        self.dev = dev = f"wgt{os.getpid() % 100000}"
        self.proc = subprocess.Popen(DIE_WITH_PARENT + ["wireguard-go", "-f", dev], stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, env={**os.environ, "LOG_LEVEL": "error"})
        try:
            self._configure(conf, address)
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
        sh("ip", "addr", "add", address, "dev", dev)
        sh("ip", "link", "set", dev, "up")
        sh("ip", "route", "add", self.inside_prefix, "dev", dev)

    def latest_handshake(self) -> int:
        out = sh("wg", "show", self.dev, "latest-handshakes").stdout.split()
        return int(out[1]) if len(out) >= 2 else 0

    def close(self):
        self.proc.kill()
        self.proc.wait()
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


def test_wireguard(loader: str, deploy: str, passed: list):
    inside = Wire()
    hostfwd = free_udp_port()
    host = InsideHost(inside)
    monitor = os.path.join(deploy, "monitor.sock")
    child, con = boot(loader, f"user,id=n0,net=10.0.2.0/24,hostfwd=udp:127.0.0.1:{hostfwd}-:{WG_PORT}",
                      inside.netdev("n1"), monitor)
    wg = None
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

        # Case 1: wireguard-go handshakes (first ping triggers it; it
        # retries every 5 s while the image is still booting).
        wg = WgGo(conf0, "10.200.0.2/32", cfg["gateway"]["inside_prefix"])
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

        def initiator(conf: str, psk=None, static=None):
            return wg_mod.Initiator(static or b64(conf_value(conf, "PrivateKey")), gw_pub,
                                    psk or b64(conf_value(conf, "PresharedKey")), sender=secrets.randbits(32))

        out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        out.bind(("127.0.0.1", 0))
        out.settimeout(REPLY_TIMEOUT_S)

        def handshake(i) -> bool:
            out.sendto(i.initiation(ts_offset_s=30), ("127.0.0.1", hostfwd))
            resp, _ = out.recvfrom(2048)
            return i.consume_response(resp)

        # Case 2: peer 0's own key with a wrong PSK and a newer timestamp.
        mark = con.mark()
        bad = initiator(peer0, psk=b"\x42" * 32)
        out.sendto(bad.initiation(ts_offset_s=30), ("127.0.0.1", hostfwd))
        resp, _ = out.recvfrom(2048)
        # Allow side first: the same response opens with peer 0's real PSK,
        # so the failure below is the PSK, not a broken response.
        probe = initiator(peer0)
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
        out.sendto(initiator(peer1, static=secrets.token_bytes(32)).initiation(), ("127.0.0.1", hostfwd))
        con.wait_for(r"audit: src=hs HandshakeUnknownPeer total=1 ", since=mark)
        ping(tries=3)
        passed.append("unknown peer")
        print("\nPASS [unknown peer rejected]")

        # Case 4: valid peer 1 sends a datagram with a source outside its
        # allowed IPs (10.200.0.3/32).
        mark = con.mark()
        good = initiator(peer1)
        if not handshake(good):
            raise Fail("peer 1 handshake failed")
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
    finally:
        try:
            with signals_held():
                host.stop = True
                if wg:
                    wg.close()
                kill(child)
        except SystemExit:
            host.stop = True
            if wg:
                wg.close()
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

    def __init__(self, conf: str, gw_pub: bytes, port: int = 0):
        self.gw_pub = gw_pub
        self.init = wg_mod.Initiator(b64(conf_value(conf, "PrivateKey")), gw_pub, b64(conf_value(conf, "PresharedKey")),
                                     sender=secrets.randbits(32))
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


def py_ping(peer: PyPeer, tries: int, ident: int) -> int:
    """ICMP echoes through the Python peer's session to the inside host, one
    per PING_INTERVAL_S, each an independent try: the sequence number of the
    first reply, or 0 once PING_WAIT_S passed after the last send."""
    seq, next_send, until = 0, time.monotonic(), None
    while True:
        if seq < tries and time.monotonic() >= next_send:
            seq += 1
            peer.send(peer.init.transport(icmp_echo(PEER1_IP, HOST_IP, 8, ident, seq, b"secureos")))
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


def paired_case(con: Console, tap: Tap, peer_conf: str, gw_pub: bytes):
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
            m = con.wait_for(r"audit: src=ingress WgUnderLoad total=1 ", since=mark)
        except Fail:
            raise Fail("paired: WgUnderLoad total=1 did not appear under the band flood")
        loaded_at = mark + m.start()
        a, b = PyPeer(peer_conf, gw_pub), PyPeer(peer_conf, gw_pub)
        cookie = learn_cookie(a, PAIRED_TRIES)
        # Deny: a fresh initiation from port B with port A's cookie.
        for _ in range(PAIRED_TRIES):
            b.send(wg_mod.with_mac2(b.init.initiation(), cookie))
            r = b.wait_kind((2, 3), COOKIE_WAIT_S)
            if r is not None and r[0] == 2:
                raise Fail("cookie deny: port B's initiation with port A's cookie got a handshake response")
            if r is not None and b.open_cookie(r) is not None:
                break
        else:
            raise Fail("cookie deny: no cookie reply at port B (positive signal missing)")
        # Allow: port A with its own cookie. Had the deny step been accepted,
        # total=1 would already be there.
        if con.count(r"audit: src=ingress WgMac2Accepted total=\d+ "):
            raise Fail("WgMac2Accepted appeared before the allow step: port B's initiation was accepted")
        allow = con.mark()
        for _ in range(PAIRED_TRIES):
            a.send(wg_mod.with_mac2(a.init.initiation(), cookie))
            r = a.wait_kind((2, 3), COOKIE_WAIT_S)
            if r is not None and r[0] == 2:
                break
            cookie = (r and a.open_cookie(r)) or cookie
        else:
            raise Fail("cookie allow: no handshake response at port A")
        con.wait_for(r"audit: src=ingress WgMac2Accepted total=1 ", since=allow)
        if not a.init.consume_response(r):
            raise Fail("cookie allow: the handshake response does not open")
        if con.count(r"audit: src=ingress WgLoadCleared ", since=loaded_at):
            raise Fail("WgLoadCleared during the paired flood: load did not hold")
        if con.count(r"audit: src=ingress WgCookieSuppressed total=1 "):
            raise Fail("WgCookieSuppressed total=1 during the paired flood: the TX reserve bound below capacity")
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


def test_cookie_a(loader: str, deploy: str, passed: list):
    """Boot "cookie-a": the keepalive case, then the paired cookie case."""
    tap = Tap()
    inside = Wire()
    host = InsideHost(inside)
    try:
        child, con = boot(loader, tap.netdev("n0"), inside.netdev("n1"))
    except BaseException:
        tap.close()
        raise
    py = None
    try:
        start_without_stop_signals(host)
        wait_tap_ready(tap, con)
        cfg = tomllib.load(open(os.path.join(deploy, "gateway.toml"), "rb"))
        gw_pub = b64(cfg["gateway"]["public_key"])
        peer1 = open(os.path.join(deploy, "peer-1.conf")).read()
        py = PyPeer(peer1, gw_pub)
        keepalive_case(con, py)
        passed.append("passive keepalive")
        print("\nPASS [passive keepalive: one empty message 10-13 s after unanswered data, none after a reply]")
        paired_case(con, tap, peer1, gw_pub)
        passed.append("cookie path, paired")
        print("\nPASS [cookie path, paired: port B denied, port A allowed, load cleared in its window]")
    finally:
        try:
            with signals_held():
                host.stop = True
                close_all(py)
                kill(child)
                tap.close()
        except SystemExit:
            host.stop = True
            close_all(py)
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
    # Over capacity a frame survives about C / rate (C from this run's probe).
    rate2 = STEP2_RATE * c
    s2 = SURVIVAL_MARGIN * c / rate2
    ping2 = tries_for(s2)
    print(f"\nbudgets: below capacity survival {s1:.3f} -> wireguard-go deadline {hs_deadline:.1f} s "
          f"({attempts} attempts), {ping1} ping tries; step 2 survival {s2:.3f} -> {ping2} ping tries "
          f"({ping_budget(ping2):.0f} s)", flush=True)

    # Flood step 1, below capacity: wireguard-go (re)started on a fixed port.
    step1 = flood.snapshot()
    step1_mark = con.mark()
    wg = WgGo(wg_go_conf(deploy), "10.200.0.2/32", cfg["gateway"]["inside_prefix"])
    opened.append(wg)
    before_hs = wg.latest_handshake()
    trigger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    trigger.sendto(b"x", (ip_str(HOST_IP), 9))
    trigger.close()
    started = time.monotonic()
    attribute_wireguard_go(sniffer, con, gw_pub, started + hs_deadline)
    print(f"\nflood step 1: wireguard-go's mac2 accepted {time.monotonic() - started:.1f} s after its start", flush=True)
    deadline = time.monotonic() + REKEY_ATTEMPT_S
    while wg.latest_handshake() == before_hs:
        if time.monotonic() > deadline:
            raise Fail("cookie attribution failed: wireguard-go reports no new handshake")
        time.sleep(0.1)
    if con.count(r"audit: src=ingress WgLoadCleared "):
        raise Fail("flood step 1: WgLoadCleared between WgUnderLoad and the handshake: load did not hold")
    ping(tries=ping1)
    # The probe saturates ingress, where the reserve does bind, so this
    # boot's first WgCookieSuppressed is the probe's; the paired case holds
    # the fresh-counter check. Here: no new line during step 1.
    if con.count(r"audit: src=ingress WgCookieSuppressed ", since=step1_mark):
        raise Fail("flood step 1: WgCookieSuppressed during step 1: the TX reserve bound below capacity")
    check_band("flood step 1", step1, flood.snapshot(), lo1, hi1)
    sniffer.check_drops()
    print("\nPASS [cookie flood step 1: wireguard-go drew a cookie, handshook with mac2 and pinged below capacity]",
          flush=True)
    wg.close()
    opened.remove(wg)

    # The Python peer's session, made under load through the cookie path
    # right before step 2.
    peer1 = open(os.path.join(deploy, "peer-1.conf")).read()
    py = PyPeer(peer1, gw_pub)
    opened.append(py)
    if not cookie_handshake(py, tries_for(s1 * s1) + 1) or not py_ping(py, ping1, ident=0x4642):
        raise Fail("precondition: no Python-peer session under load through the cookie path")
    budget2 = STEP2_WARMUP_S + ping_budget(ping2)
    age = time.monotonic() - py.established
    if age + budget2 >= rust_const(WG_CORE, "REJECT_AFTER_TIME_NS") / NS:
        raise Fail(f"precondition: session age {age:.0f} s leaves no room for step 2's {budget2:.0f} s budget")

    # Flood step 2, over capacity, running until the ping assertion concludes.
    step2 = flood.set_rate(rate2)
    time.sleep(STEP2_WARMUP_S)
    ok = py_ping(py, ping2, ident=0x4643)
    print(f"\nflood step 2: ping reply on try {ok} of {ping2}", flush=True)
    if not flood.running():
        raise Fail("flood step 2: the flood was not running when the ping assertion concluded")
    check_band("flood step 2", step2, flood.snapshot(), STEP2_BAND[0] * c, STEP2_BAND[1] * c)
    if not ok:
        raise Fail(f"flood step 2: no ping reply through the established session in {ping2} tries over capacity")
    flood.set_rate(0)
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


def preflight():
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
    """Two deployments: A (packaged normally) and B (only its blob, packaged
    onto A's image for the mismatch case)."""
    for name in ("a", "b"):
        subprocess.run(["cargo", "run", "--locked", "-q", "-p", "mksecrets", "--", "--template",
                        os.path.join(ROOT, "config/gateway.toml"), "--peers", "2", "--out",
                        os.path.join(tmp, name)], check=True, cwd=ROOT)
    env = {**os.environ, "SECUREOS_CONFIG": os.path.join(tmp, "a/gateway.toml")}
    make("image", env=env)
    make("package", f"SECRETS={tmp}/a/secrets.bin", f"OUT={tmp}/a/pkg", env=env)
    make("package", f"SECRETS={tmp}/b/secrets.bin", f"OUT={tmp}/b/pkg", env=env)
    return f"{tmp}/a/pkg/loader.img", f"{tmp}/b/pkg/loader.img"


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
        "gateway.inside_ip": (g["inside_ip"], ip(INSIDE_IP)),
        "gateway.inside_mac": (g["inside_mac"], mac(INSIDE_MAC)),
        "neighbors[0].ip": (cfg["neighbors"][0]["ip"], ip(HOST_IP)),
        "neighbors[0].mac": (cfg["neighbors"][0]["mac"], mac(HOST_MAC)),
        "peers[0].allowed_ips": (cfg["peers"][0]["allowed_ips"], ["10.200.0.2/32"]),
        # Case 4 sends from 10.200.0.99 as peer 1, which must not own it.
        "peers[1].allowed_ips": (cfg["peers"][1]["allowed_ips"], ["10.200.0.3/32"]),
    }
    wrong = [f"{k}={got!r} (harness uses {want!r})" for k, (got, want) in expected.items() if got != want]
    if wrong:
        raise Fail("config/gateway.toml no longer matches the harness: " + "; ".join(wrong))


def in_netns(good: str, mismatched: str, deploy: str) -> int:
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
        return in_netns(*sys.argv[2:5])
    tmp = tempfile.mkdtemp(prefix="secureos-it-")
    status = 1
    try:
        preflight()
        good, mismatched = build(tmp)
        # `unshare` execs the child, so the Popen pid is the netns harness.
        # The outer harness has no threads, so preexec_fn is safe here.
        child = subprocess.Popen(["unshare", "-rn", sys.executable, os.path.abspath(__file__), "--netns",
                                  good, mismatched, os.path.join(tmp, "a")], preexec_fn=die_with_parent,
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

if __name__ == "__main__":
    sys.exit(main())
