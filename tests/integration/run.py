"""Builds a dev deployment and exercises it end to end (plan C18).

Usage: run.py            (from `make test`)

Generates fresh keys with tools/mksecrets into a temporary directory
(removed on every exit path), builds the image against that configuration
and packages it, then re-runs itself inside `unshare -rn` (no NET_ADMIN in
the container; architecture R5) for three boots:

  1. raw frames: the outside NIC on a `-netdev dgram` socket; ARP, one frame
     per wire::DropReason, a coalesced flood, ARP as the liveness barrier;
  2. WireGuard: the outside NIC on user-net with a hostfwd to 51820, the
     inside NIC on a dgram socket played by a Python inside host;
     wireguard-go is the interop oracle, tests/integration/wg.py sends what
     wireguard-go will not. Every negative case asserts a positive audit
     line and then a liveness barrier (a ping through wireguard-go);
  3. a blob whose public key does not match the configuration: `key`
     prints the mismatch and halts.

Missing prerequisites fail the run; nothing is skipped.
"""

import base64
import contextlib
import ctypes
import json
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
        kill(child)


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
        with signals_held():
            host.stop = True
            if wg:
                wg.close()
            kill(child)


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
        kill(child)


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
    arrives meanwhile is delivered when the teardown has finished."""
    old = signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old)


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
        removed, held = final_teardown(tmp)
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
