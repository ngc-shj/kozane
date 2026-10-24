"""Builds a dev deployment and exercises it end to end (plan C18).

Usage: run.py            (from `make test`)

Generates fresh keys with tools/mksecrets into a temporary directory
(removed on every exit path), provisions a swtpm state per deployment and
reads its SRK, builds the image against that configuration and packages it
on a release kernel (M5 plan C7: no debug printing; every line on the
console is `audit`'s, C6) with its secrets sealed to that SRK (C11). Then
it re-runs itself inside `unshare -rn` (no NET_ADMIN in the container;
architecture R5). Every boot is the shipped path (C14): U-Boot measures the
published image and descriptor into PCR 8, copies the envelopes in and
runs the loader; its TPM is a fresh copy of the deployment's swtpm state,
removed after the boot. The boots:

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
     stays up Unavailable and `hs`, its only caller, audits `KeyUnavailable`
     with the boot error's code, then halts; `tls`, on `tlskey`, gets ready;
  7. measured boot (C8): U-Boot's measure variant against tools/measure.py;
  8. sealed boots (C14): another image, a tampered descriptor and another
     TPM's envelopes leave the three key PDs Unavailable with the codes the
     Rust tables give; after a sealed boot PCR 8 is capped;
  9. the A7 proxy between QEMU and swtpm: the unmodified relay passes a
     sealed boot, a flipped Unseal response is refused;
 10. https (M6 plan C3, C7, C9, C10): the outside NIC on the tap, the
     inside NIC on a second tap whose kernel end is a raw Python backend
     (each connection's peer and bytes logged; every peer must be the
     gateway's inside address, so nothing reaches the backend around it); OpenSSL
     s_client, curl and Python's ssl complete X25519MLKEM768 handshakes
     against the dev CA and reach the backend through the proxy: the
     backend sees exactly `rewrite`'s bytes and exact POST bodies, smuggling
     forms and oversized heads and bodies are refused before it, its RST
     mid-response reaches the client as a RST without close_notify, a
     client's early FIN aborts it; classical-only and TLS 1.2-only clients
     are refused; the probe canary; the TLS scalar count;
 11. https-residue (M6 plan C8): slowloris first, then one connection's
     secrets and marker checked at each backend-logged barrier (head, body
     after each KeyUpdate) and absent from guest RAM once it closed, while
     a live connection held in response streaming keeps its secret;
 12. tls key failure (M6 plan C12, case 8): a TLS blob whose scalar does
     not match the certificate, on the same image: `tlskey` is Unavailable,
     `tls` halts at init before it listens, PCR 8 is capped, the VPN still
     handshakes.

Since M3 (L8) hs refuses every WireGuard initiation without a fresh
Rosenpass PSK, so each WireGuard peer first runs upstream rosenpass (the VE9
oracle in the dev image) and its key_out is the PresharedKey. Boots 1, 6 to
9, 10 and 11 run no Rosenpass.

Missing prerequisites fail the run; nothing is skipped.
"""

import array
import base64
import bisect
import contextlib
import ctypes
import errno
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import select
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import xml.etree.ElementTree as ET
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


TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10


def ipv4_tcp(flags: int, options=b"", payload=b"", sport=40000, dport=443) -> bytearray:
    """An IPv4/TCP datagram from PEER_IP to GW_IP, both checksums right."""
    seg = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, (20 + len(options)) // 4 << 4, flags, 65535, 0, 0)
    seg += options + payload
    c = csum(PEER_IP + GW_IP + struct.pack("!BBH", 0, 6, len(seg)) + seg)
    seg = seg[:16] + struct.pack("!H", c) + seg[18:]
    return bytearray(ip_hdr(PEER_IP, GW_IP, 6, len(seg)) + seg)


def fix_tcp_csum(p: bytearray) -> bytearray:
    p[36:38] = b"\0\0"
    p[36:38] = struct.pack("!H", csum(bytes(p[12:20]) + struct.pack("!BBH", 0, 6, len(p) - 20) + bytes(p[20:])))
    return p


def tcp_frame(p: bytearray) -> bytes:
    return eth(GW_MAC, PEER_MAC, 0x0800, bytes(p))


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
        # GRE: a protocol nothing serves (TCP has reasons of its own).
        f[14 + 9] = 47
        fix_ip_csum(f)
    elif reason == "UdpBadLength":
        f[14 + 20 + 5] -= 1
    elif reason == "UdpBadChecksum":
        f[-1] ^= 1
    elif reason == "TcpBadLength":
        p = bytearray(ip_hdr(PEER_IP, GW_IP, 6, 19) + bytes(19))
        return tcp_frame(p)
    elif reason == "TcpBadOffset":
        p = ipv4_tcp(TCP_SYN)
        p[20 + 12] = 4 << 4
        return tcp_frame(fix_tcp_csum(p))
    elif reason == "TcpBadChecksum":
        p = ipv4_tcp(TCP_SYN)
        p[20 + 16] ^= 1
        return tcp_frame(p)
    elif reason == "TcpBadPort":
        p = ipv4_tcp(TCP_SYN)
        p[20:22] = b"\0\0"
        return tcp_frame(fix_tcp_csum(p))
    elif reason == "TcpBadFlags":
        return tcp_frame(ipv4_tcp(TCP_SYN | TCP_FIN))
    elif reason == "TcpBadOptions":
        return tcp_frame(ipv4_tcp(TCP_SYN, options=bytes([2, 1, 0, 0])))
    else:
        raise Fail(f"no frame for {reason}")
    return bytes(f)


# Must list every wire::DropReason; checked against the Rust source below.
DROP_REASONS = [
    "TooShort", "TooLong", "EthBadSrc", "UnknownEtherType", "ArpMalformed",
    "ArpBadSender", "Ipv4Version", "Ipv4Options", "Ipv4Fragment", "Ipv4BadLength",
    "Ipv4BadChecksum", "Ipv4BadSrc", "NotUdp", "UdpBadLength", "UdpBadChecksum",
    "TcpBadLength", "TcpBadOffset", "TcpBadChecksum", "TcpBadPort", "TcpBadFlags", "TcpBadOptions",
]
# Produced by forwarding (wire::forward_ipv4), not by any outside frame.
FORWARD_ONLY = ["TtlExpired"]
# Produced by ingress_core::tls_egress on what `tls` sends, not by any
# outside frame.
EGRESS_ONLY = ["TcpEgressRefused"]


def check_reason_list_matches_rust():
    src = open(os.path.join(os.path.dirname(__file__), "../../crates/wire/src/lib.rs")).read()
    block = src[src.index("pub enum DropReason {"):]
    block = block[: block.index("}")]
    rust = re.findall(r"^\s+(\w+) = \d+,", block, re.M)
    mirror = DROP_REASONS + FORWARD_ONLY + EGRESS_ONLY
    if sorted(rust) != sorted(mirror) or len(set(mirror)) != len(mirror):
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


# QEMU's serial console ends lines with "\r\r\n". `audit` prints these for
# each PD's `Ready` record, and its own.
READY_LINE = re.compile(r"(eth_out|eth_in|ingress|inner|data|hs|audit|pq|tls): ready\r*\n")


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
                # The last chunk can land between the copy above and the
                # drain thread seeing EOF (a guest that powers off at once).
                with self.lock:
                    text = self.text[since:]
                if strip_ready:
                    text = READY_LINE.sub(lambda r: r.group(0) if f"{r.group(1)}: ready" in pattern else "", text)
                m = rx.search(text)
                if m:
                    return m
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


def boot(pkg: "Package", outside: str, inside: str, monitor: str = "", media=None, flip=None) -> tuple:
    """Every boot is the shipped one (M5 plan C14): U-Boot measures and
    assembles the package's boot media (`media`, the package's own unless
    given: (path, address) pairs at measure.LOAD_*), and its TPM is a fresh
    copy of the deployment's provisioned swtpm state (the same SRK, fresh
    PCRs), stopped and removed by kill(). `flip` puts the A7 proxy between
    QEMU and swtpm, flipping a byte of each Unseal response if true."""
    tpm = Swtpm(os.path.dirname(pkg.dir), state=pkg.state)
    proxy = None
    try:
        if flip is not None:
            proxy = TpmProxy(tpm, flip)
        cmd = ["-machine", "virt,virtualization=on", "-cpu", "neoverse-n2", "-m", "size=2G",
               "-serial", "mon:stdio", "-nographic", "-bios", UBOOT]
        for path, addr in media or pkg.media():
            cmd += ["-device", f"loader,file={path},addr={addr:#x},force-raw=on"]
        cmd += (proxy or tpm).qemu_args()
        cmd += [
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
    except BaseException:
        close_tpm(proxy, tpm)
        raise
    child.tpm, child.proxy = tpm, proxy
    return child, Console(child)


def close_tpm(proxy, tpm):
    """The proxy, then swtpm and its state directory (T6: a leftover fails)."""
    try:
        if proxy is not None:
            proxy.close()
    finally:
        if tpm is not None:
            tpm.close()


def kill_qemu(child: pexpect.spawn):
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.close(force=True)


def kill(child: pexpect.spawn):
    """Ends QEMU, then the boot's TPM. Idempotent: the teardown paths call
    it again after a stop signal."""
    kill_qemu(child)
    tpm, proxy = getattr(child, "tpm", None), getattr(child, "proxy", None)
    child.tpm = child.proxy = None
    close_tpm(proxy, tpm)


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


def test_raw(pkg: "Package"):
    w = Wire()
    child, con = boot(pkg, w.netdev("n0"), dgram("n1", free_udp_port(), free_udp_port()))
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
    # The whole last line: audit prints a character at a time, so waiting
    # only for "total=N " could count it before its "lost=" arrived.
    con.wait_for(rf"FrameDropped\({reason}\) total={want[-1]} lost=\d+\r*\n", since=mark)
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


def test_wireguard(pkg: "Package", deploy: str, passed: list):
    inside = Wire()
    hostfwd = free_udp_port()
    rp_fwd = free_udp_port()
    host = InsideHost(inside)
    monitor = os.path.join(deploy, "monitor.sock")
    child, con = boot(pkg, f"user,id=n0,net=10.0.2.0/24,hostfwd=udp:127.0.0.1:{hostfwd}-:{WG_PORT},"
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


def test_peer_binding(pkg: "Package", deploy: str, passed: list):
    """Only client 0 runs, with WireGuard key wg0 and Rosenpass key rp0, on
    deployment `c`, where rp0 belongs to record 1: its PSK lands at record 1,
    so wg0 is refused, while wg1 with that PSK is accepted [R5-T-R1]. The
    correctly bound allow side is boot 2's interop."""
    hostfwd = free_udp_port()
    rp_fwd = free_udp_port()
    child, con = boot(pkg, f"user,id=n0,net=10.0.2.0/24,hostfwd=udp:127.0.0.1:{hostfwd}-:{WG_PORT},"
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


# `key` blob v2's gateway key (secret_blob::GATEWAY_PRIVATE_AT, pinned
# numerically by its offsets test), and the TLS scalar in `tlskey`'s own
# blob, tls-secrets.bin (secret_blob::tls::TLS_PRIVATE_AT; M6 plan C12):
# `key`'s blob holds no TLS scalar.
KEY_BLOB_GATEWAY_PRIVATE = slice(16, 48)
TLS_BLOB_TLS_PRIVATE = slice(16, 48)


def key_boot_code(variant: str) -> int:
    """`BootError::<variant> => <n>,` from key-core's code table (C6)."""
    src = open(os.path.join(ROOT, "crates/key-core/src/lib.rs")).read()
    m = re.search(rf"^\s+BootError::{variant} => (\d+),$", src, re.M)
    if not m:
        raise Fail(f"BootError::{variant} has no code in crates/key-core/src/lib.rs")
    return int(m.group(1))


# Where a PD's `halt` reason table lives, if not in the PD itself: `tls`'s
# is tls-core's (M6 plan C12, its sign-path halt unit-tested there).
HALT_TABLES = {"tls": "crates/tls-core/src/halt.rs"}


def halt_reason(pd: str, name: str) -> int:
    """`pub const <name>: u32 = <n>;` in the PD's `halt` reason table."""
    rel = HALT_TABLES.get(pd, f"crates/pds/{pd}/src/main.rs")
    src = open(os.path.join(ROOT, rel)).read()
    m = re.search(rf"^\s*pub const {name}: u32 = (\d+);$", src, re.M)
    if not m:
        raise Fail(f"no halt reason {name} in {rel}")
    return int(m.group(1))


def test_mismatched_blob(pkg: "Package"):
    """Under the release kernel nothing but `audit` prints (C6, C7): `key`
    stays up Unavailable, and `hs`'s boot-seed call, its first call to
    `key`, is where the failure shows. `tls` calls `tlskey`, not `key` (M6
    plan C12): it audits no KeyUnavailable and gets ready.

    The envelope unseals and opens: only validation fails, after the unseal.
    An Unavailable `key` holds no secret (M5 plan C6), so the opened blob's
    gateway key must be gone from guest RAM, while pqkey, which booted, still
    holds its own plaintext (the control, so the scan proves something)."""
    code = key_boot_code("GatewayKeyMismatch")
    reason = halt_reason("hs", "NO_BOOT_SEED")
    deploy = os.path.dirname(pkg.dir)
    with open(os.path.join(deploy, "secrets.bin"), "rb") as f:
        gateway_private = f.read()[KEY_BLOB_GATEWAY_PRIVATE]
    with open(os.path.join(os.path.dirname(deploy), "a", "pqkey-secrets.bin"), "rb") as f:
        pq_plain = f.read()[1024:1088]  # inside the McEliece secret key
    if not any(gateway_private) or not any(pq_plain):
        raise Fail("mismatched blob: a needle is all zero; the scan would prove nothing")
    monitor = os.path.join(deploy, "monitor.sock")
    child, con = boot(pkg, dgram("n0", free_udp_port(), free_udp_port()),
                      dgram("n1", free_udp_port(), free_udp_port()), monitor)
    try:
        m = con.wait_for(rf"audit: src=hs KeyUnavailable code={code} lost=\d+\r*\n", timeout=BOOT_TIMEOUT_S)
        con.wait_for(rf"audit: src=hs Halted reason={reason} lost=\d+\r*\n", since=m.end(), timeout=LINE_TIMEOUT_S)
        m = con.wait_for(r"audit: src=tls KeyUnavailable code=(\d+) lost=\d+\r*\n|tls: ready\r*\n",
                         timeout=BOOT_TIMEOUT_S, strip_ready=True)
        if m.group(1) is not None:
            raise Fail(f"mismatched blob: tls audited KeyUnavailable code={m.group(1)}: it shares key's failure")
        # pq audits pqkey's stack mark only once pqkey's init has returned:
        # before it, pqkey may not yet have unsealed its control plaintext.
        con.wait_for(r"audit: src=pq KeyStackHighWater bytes=", timeout=BOOT_TIMEOUT_S)
        scan_absent(Monitor(monitor), gateway_private, pq_plain, os.path.join(deploy, "pmem-b.bin"),
                    "key's opened blob (an Unavailable key must hold no secret)", "pqkey's plaintext")
    finally:
        try:
            with signals_held():
                kill(child)
        except SystemExit:
            kill(child)
            raise


# ---------------------------------------------------------------- measured boot (M5 plan C8)

sys.path.insert(0, os.path.join(ROOT, "tools"))
import measure  # noqa: E402  (the host model of support/u-boot/boot.cmd)

UBOOT_MEASURE = os.path.join(ROOT, "build/u-boot-measure/u-boot.bin")
# What every other boot runs (M5 plan C14): the same boot command, ending in
# the jump to the loader.
UBOOT = os.path.join(ROOT, "build/u-boot-shipped/u-boot.bin")
SWTPM_SOCKET_WAIT_S = 10.0
# How often measure_boot repeats its Ctrl-C until the boot command decides.
CTRLC_REPEAT_S = 0.25
# The swtpm state file that holds the TPM's seeds (the SRK derives from
# them); a volatile state file would make U-Boot's TPM2_Startup fail.
SWTPM_PERMALL = "tpm2-00.permall"
SWTPM_VOLATILE = "tpm2-00.volatilestate"


class Swtpm:
    """One swtpm per boot, in its own state directory (plan T6): started
    before QEMU, stopped and its directory removed after, and a directory
    that survives the removal fails the case. `state`, a provisioned state
    directory, is copied in first: the deployment's SRK, fresh PCRs."""

    def __init__(self, parent: str, state: str = None):
        self.dir = tempfile.mkdtemp(prefix="swtpm-", dir=parent)
        self.sock = os.path.join(self.dir, "ctrl.sock")
        self.proc = None
        try:
            if state is not None:
                shutil.copy2(os.path.join(state, SWTPM_PERMALL), self.dir)
            self.proc = subprocess.Popen(DIE_WITH_PARENT + ["swtpm", "socket", "--tpm2", "--tpmstate",
                                                            f"dir={self.dir}", "--ctrl",
                                                            f"type=unixio,path={self.sock}"],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + SWTPM_SOCKET_WAIT_S
            while not os.path.exists(self.sock):
                if self.proc.poll() is not None or time.monotonic() > deadline:
                    raise Fail("swtpm did not open its control socket")
                time.sleep(0.05)
        except BaseException:
            self.close()
            raise

    def qemu_args(self) -> list:
        return ["-chardev", f"socket,id=chrtpm,path={self.sock}", "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
                "-device", "tpm-tis-device,tpmdev=tpm0"]

    def close(self):
        if self.proc is not None:
            if self.proc.poll() is None:
                self.proc.kill()
            self.proc.wait()
        shutil.rmtree(self.dir, ignore_errors=True)
        if os.path.exists(self.dir):
            raise Fail(f"swtpm state {self.dir} survived its boot")


class Package:
    """One deployment's boot media, as tools/package wrote them, and the
    provisioned swtpm state its envelopes are sealed to."""

    def __init__(self, pkg_dir: str, state: str):
        self.dir, self.state = pkg_dir, state

    def path(self, name: str) -> str:
        return os.path.join(self.dir, name)

    def read(self, name: str) -> bytes:
        with open(self.path(name), "rb") as f:
            return f.read()

    def media(self) -> list:
        names = ("published.img", "boot.desc", "secrets.env", "pq_secrets.env", "tls_secrets.env")
        return list(zip(map(self.path, names), (measure.LOAD_IMAGE, measure.LOAD_DESC) + measure.LOAD_ENVELOPES))


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise Fail(f"socket closed after {len(buf)} of {n} bytes")
        buf += chunk
    return buf


# swtpm's control channel (tpm_ioctl.h): commands are big-endian u32 codes.
SWTPM_CMD_SET_DATAFD = 16
# TPM2_PCR_Read of PCR 8, sha256 bank (tpm2_wire::pcr_read).
PCR_READ_8 = bytes.fromhex("8001" "00000014" "0000017e" "00000001" "000b" "03" "000100")
PCR8_SELECTION = bytes.fromhex("00000001" "000b" "03" "000100")


def read_pcr8(tpm: Swtpm) -> bytes:
    """PCR 8 of a swtpm whose QEMU has been killed (T11): a second control
    connection hands swtpm a fresh data socket (CMD_SET_DATAFD; no CMD_INIT,
    which would restart the TPM), then TPM2_PCR_Read. Probed host-side in
    slice 7: swtpm keeps the TPM running once the killed QEMU's data socket
    closes."""
    ctrl = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    mine, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        ctrl.settimeout(LINE_TIMEOUT_S)
        ctrl.connect(tpm.sock)
        ctrl.sendmsg([struct.pack(">I", SWTPM_CMD_SET_DATAFD)],
                     [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [theirs.fileno()]))])
        if recv_exact(ctrl, 4) != bytes(4):
            raise Fail("swtpm refused a data socket after QEMU exited")
        theirs.close()
        mine.settimeout(LINE_TIMEOUT_S)
        mine.sendall(PCR_READ_8)
        head = recv_exact(mine, 10)
        rsp = head + recv_exact(mine, struct.unpack(">I", head[2:6])[0] - 10)
    finally:
        for s in (ctrl, mine, theirs):
            s.close()
    # header, pcrUpdateCounter, the selection as asked, one 32-byte digest.
    if len(rsp) != 62 or rsp[6:10] != bytes(4) or rsp[14:24] != PCR8_SELECTION or rsp[24:30] != bytes.fromhex("000000010020"):
        raise Fail(f"unexpected PCR_Read response {rsp.hex()}")
    return rsp[30:]


CC_UNSEAL = 0x15E


class TpmProxy:
    """The A7 proxy (M5 plan C14): QEMU's tpm-emulator backend talks to
    this socket instead of swtpm's control channel. Control bytes pass
    through as they are; the data socket QEMU hands over (CMD_SET_DATAFD)
    is swapped for one end of a pair whose other end swtpm gets, and TPM
    commands and responses are relayed between the two, framed by their
    headers. With `flip`, the first byte of every successful Unseal
    response's outData is flipped. Feasibility (F6-A): the unmodified relay
    must pass a sealed boot first."""

    def __init__(self, tpm: Swtpm, flip: bool):
        self.tpm, self.flip = tpm, flip
        self.path = os.path.join(tpm.dir, "proxy.sock")
        self.unseals = self.flipped = 0
        self.error = None
        self.stopped = False
        self.socks = []
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.path)
        self.listener.listen(1)
        self.listener.settimeout(0.2)
        self.thread = threading.Thread(target=self._run, daemon=True)
        start_without_stop_signals(self.thread)

    def qemu_args(self) -> list:
        return ["-chardev", f"socket,id=chrtpm,path={self.path}", "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
                "-device", "tpm-tis-device,tpmdev=tpm0"]

    def _run(self):
        try:
            self._relay()
        except Exception as e:  # reported by the case, which then fails
            if not self.stopped:
                self.error = e

    def _relay(self):
        while True:
            if self.stopped:
                return
            try:
                qemu, _ = self.listener.accept()
                break
            except socket.timeout:
                continue
        swtpm = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        swtpm.connect(self.tpm.sock)
        self.socks += [qemu, swtpm]
        # (QEMU's data socket, ours to swtpm, command buffer, response
        # buffer, command codes awaiting their response)
        relays = []
        while not self.stopped:
            readable, _, _ = select.select([qemu, swtpm] + [s for r in relays for s in r[:2]], [], [], 0.2)
            for s in readable:
                if s is qemu:
                    data, anc, _, _ = qemu.recvmsg(4096, socket.CMSG_LEN(4 * array.array("i").itemsize))
                    if not data:
                        return
                    fds = [fd for level, kind, raw in anc if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS
                           for fd in array.array("i", raw[:len(raw) - len(raw) % 4])]
                    if fds:
                        theirs = socket.socket(fileno=fds[0])
                        mine, for_swtpm = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
                        swtpm.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                 array.array("i", [for_swtpm.fileno()]))])
                        for_swtpm.close()
                        self.socks += [theirs, mine]
                        relays.append([theirs, mine, b"", b"", []])
                    else:
                        swtpm.sendall(data)
                elif s is swtpm:
                    data = swtpm.recv(4096)
                    if not data:
                        return
                    qemu.sendall(data)
                else:
                    for r in relays:
                        if s is r[0]:
                            self._commands(r, s.recv(4096))
                        elif s is r[1]:
                            self._responses(r, s.recv(4096))

    @staticmethod
    def _frames(buf: bytes):
        """Complete TPM frames at the head of `buf`, and the rest."""
        frames = []
        while len(buf) >= 10 and len(buf) >= struct.unpack(">I", buf[2:6])[0]:
            n = struct.unpack(">I", buf[2:6])[0]
            if n < 10:
                raise Fail(f"proxy: a TPM frame of {n} bytes")
            frames.append(bytearray(buf[:n]))
            buf = buf[n:]
        return frames, buf

    def _commands(self, r: list, data: bytes):
        if not data:
            raise Fail("proxy: QEMU closed its data socket")
        frames, r[2] = self._frames(r[2] + data)
        for cmd in frames:
            r[4].append(struct.unpack(">I", cmd[6:10])[0])
            r[1].sendall(cmd)

    def _responses(self, r: list, data: bytes):
        if not data:
            raise Fail("proxy: swtpm closed its data socket")
        frames, r[3] = self._frames(r[3] + data)
        for rsp in frames:
            cc = r[4].pop(0) if r[4] else None
            if cc == CC_UNSEAL and rsp[6:10] == bytes(4) and len(rsp) > 16:
                self.unseals += 1
                if self.flip:
                    # parameterSize (4), outData's size (2), then outData.
                    rsp[16] ^= 1
                    self.flipped += 1
            r[0].sendall(bytes(rsp))

    def close(self):
        self.stopped = True
        self.thread.join(timeout=5)
        for s in [self.listener] + self.socks:
            s.close()
        # As Swtpm.close: a relay that outlives its boot fails the case (T2).
        if self.thread.is_alive():
            raise Fail("tpm proxy relay thread survived its boot")


def boot_uboot(uboot: str, files: list, tpm: Swtpm) -> tuple:
    """QEMU with U-Boot as firmware; `files` are (path, address) pairs, the
    boot media U-Boot reads (measure.LOAD_*)."""
    cmd = ["-machine", "virt,virtualization=on", "-cpu", "neoverse-n2", "-m", "size=2G",
           "-serial", "mon:stdio", "-nographic", "-bios", uboot]
    for path, addr in files:
        cmd += ["-device", f"loader,file={path},addr={addr:#x},force-raw=on"]
    cmd += tpm.qemu_args()
    child = pexpect.spawn(DIE_WITH_PARENT[0], DIE_WITH_PARENT[1:] + ["qemu-system-aarch64"] + cmd,
                          encoding="utf-8", timeout=BOOT_TIMEOUT_S)
    return child, Console(child)


# `tpm2 pcr_read 8`'s own print of the digest, 16 bytes a line.
PCR_DUMP = re.compile(r"PCR #8 sha256 32 byte content \(\d+ known updates\):\r*\n"
                      r"((?: [0-9a-f]{2}){16})\r*\n((?: [0-9a-f]{2}){16})\r*\n")


def measure_boot(pkg: str, scratch: str, image: bytes, desc: bytes, envelopes: list) -> tuple:
    """Boots the measure variant on these boot media: (PCR 8 or None, whether
    U-Boot refused)."""
    paths = []
    for name, data in (("published.img", image), ("boot.desc", desc),
                       *((f"env{i}", env) for i, env in enumerate(envelopes))):
        path = os.path.join(scratch, name)
        with open(path, "wb") as f:
            f.write(data)
        paths.append(path)
    tpm = Swtpm(scratch)
    try:
        child, con = boot_uboot(UBOOT_MEASURE, list(zip(paths, (measure.LOAD_IMAGE, measure.LOAD_DESC)
                                                              + measure.LOAD_ENVELOPES)), tpm)
        try:
            # Ctrl-C on the UART throughout the boot command: with the lock
            # (AUTOBOOT_KEYED) it is never read, so it cannot skip a check of
            # the command (S-BOOT-5, R3-N2). It starts after U-Boot's banner,
            # once QEMU's stdio is raw (an earlier 0x03 is the pty's SIGINT)
            # and the PL011 is set up, and repeats, so one is always pending
            # when the command's first loop polls (R4-S1).
            banner = con.wait_for(r"U-Boot \d{4}\.\d{2} ", timeout=BOOT_TIMEOUT_S)
            deadline = time.monotonic() + BOOT_TIMEOUT_S
            while True:
                try:
                    child.send("\x03")
                except OSError:
                    pass  # QEMU has exited; wait_for reports it
                try:
                    m = con.wait_for(r"secureos: (measured|boot refused)\r*\n", since=banner.end(),
                                     timeout=CTRLC_REPEAT_S)
                    break
                except Fail:
                    if not con.alive or time.monotonic() > deadline:
                        raise
            if m.group(1) == "boot refused":
                # A refusal must end the boot: nothing runs after it, not
                # even when someone on the UART presses Ctrl-C (S-BOOT-1,
                # S-BOOT-5). U-Boot powers off; until it does (or for the
                # bound, if its power-off ever returned and it spins), the
                # console must show neither a later measurement nor a prompt.
                # measure-ctrlc proves the lock through the Ctrl-C above; this
                # one has no red-proof of its own (R4-N1).
                try:
                    child.send("\x03")
                except OSError:
                    pass  # already powered off
                deadline = time.monotonic() + LINE_TIMEOUT_S
                while con.alive and time.monotonic() < deadline:
                    time.sleep(0.05)
                after = con.text[banner.end() + m.end():]
                # Two controls, each failing on its own: nothing runs after the
                # refusal (the spin and the Ctrl-C lock), and U-Boot powers off.
                if "secureos: measured" in after or re.search(r"(^|\n)=> ", after):
                    raise Fail("measure_boot: U-Boot ran past its refusal")
                if con.alive:
                    raise Fail("measure_boot: U-Boot did not power off after its refusal")
                return None, True
            dump = PCR_DUMP.search(con.text, 0, banner.end() + m.start())
            if not dump:
                raise Fail("measure variant printed no PCR 8 dump")
            return bytes.fromhex((dump.group(1) + dump.group(2)).replace(" ", "")), False
        finally:
            try:
                with signals_held():
                    kill(child)
            except SystemExit:
                kill(child)
                raise
    finally:
        tpm.close()


def test_measured_boot(pkg: str, passed: list):
    """C8: the PCR 8 U-Boot produces is the one tools/measure.py computes
    from the public release files; it moves with any byte of the image or
    the descriptor; and the descriptor checks U-Boot runs on-device refuse a
    wrapping range, each overlapping pair of the three ranges, range 2 past
    image_len and a version-1 descriptor, but allow a range ending exactly
    at image_len."""
    def read(name):
        with open(os.path.join(pkg, name), "rb") as f:
            return f.read()
    image, desc = read("published.img"), read("boot.desc")
    envs = [read("secrets.env"), read("pq_secrets.env"), read("tls_secrets.env")]
    want = measure.expected_pcr8(desc, image)
    if read("pcr8").decode().strip() != want.hex():
        raise Fail("package's pcr8 differs from tools/measure.py's")
    scratch = tempfile.mkdtemp(prefix="measure-", dir=pkg)
    try:
        got, refused = measure_boot(pkg, scratch, image, desc, envs)
        if refused or got != want:
            raise Fail(f"measured PCR 8 {got and got.hex()} != expected {want.hex()} (refused={refused})")
        passed.append("measured boot: PCR 8 as computed")

        image_len, ranges = measure.parse(desc)
        # One byte inside image_len but outside every envelope range.
        at = next(i for i in range(image_len // 2, image_len)
                  if not any(o <= i < o + n for o, n in ranges))
        flipped = image[:at] + bytes([image[at] ^ 1]) + image[at + 1:]
        got, refused = measure_boot(pkg, scratch, flipped, desc, envs)
        if refused or got == want or got != measure.expected_pcr8(desc, flipped):
            raise Fail(f"a flipped image byte gave PCR 8 {got and got.hex()} (refused={refused})")
        passed.append("measured boot: image byte measured")

        # A range moved onto the loader's entry code: still in bounds and
        # disjoint, so U-Boot accepts and measures it, and PCR 8 is no longer
        # the release's.
        (o0, l0), (o1, l1), (o2, l2) = ranges
        if min(o1, o2) < l0:
            raise Fail(f"another envelope range ({min(o1, o2):#x}) overlaps [0, {l0:#x}); pick another target")
        tampered = desc[:24] + struct.pack("<Q", 0) + desc[32:]
        got, refused = measure_boot(pkg, scratch, image, tampered, envs)
        if refused or got == want:
            raise Fail(f"a moved range kept PCR 8 {got and got.hex()} (refused={refused})")
        passed.append("measured boot: descriptor measured")

        def with_ranges(moved: list) -> bytes:
            return desc[:24] + struct.pack("<6Q", *(v for r in moved for v in r)) + desc[72:]

        # Range 2 moved to run 0x10 past image_len, clear of ranges 0 and 1.
        past = (image_len - 0x10, 0x20)
        if max(o0 + l0, o1 + l1) > past[0]:
            raise Fail("ranges 0 and 1 reach the image's last 0x10 bytes; pick another range-2 target")
        # On-device refusals, one measure-variant boot each. Every descriptor
        # but the first is refused by one boot.cmd line alone (one selftest
        # drops each): a pair's overlap moves one range onto the other of its
        # pair, which stays disjoint from the third.
        refusals = (
            # S12: offset + len wraps 64 bits into the image.
            ("wrapping range refused", "a wrapping range was not refused",
             desc[:24] + struct.pack("<QQ", 2**64 - 0x10, 0x20) + desc[40:]),
            ("0-1 overlap refused", "the 0-1 overlap was not refused", with_ranges([ranges[0], ranges[0], ranges[2]])),
            ("0-2 overlap refused", "the 0-2 overlap was not refused", with_ranges([ranges[0], ranges[1], ranges[0]])),
            ("1-2 overlap refused", "the 1-2 overlap was not refused", with_ranges([ranges[0], ranges[1], ranges[1]])),
            # Within 32 bits, so only the no-wrap form len <= image_len - offset
            # catches it (offset + len is never computed).
            ("range 2 wrap refused", "the range-2 wrap was not refused", with_ranges([ranges[0], ranges[1], past])),
            # M5's version at v2's length: only the version compare catches it.
            ("version-1 descriptor refused", "the version-1 descriptor was not refused",
             desc[:8] + struct.pack("<I", 1) + desc[12:]),
        )
        for case, missing, bad in refusals:
            got, refused = measure_boot(pkg, scratch, image, bad, envs)
            if not refused:
                raise Fail(f"{missing} (PCR 8 {got and got.hex()})")
            passed.append(f"measured boot: {case}")

        # Its allow pair: a range ending exactly at image_len (the first of
        # the three that can move there without overlapping the others).
        for i, (_, length) in enumerate(ranges):
            moved_ranges = ranges[:i] + [(image_len - length, length)] + ranges[i + 1:]
            if not measure.check_ranges(image_len, moved_ranges):
                break
        else:
            raise Fail("no envelope range can end at image_len without overlap")
        edge = with_ranges(moved_ranges)
        got, refused = measure_boot(pkg, scratch, image, edge, envs)
        if refused or got is None:
            raise Fail("a range ending exactly at image_len was refused")
        passed.append("measured boot: range at image_len allowed")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# ---------------------------------------------------------------- sealed boots (M5 plan C14)


def code_table(crate: str) -> dict:
    """A key PD core's code table (C6): `BootError::<variant> => <n>,`, each
    above the crate's `CODE_BASE` if it has one (tlskey-core's own range,
    M6 plan C12)."""
    src = open(os.path.join(ROOT, f"crates/{crate}/src/lib.rs")).read()
    base = re.search(r"^pub const CODE_BASE: u32 = (0x[0-9a-fA-F]+|\d+);$", src, re.M)
    base = int(base.group(1), 0) if base else 0
    table = {m.group(1): base | int(m.group(2))
             for m in re.finditer(r"^\s+BootError::(\w+(?:\(\w+::\w+\))?) => (\d+),$", src, re.M)}
    if not table:
        raise Fail(f"no BootError code table in crates/{crate}/src/lib.rs")
    return table


def boot_code(crate: str, variant: str) -> int:
    """`BootError::<variant>`'s code in a key PD core's table (C6)."""
    table = code_table(crate)
    if variant not in table:
        raise Fail(f"BootError::{variant} has no code in crates/{crate}/src/lib.rs")
    return table[variant]


def check_key_code_tables_apart():
    """M6 plan C12 (R1-S F6, R2-T N8): `key`'s and `tlskey`'s codes are
    disjoint, so a `KeyUnavailable` code names the key PD that failed; each
    table's codes are distinct too. The mirror keeps the crates apart (no
    dependency edge between them)."""
    key, tlskey = code_table("key-core"), code_table("tlskey-core")
    for name, table in (("key-core", key), ("tlskey-core", tlskey)):
        if len(set(table.values())) != len(table):
            raise Fail(f"key code tables: {name} uses a code twice: {table}")
    shared = sorted(set(key.values()) & set(tlskey.values()))
    if shared:
        raise Fail(f"key code tables: key-core and tlskey-core share codes {shared}")


def cap_digest() -> bytes:
    """`CAP_DIGEST`, what tpm extends PCR 8 with once both clients finished
    (crates/tpm2-wire, RT3)."""
    src = open(os.path.join(ROOT, "crates/tpm2-wire/src/gate.rs")).read()
    m = re.search(r"^pub const CAP_DIGEST: \[u8; DIGEST_LEN\] = \[0x([0-9A-Fa-f]{2}); DIGEST_LEN\];$", src, re.M)
    n = re.search(r"^pub const DIGEST_LEN: usize = (\d+);$",
                  open(os.path.join(ROOT, "crates/tpm2-wire/src/lib.rs")).read(), re.M)
    if not m or not n:
        raise Fail("CAP_DIGEST or DIGEST_LEN not found in crates/tpm2-wire")
    return bytes([int(m.group(1), 16)]) * int(n.group(1))


# The PDs whose init calls a key PD, and the key PD's code table: each key
# PD has one caller (M6 plan C12), which audits it Unavailable.
KEY_CALLERS = (("hs", "key-core"), ("tls", "tlskey-core"), ("pq", "pqkey-core"))


def key_outcomes(con: Console, codes: dict, what: str):
    """Waits for each caller's `KeyUnavailable` with the code `codes` names
    (a variant per key-core crate). A caller reaching `<pd>: ready` means
    its key PD unsealed: that, or another code, fails at once
    (failure-only)."""
    for pd, crate in KEY_CALLERS:
        want = boot_code(crate, codes[crate])
        m = con.wait_for(rf"audit: src={pd} KeyUnavailable code=(\d+) lost=\d+\r*\n|{pd}: ready\r*\n",
                         timeout=BOOT_TIMEOUT_S, strip_ready=True)
        if m.group(1) is None:
            raise Fail(f"{what}: the {crate.removesuffix('-core')} PD unsealed ({pd} became ready)")
        if int(m.group(1)) != want:
            raise Fail(f"{what}: {pd} audited KeyUnavailable code={m.group(1)}, want {codes[crate]} ({want})")


def media_with(pkg: Package, scratch: str, image: bytes = None, desc: bytes = None) -> list:
    """The package's boot media with the image or the descriptor replaced."""
    media = pkg.media()
    for i, data in ((0, image), (1, desc)):
        if data is not None:
            path = os.path.join(scratch, os.path.basename(media[i][0]))
            with open(path, "wb") as f:
                f.write(data)
            media[i] = (path, media[i][1])
    return media


def sealed_boot(pkg: Package, media=None, flip=None) -> tuple:
    return boot(pkg, dgram("n0", free_udp_port(), free_udp_port()), dgram("n1", free_udp_port(), free_udp_port()),
                media=media, flip=flip)


def stop(child):
    try:
        with signals_held():
            kill(child)
    except SystemExit:
        kill(child)
        raise


def test_sealed(good: Package, foreign: Package, passed: list):
    """C14 on the shipped path: the envelopes open only on the image and
    descriptor they were sealed to, and only on their own TPM; once the three
    key PDs have finished, PCR 8 is capped. The allow side, a sealed boot
    that reaches its handshakes, is every other boot's."""
    image, desc = good.read("published.img"), good.read("boot.desc")
    image_len, ranges = measure.parse(desc)
    refused = {"key-core": "UnsealRefused", "pqkey-core": "UnsealRefused", "tlskey-core": "UnsealRefused"}
    scratch = tempfile.mkdtemp(prefix="sealed-", dir=os.path.dirname(good.dir))
    try:
        # Another image: one byte of audit's text (printed by no case here),
        # inside image_len and outside every envelope range.
        text = b"HandshakePskStale"
        at = image.find(text)
        if image.count(text) != 1 or not at < image_len or any(o <= at < o + n for o, n in ranges):
            raise Fail("wrong image: the byte to flip is not one place inside the image outside the envelopes")
        flipped = image[:at] + bytes([image[at] ^ 1]) + image[at + 1:]
        child, con = sealed_boot(good, media_with(good, scratch, image=flipped))
        try:
            key_outcomes(con, refused, "wrong image")
        finally:
            stop(child)
        passed.append("sealed boot: another image is refused")

        # A tampered descriptor, valid for U-Boot: image_len cut short of the
        # image (every range still inside), so less is measured while the
        # whole image still runs. PCR 8 differs; the TPM refuses.
        end = max(o + n for o, n in ranges)
        if end >= image_len:
            raise Fail("tampered descriptor: an envelope range ends at image_len; cannot cut it short")
        cut = desc[:16] + struct.pack("<Q", end) + desc[24:]
        measure.parse(cut)
        child, con = sealed_boot(good, media_with(good, scratch, desc=cut))
        try:
            key_outcomes(con, refused, "tampered descriptor")
        finally:
            stop(child)
        passed.append("sealed boot: a tampered descriptor is refused")

        # Envelopes sealed to another TPM's SRK, booted on this one (I10.2).
        child, con = sealed_boot(Package(foreign.dir, good.state))
        try:
            key_outcomes(con, {"key-core": "SrkMismatch", "pqkey-core": "SrkMismatch", "tlskey-core": "SrkMismatch"},
                         "foreign TPM")
        finally:
            stop(child)
        passed.append("sealed boot: another TPM's envelopes are refused")

        # The cap (T11): once hs, pq and tls are ready the three key PDs have
        # sent Done (tls is ready only after tlskey's init returned its boot
        # seed, M6 plan C12), and tpm extended PCR 8 with CAP_DIGEST before
        # answering the last. Read from swtpm after QEMU is gone and before
        # swtpm is stopped.
        want = measure.extend(measure.expected_pcr8(desc, image), cap_digest())
        child, con = sealed_boot(good)
        try:
            con.wait_for(r"hs: ready", timeout=BOOT_TIMEOUT_S, strip_ready=True)
            con.wait_for(r"pq: ready", timeout=BOOT_TIMEOUT_S, strip_ready=True)
            con.wait_for(r"tls: ready", timeout=BOOT_TIMEOUT_S, strip_ready=True)
            # QEMU killed (no CMD_SHUTDOWN reaches swtpm), its TPM kept.
            kill_qemu(child)
            got = read_pcr8(child.tpm)
        finally:
            stop(child)
        if got != want:
            capped = "uncapped" if got == measure.expected_pcr8(desc, image) else "unexpected"
            raise Fail(f"cap: PCR 8 after the boot is {got.hex()} ({capped}), want {want.hex()}")
        passed.append("sealed boot: PCR 8 capped after the three key PDs")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def test_tpm_proxy(good: Package, passed: list):
    """A7 (C14, integrity evidence only, S9): a proxy between QEMU and swtpm.
    F6-A: the unmodified relay must first pass a sealed boot; only then is
    the flipped Unseal response's refusal evidence."""
    child, con = sealed_boot(good, flip=False)
    try:
        try:
            con.wait_for(r"hs: ready", timeout=BOOT_TIMEOUT_S, strip_ready=True)
            con.wait_for(r"pq: ready", timeout=BOOT_TIMEOUT_S, strip_ready=True)
            con.wait_for(r"tls: ready", timeout=BOOT_TIMEOUT_S, strip_ready=True)
        except Fail as e:
            raise Fail(f"A7 proxy: the unmodified relay did not pass a sealed boot ({e}); "
                       f"relay error: {child.proxy.error!r}") from None
        if child.proxy.unseals != 3:
            raise Fail(f"A7 proxy: the relay saw {child.proxy.unseals} Unseal responses, want 3")
    finally:
        stop(child)
    passed.append("A7 proxy: the unmodified relay passes a sealed boot")

    invalid = {"key-core": "TpmResponseInvalid", "pqkey-core": "TpmResponseInvalid", "tlskey-core": "TpmResponseInvalid"}
    child, con = sealed_boot(good, flip=True)
    try:
        key_outcomes(con, invalid, "A7 proxy")
        if child.proxy.flipped != 3 or child.proxy.error is not None:
            raise Fail(f"A7 proxy: {child.proxy.flipped} responses flipped, relay error {child.proxy.error!r}")
    finally:
        stop(child)
    passed.append("A7 proxy: a flipped Unseal response is refused")


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


def udp_filter(port: int, proto: int = 17) -> bytes:
    """Classic BPF: unfragmented IPv4/UDP (or `proto`: TCP) to or from
    `port`."""
    prog = [
        (0x28, 0, 0, 12),       # ldh [12]
        (0x15, 0, 9, 0x0800),   # IPv4, else drop
        (0x30, 0, 0, 23),       # ldb [23]
        (0x15, 0, 7, proto),    # UDP (TCP), else drop
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
    """AF_PACKET on the tap keeping only UDP (or TCP, `proto` 6) to and from
    one port (classic BPF, enlarged SO_RCVBUF). A kernel-side drop
    (PACKET_STATISTICS) aborts the case, so a lost frame never reads as an
    attribution failure."""

    def __init__(self, port: int, proto: int = 17):
        self.frames = []  # (monotonic, frame, outgoing)
        self.lock = threading.Lock()
        self.drops = 0
        self.alive = True
        # Protocol 0 receives nothing until the bind, after the filter.
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SNIFF_RCVBUF)
            prog = udp_filter(port, proto)
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


class Spoof:
    """Spoofed frames at `rate` per second, cycling through `frames`, on
    the tap by a helper thread (the shape of `Flood`). A case that relies
    on the attack calls `verify` at its judgment point: an attack that
    stopped or fell short fails the case instead of passing it vacuously."""

    # Delivered frames below this share of the scheduled ones fail
    # `verify`.
    MIN_DELIVERED = 0.9

    def __init__(self, tap: Tap, frames: list, rate: float):
        self.frames = frames
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


class RpSpoof(Spoof):
    """Datagrams to the Rosenpass port from (ip, port) sources, cycling
    payloads and sources."""

    def __init__(self, tap: Tap, payloads: list, sources: list, rate: float):
        super().__init__(tap, [ipv4_udp(ip, GW_IP, port, RP_PORT, payloads[i % len(payloads)])
                               for i, (ip, port) in enumerate(sources)], rate)


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
    """`stack_size` of `pd`, read as XML (as microkit and laws read it)."""
    root = ET.parse(os.path.join(ROOT, "system/secureos.system")).getroot()
    sizes = [e.get("stack_size") for e in root.iter("protection_domain") if e.get("name") == pd]
    if len(sizes) != 1 or not sizes[0]:
        raise Fail(f"no single stack_size for {pd} in system/secureos.system")
    return int(sizes[0].replace("_", ""), 0)


def mce_const(name: str) -> int:
    """`pub const <name>: usize = <a> * 1024;` from mce460896."""
    text = open(os.path.join(ROOT, "crates/mce460896/src/lib.rs")).read()
    m = re.search(rf"pub const {name}: usize = (\d+) \* 1024;", text)
    if not m:
        raise Fail(f"{name} not found in crates/mce460896/src/lib.rs")
    return int(m.group(1)) * 1024


def pd_stack_const(pd: str) -> int:
    """`const STACK_SIZE` in the PD's main.rs, the size its probe paints."""
    text = open(os.path.join(ROOT, f"crates/pds/{pd}/src/main.rs")).read()
    m = re.search(r"^const STACK_SIZE: usize = (0x[0-9a-f_]+);", text, re.M)
    if not m:
        raise Fail(f"no STACK_SIZE in crates/pds/{pd}/src/main.rs")
    return int(m.group(1).replace("_", ""), 16)


def stack_headroom_case(con):
    """C8: pq and pqkey paint their free stack at init (cpu::StackProbe).
    pq reports each deeper mark as an audit record, `StackHighWater
    bytes=N`; pqkey, which has no audit ring and no console (M5 plan C6),
    hands its mark after the boot KAT to pq (PQ_STACK_MARK), which audits
    it once as `KeyStackHighWater bytes=N`. Each must leave
    STACK_HEADROOM_MIN free at the stack_size the
    system file gives it, which its STACK_SIZE (the size it paints) must
    equal.

    The mark must also reach the PD's own scrub (pqkey's decaps, pq's
    encaps): a shallower one means the probe is not measuring. Every
    report must parse: a garbled one would drop the deepest figure."""
    # Several PDs report `StackHighWater` (pq, and tls since M6), so a
    # garbled report is any occurrence of the name that is not a whole
    # line of some producer; each PD's marks are then its own lines.
    reports = {
        "pq": (r"\bStackHighWater", r"audit: src=[a-z_]+ StackHighWater bytes=\d+ ",
               r"audit: src=pq StackHighWater bytes=(\d+) ", 10),
        "pqkey": (r"KeyStackHighWater", r"audit: src=pq KeyStackHighWater bytes=\d+ ",
                  r"audit: src=pq KeyStackHighWater bytes=(\d+) ", 10),
    }
    for pd, (any_line, whole_line, line, base) in reports.items():
        every = len(con.count(any_line))
        whole = len(con.count(whole_line))
        marks = [int(h, base) for h in con.count(line)]
        if not marks:
            raise Fail(f"{pd}: no stack high-water report; the probe reported nothing")
        if every != whole:
            raise Fail(f"{pd}: {every - whole} of {every} stack high-water reports garbled")
        size = system_stack_size(pd)
        if pd_stack_const(pd) != size:
            raise Fail(f"{pd}: STACK_SIZE {pd_stack_const(pd)} paints other than the system file's {size}")
        hw = max(marks)
        floor = mce_const("SCRUB_DEPTH" if pd == "pqkey" else "SCRUB_DEPTH_ENCAPS")
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


def test_rp_gate(pkg: "Package", deploy: str, passed: list):
    """Boot "rp gate" (M3b plan C6): the Rosenpass cookie gate under its
    attacks, each case after the previous one's load has cleared."""
    tap = Tap()
    inside = Wire()
    host = InsideHost(inside)
    try:
        child, con = boot(pkg, tap.netdev("n0"), inside.netdev("n1"))
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


def test_cookie_a(pkg: "Package", deploy: str, passed: list):
    """Boot "cookie-a": Rosenpass 0.2.3 interop (peer 2) and ingress's
    Rosenpass pairs, then the keepalive case and the paired cookie case
    (peer 1)."""
    tap = Tap()
    inside = Wire()
    host = InsideHost(inside)
    try:
        child, con = boot(pkg, tap.netdev("n0"), inside.netdev("n1"))
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


def test_cookie_b(pkg: "Package", deploy: str, passed: list):
    """Boot "cookie-b": the flood case."""
    tap = Tap()
    inside = Wire()
    host = InsideHost(inside)
    try:
        child, con = boot(pkg, tap.netdev("n0"), inside.netdev("n1"))
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


# ---------------------------------------------------------------- https (M6)


HTTPS_PORT = 443
HTTPS_WAIT_S = 10.0             # one client's connect, handshake and response
TLS_CONN = "crates/tls-core/src/conn.rs"
TLS_HANDSHAKE = "crates/tls-core/src/handshake.rs"
HTTP_WIRE = "crates/http-wire/src/lib.rs"
LIMITS = "crates/limits/src/lib.rs"
# The probe (M6 plan C10, D3): sequential handshakes, the slowest of which
# must stay within a third of the Rust handshake timeout (the canary).
PROBE_HANDSHAKES = 20
# An address the residue boot uses for nothing but its barrier SYNs.
BARRIER_IP = bytes([10, 0, 2, 77])
BARRIER_SYN_TRIES = 10
BARRIER_SYN_WAIT_S = 0.5
# Slowloris: one byte per interval, well inside the handshake timeout.
SLOWLORIS_INTERVAL_S = 1.0
SLOWLORIS_SLACK_S = 2 * TIMER_TICK_S + 3.0
# The https boots' inside NIC (M6 plan T10): a second tap whose kernel end
# is the backend host (neighbors[0], the configured backend), reached only
# through `inner`.
INSIDE_TAP = "tapi0"
BACKEND_PORT = 8080
# POST bodies up to this are echoed; a larger one is answered with its
# SHA-256 (the backend log is what proves the body exact).
ECHO_MAX = 16 * 1024
# The https-flood boot's client addresses on the tap (M6 plan cases 10 and
# 12, the concurrent probe), each its own source to the per-source cap:
# MAX_CONNS / MAX_PER_SOURCE of them fill every slot, one more is the
# ninth connection's (checked against the Rust constants).
CLIENT_IPS = [bytes([10, 0, 2, 101 + i]) for i in range(5)]
# Case 10: requests run through the one free slot while the others are
# held, and the body each held response streams (one byte per cycle).
RECYCLE_CYCLES = 9
HELD_BODY_LEN = 64
HELD_FIRST = 16
# Case 9: spoofed SYNs from SPOOF_SOURCES addresses, each source well under
# its own SYN refill (so the refusals are the global bucket's), the total
# far over the global one; the coalesced line awaited is the first after 64
# refusals (audit prints totals 1, 65, 129, ...).
SYN_FLOOD_RATE = 200.0
SYN_GLOBAL_POINT = 65
FLOOD_PING_TRIES = 3


def rust_size(rel: str, name: str) -> int:
    """`pub const NAME: usize = <integer expression>;` (digits, `*`, `+`,
    `<<`) from a Rust source."""
    m = re.search(rf"pub const {name}: usize = ([^;]+);", open(os.path.join(ROOT, rel)).read())
    if not m or not re.fullmatch(r"[0-9_ *+<]+", m.group(1)):
        raise Fail(f"{name} not found in {rel} as a plain integer expression")
    return int(eval(m.group(1)))  # digits and operators only, checked above


def backend_body() -> bytes:
    """What the backend answers a GET with: binary, and six of `tls`'s
    server records long (several backend chunks, more than the backend
    socket's receive buffer), so its FIN arrives while bytes before it
    still wait for room on the client socket."""
    return hashlib.shake_256(b"secureos backend body").digest(6 * rust_size(TLS_HANDSHAKE, "MAX_SERVER_RECORD") + 123)


def backend_response(data: bytes):
    """The backend's answer once `data` holds a complete request (head and
    Content-Length body bytes), else None: the GET body, or the POST body
    echoed (its SHA-256 above ECHO_MAX)."""
    end = data.find(b"\r\n\r\n")
    if end < 0:
        return None
    head = data[:end + 4]
    m = re.search(rb"\r\ncontent-length: *(\d+)\r\n", head, re.I)
    length = int(m.group(1)) if m else 0
    if len(data) < end + 4 + length:
        return None
    if head.startswith(b"POST "):
        body = data[end + 4:end + 4 + length]
        payload = body if length <= ECHO_MAX else hashlib.sha256(body).hexdigest().encode()
    else:
        payload = backend_body()
    return (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n"
            b"Connection: close\r\n\r\n" % len(payload)) + payload


def forwarded_head(lines: list) -> bytes:
    """What `rewrite` must send the backend for a head whose kept lines are
    `lines` (request line first), from a client on the tap's address."""
    return (b"".join(line + b"\r\n" for line in lines) + b"X-Forwarded-For: " + ip_str(PEER_IP).encode()
            + b"\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n")


class BackendConn:
    """One connection the raw backend accepted: its peer, every byte it
    received, and how it ended ("eof", "reset" when the peer aborted it,
    "closed" when the test reset it). A thread owns the socket; the test's
    sends run on that thread, in order."""

    def __init__(self, sock: socket.socket, peer: tuple, auto: bool):
        self.sock, self.peer, self.auto = sock, peer, auto
        self.data = bytearray()
        self.ended = None
        self.stopped = False
        self.lock = threading.Lock()
        self.ops = []
        self.thread = threading.Thread(target=self._run, daemon=True)
        start_without_stop_signals(self.thread)

    def _run(self):
        answered = False
        try:
            while self.ended is None and not self.stopped:
                self._run_ops()
                if self.ended is not None:
                    break
                if not select.select([self.sock], [], [], 0.05)[0]:
                    continue
                try:
                    chunk = self.sock.recv(65536)
                except ConnectionResetError:
                    self.ended = "reset"
                    break
                if not chunk:
                    self.ended = "eof"
                    break
                with self.lock:
                    self.data += chunk
                if self.auto and not answered:
                    response = backend_response(bytes(self.data))
                    if response is not None:
                        answered = True
                        self.sock.sendall(response)
                        self.sock.shutdown(socket.SHUT_WR)
        except OSError:
            self.ended = self.ended or "error"
        finally:
            if self.ended != "closed":
                self.sock.close()
            with self.lock:
                for _, _, done in self.ops:
                    done.set()

    def _run_ops(self):
        with self.lock:
            ops, self.ops = self.ops, []
        for op, payload, done in ops:
            try:
                self.sock.sendall(payload)
                if op == "finish":
                    self.sock.shutdown(socket.SHUT_WR)
                elif op == "reset":
                    # SO_LINGER 0: close sends RST, not FIN.
                    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    self.sock.close()
                    self.ended = "closed"
            finally:
                done.set()

    def _do(self, op: str, payload: bytes, what: str):
        done = threading.Event()
        with self.lock:
            if self.ended is not None:
                raise Fail(f"{what}: the backend connection already ended ({self.ended})")
            self.ops.append((op, payload, done))
        if not done.wait(HTTPS_WAIT_S) or self.ended == "error":
            raise Fail(f"{what}: the backend could not send")

    def send(self, payload: bytes, what: str):
        self._do("send", payload, what)

    def finish(self, payload: bytes, what: str):
        """`payload`, then FIN."""
        self._do("finish", payload, what)

    def reset(self, payload: bytes, what: str):
        """`payload`, then RST (SO_LINGER 0)."""
        self._do("reset", payload, what)

    def snapshot(self) -> tuple:
        with self.lock:
            return bytes(self.data), self.ended

    def wait(self, pred, what: str, timeout: float = HTTPS_WAIT_S) -> bytes:
        """Until pred(data, ended) holds; the data."""
        deadline = time.monotonic() + timeout
        while True:
            data, ended = self.snapshot()
            if pred(data, ended):
                return data
            if time.monotonic() > deadline:
                raise Fail(f"{what}: the backend did not see it ({len(data)} bytes so far, ended: {ended})")
            time.sleep(0.02)

    def close(self):
        self.stopped = True
        self.thread.join(1.0)


class Backend:
    """The raw-capture backend (M6 plan T10) on the inside tap: a TCP
    listener at the configured backend address that logs each connection's
    peer and raw bytes and answers a complete request with
    `backend_response`, then FIN, unless the test holds the connection
    (`hold_next`) to answer it itself."""

    def __init__(self):
        self.conns = []
        self.held = 0
        self.lock = threading.Lock()
        self.alive = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((ip_str(HOST_IP), BACKEND_PORT))
            self.sock.listen(16)
            self.sock.settimeout(0.2)
        except BaseException:
            self.sock.close()
            raise
        self.thread = threading.Thread(target=self._accept, daemon=True)
        start_without_stop_signals(self.thread)

    def _accept(self):
        while self.alive:
            try:
                sock, peer = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            sock.setblocking(True)
            with self.lock:
                auto = self.held == 0
                self.held = max(0, self.held - 1)
                self.conns.append(BackendConn(sock, peer, auto))

    def hold_next(self, n: int = 1):
        """The next `n` connections are answered by the test."""
        with self.lock:
            self.held += n

    def count(self) -> int:
        with self.lock:
            return len(self.conns)

    def conn(self, i: int, what: str, timeout: float = HTTPS_WAIT_S) -> BackendConn:
        """Connection number `i` (from 0), once accepted."""
        deadline = time.monotonic() + timeout
        while True:
            with self.lock:
                if len(self.conns) > i:
                    return self.conns[i]
            if time.monotonic() > deadline:
                raise Fail(f"{what}: no backend connection number {i} (the backend saw {self.count()})")
            time.sleep(0.02)

    def close(self):
        self.alive = False
        self.thread.join(1.0)
        self.sock.close()
        with self.lock:
            conns = list(self.conns)
        for c in conns:
            c.close()


class InsideTap:
    """The inside NIC on a second tap in the test netns (the https boots;
    the VPN boots keep the dgram inside host): the kernel end is the backend
    host with the configured neighbour address, and the gateway's inside MAC
    is static, as the outside tap's router side is."""

    def __init__(self):
        sh("ip", "tuntap", "add", "dev", INSIDE_TAP, "mode", "tap")
        try:
            sh("ip", "link", "set", INSIDE_TAP, "address", HOST_MAC.hex(":"))
            sh("ip", "addr", "add", f"{ip_str(HOST_IP)}/24", "dev", INSIDE_TAP)
            sh("ip", "link", "set", INSIDE_TAP, "up")
            sh("ip", "neigh", "replace", ip_str(INSIDE_IP), "lladdr", INSIDE_MAC.hex(":"), "dev", INSIDE_TAP,
               "nud", "permanent")
        except BaseException:
            self.close()
            raise

    def netdev(self, name: str) -> str:
        return f"tap,id={name},ifname={INSIDE_TAP},script=no,downscript=no"

    def close(self):
        subprocess.run(["ip", "link", "del", INSIDE_TAP], capture_output=True)


def tls_client(ca: str, timeout: float = HTTPS_WAIT_S, source: bytes = None) -> ssl.SSLSocket:
    """A verified TLS 1.3 connection from Python (OpenSSL 3.5's default
    groups offer X25519MLKEM768 first), for requests whose bytes must be
    exact; from `source` (one of CLIENT_IPS) if given, else the tap's
    address."""
    ctx = ssl.create_default_context(cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    raw = socket.create_connection((ip_str(GW_IP), HTTPS_PORT), timeout=timeout,
                                   source_address=(ip_str(source), 0) if source else None)
    try:
        return ctx.wrap_socket(raw, server_hostname=ip_str(GW_IP))
    except BaseException:
        raw.close()
        raise


def read_to_end(s: ssl.SSLSocket) -> bytes:
    got = bytearray()
    while True:
        chunk = s.recv(65536)
        if not chunk:
            return bytes(got)
        got += chunk


def tls_exchange(ca: str, request: bytes, what: str, timeout: float = HTTPS_WAIT_S) -> bytes:
    """`request` over a fresh verified connection, then everything the
    server sends until its close_notify."""
    try:
        with tls_client(ca, timeout) as s:
            s.sendall(request)
            return read_to_end(s)
    except OSError as e:
        raise Fail(f"{what}: {type(e).__name__}: {e}") from e


def https_url(host: str = None) -> str:
    return f"https://{host or ip_str(GW_IP)}:{HTTPS_PORT}/"


def curl(cacert: str, *args: str) -> subprocess.CompletedProcess:
    """curl offering X25519MLKEM768 only, verifying against `cacert`."""
    return subprocess.run(["curl", "--silent", "--show-error", "--max-time", str(HTTPS_WAIT_S),
                           "--curves", "X25519MLKEM768", "--cacert", cacert, *args],
                          capture_output=True, timeout=HTTPS_WAIT_S + 5)


def curl_get(cacert: str) -> tuple:
    """A verified GET: (body, time_appconnect - time_connect in s)."""
    r = curl(cacert, "--write-out", "\n@@%{time_connect} %{time_appconnect}", https_url())
    if r.returncode != 0:
        raise Fail(f"https: curl failed ({r.returncode}): {r.stderr.decode(errors='replace').strip()}")
    body, _, timing = r.stdout.rpartition(b"\n@@")
    connect, appconnect = (float(x) for x in timing.split())
    return body, appconnect - connect


def s_client(*args: str, data: bytes = b"") -> str:
    """One s_client run to its end: `data` sent, then (with -ign_eof) its
    output until the server closes."""
    try:
        r = subprocess.run(["openssl", "s_client", "-connect", f"{ip_str(GW_IP)}:{HTTPS_PORT}", "-ign_eof", *args],
                           input=data, capture_output=True, timeout=HTTPS_WAIT_S + 5)
    except subprocess.TimeoutExpired as e:
        raise Fail(f"https: s_client {' '.join(args)} did not finish") from e
    return (r.stdout + r.stderr).decode(errors="replace")


def request_head(extra: str = "") -> bytes:
    return f"GET / HTTP/1.1\r\nHost: {ip_str(GW_IP)}\r\n{extra}\r\n".encode()


class SClient:
    """An interactive s_client (commands on: `k`/`K` send KeyUpdate), its
    output read by a helper thread; killed by close()."""

    def __init__(self, *args: str):
        self.out = b""
        self.lock = threading.Lock()
        self.proc = subprocess.Popen(DIE_WITH_PARENT + ["openssl", "s_client", "-connect",
                                                        f"{ip_str(GW_IP)}:{HTTPS_PORT}", *args],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        start_without_stop_signals(threading.Thread(target=self._drain, daemon=True))

    def _drain(self):
        while True:
            try:
                chunk = os.read(self.proc.stdout.fileno(), 65536)
            except OSError:
                return
            if not chunk:
                return
            with self.lock:
                self.out += chunk

    def wait_for(self, pattern: bytes, what: str, timeout: float = HTTPS_WAIT_S) -> re.Match:
        deadline = time.monotonic() + timeout
        while True:
            with self.lock:
                m = re.search(pattern, self.out)
            if m:
                return m
            if time.monotonic() > deadline:
                raise Fail(f"{what}: s_client did not print {pattern!r}")
            time.sleep(0.05)

    def handshake(self, what: str):
        m = self.wait_for(rb"Verify return code: (\d+)", what)
        if m.group(1) != b"0":
            raise Fail(f"{what}: s_client verify return code {m.group(1).decode()}")

    def send(self, data: bytes):
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def key_update(self, cmd: bytes, what: str):
        """One KeyUpdate (s_client reads a command per stdin read, so each
        waits for the previous one's KEYUPDATE line)."""
        with self.lock:
            n = self.out.count(b"KEYUPDATE")
        self.send(cmd + b"\n")
        deadline = time.monotonic() + HTTPS_WAIT_S
        while True:
            with self.lock:
                if self.out.count(b"KEYUPDATE") > n:
                    return
            if time.monotonic() > deadline:
                raise Fail(f"{what}: s_client did not send it")
            time.sleep(0.05)

    def close(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()
        with contextlib.suppress(OSError):
            self.proc.stdin.close()


def hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    """RFC 8446 section 7.1 with SHA-256, empty context; one HMAC block is
    every output this suite needs."""
    full = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    return hmac.new(secret, info + b"\x01", hashlib.sha256).digest()[:length]


def keylog(path: str) -> dict:
    """label -> secrets (in order) from an SSLKEYLOGFILE of one connection."""
    out = {}
    for line in open(path):
        parts = line.split()
        if len(parts) == 3 and not line.startswith("#"):
            out.setdefault(parts[0], []).append(bytes.fromhex(parts[2]))
    return out


def secret_forms(name: str, secret: bytes) -> dict:
    """A traffic secret and the ChaCha20-Poly1305 record key and IV it gives
    (RFC 8446 section 7.3): every stored form `tls` derives from it."""
    return {name: secret, f"{name} key": hkdf_expand_label(secret, b"key", 32),
            f"{name} iv": hkdf_expand_label(secret, b"iv", 12)}


def scan_snapshot(mon: Monitor, scratch: str, what: str, absent: dict, present: dict, counts: dict = None):
    """One snapshot of all of guest RAM: each `absent` needle occurs nowhere,
    each `present` one (the controls: the scan covers the memory that would
    hold the needles) occurs, and each `counts` needle exactly as often as
    given."""
    base, size = GUEST_RAM
    ram = mon.pmem(base, size, scratch)
    try:
        for name, needle in present.items():
            if ram.find(needle) < 0:
                raise Fail(f"{what}: {name} not found in guest RAM; the scan proves nothing")
        for name, (needle, want) in (counts or {}).items():
            n = ram.count(needle)
            if n != want:
                raise Fail(f"{what}: {name} occurs {n} time(s) in guest RAM, want exactly {want}")
        for name, needle in absent.items():
            at = ram.find(needle)
            if at >= 0:
                raise Fail(f"{what}: {name} still in guest RAM at {base + at:#x}")
    finally:
        del ram


def https_handshake_cases(con: Console, deploy: str, other_ca: str, backend: Backend, passed: list):
    """M6 plan C7 integration and strategy cases 1, 3 and 4: s_client and
    curl complete X25519MLKEM768 handshakes and get the backend's response
    through the proxy, curl's body byte for byte, curl verifying the chain
    and the IP name, the backend's peer the inside address; a wrong CA or
    name fails curl; a classical-only client gets handshake_failure and the
    NoPqGroup audit (L14); a TLS 1.2-only client protocol_version."""
    ca = os.path.join(deploy, "devca.pem")
    before = backend.count()
    out = s_client("-groups", "X25519MLKEM768", "-CAfile", ca, "-verify_return_error", data=request_head())
    if not re.search(r"Negotiated TLS1\.3 group: X25519MLKEM768\n", out):
        raise Fail(f"https: s_client did not negotiate X25519MLKEM768:\n{out[-2000:]}")
    if "Verify return code: 0 (ok)" not in out or "HTTP/1.1 200 OK\r\n" not in out:
        raise Fail(f"https: s_client did not verify the chain or got no response:\n{out[-2000:]}")
    body, _ = curl_get(ca)
    if body != backend_body():
        raise Fail(f"https: curl got a body of {len(body)} bytes, want the backend's {len(backend_body())} "
                   "byte for byte")
    peers = {backend.conn(i, "https").peer[0] for i in range(before, before + 2)}
    if peers != {ip_str(INSIDE_IP)}:
        raise Fail(f"https: the backend saw peers {sorted(peers)}, want only the inside address {ip_str(INSIDE_IP)}")
    passed.append("https tls handshake")
    print("\nPASS [https: s_client and curl complete X25519MLKEM768, chain and IP name verified, the backend's "
          "body through the proxy]")

    wrong_ca = curl(other_ca, https_url())
    if wrong_ca.returncode == 0:
        raise Fail("https: curl accepted the server against another deployment's CA")
    wrong_name = curl(ca, "--resolve", f"gateway.example:{HTTPS_PORT}:{ip_str(GW_IP)}", https_url("gateway.example"))
    if wrong_name.returncode == 0:
        raise Fail("https: curl accepted the certificate for a name it does not carry")
    passed.append("https wrong ca or name")
    print("\nPASS [https: a wrong CA and a wrong name each fail curl's verification]")

    mark = con.mark()
    out = s_client("-groups", "X25519", data=request_head())
    if not re.search(r"alert handshake failure|SSL alert number 40\b", out):
        raise Fail(f"https: a classical-only client did not get handshake_failure:\n{out[-2000:]}")
    con.wait_for(r"audit: src=tls TlsRefused\(NoPqGroup\) total=1 lost=\d+", since=mark)
    passed.append("https no pq group")
    print("\nPASS [https: -groups X25519 gets handshake_failure, TlsRefused(NoPqGroup) audited (L14)]")

    mark = con.mark()
    out = s_client("-tls1_2", data=request_head())
    if not re.search(r"alert protocol version|SSL alert number 70\b", out):
        raise Fail(f"https: a TLS 1.2-only client did not get protocol_version:\n{out[-2000:]}")
    con.wait_for(r"audit: src=tls TlsRefused\(NoTls13\) total=1 lost=\d+", since=mark)
    passed.append("https tls 1.2 refused")
    print("\nPASS [https: a TLS 1.2-only client gets protocol_version, TlsRefused(NoTls13) audited]")


def backend_exchange(ca: str, backend: Backend, request: bytes, what: str,
                     timeout: float = HTTPS_WAIT_S) -> tuple:
    """`request` through the proxy as one backend connection: (what the
    backend received, what the client received)."""
    before = backend.count()
    got = tls_exchange(ca, request, what, timeout)
    conn = backend.conn(before, what)
    data = conn.wait(lambda d, ended: ended is not None, f"{what}: the backend connection's end")
    if backend.count() != before + 1:
        raise Fail(f"{what}: the backend saw {backend.count() - before} connections, want 1")
    return data, got, conn


def https_rewrite_case(con: Console, deploy: str, backend: Backend, passed: list):
    """Strategy case 2 (C9, C10): the backend receives exactly `rewrite`'s
    bytes — every hop-by-hop and forwarding field gone, X-Forwarded-For the
    client's address, X-Forwarded-Proto https, Connection: close — from the
    inside address and a TLS_PORTS port, and the client exactly the
    backend's response; POST bodies of 0, 1 and MAX_BODY bytes arrive
    exactly, nothing after them; MAX_BODY + 1 is refused with 413 at head
    time, before any backend connection."""
    ca = os.path.join(deploy, "devca.pem")
    tls_ports = tomllib.load(open(os.path.join(deploy, "gateway.toml"), "rb"))["gateway"]["tls_ports"]
    host = b"Host: " + ip_str(GW_IP).encode()
    request = (b"GET /path?q=1 HTTP/1.1\r\n" + host + b"\r\nUser-Agent: secureos-it\r\nX-Custom: kept\r\n"
               b"Connection: keep-alive, X-Hop\r\nX-Hop: dropped\r\nKeep-Alive: timeout=5\r\nTE: trailers\r\n"
               b"Trailer: X-T\r\nProxy-Authorization: Basic eA==\r\nProxy: http://198.51.100.1/\r\n"
               b"Forwarded: for=198.51.100.6\r\nX-Forwarded-For: 198.51.100.6\r\nX-Forwarded-Proto: http\r\n"
               b"X-Real-IP: 198.51.100.6\r\n\r\n")
    want = forwarded_head([b"GET /path?q=1 HTTP/1.1", host, b"User-Agent: secureos-it", b"X-Custom: kept"])
    data, got, conn = backend_exchange(ca, backend, request, "https rewrite")
    if data != want:
        raise Fail(f"https rewrite: the backend received {data!r}, want exactly {want!r}")
    if conn.peer[0] != ip_str(INSIDE_IP) or not 0 <= conn.peer[1] - tls_ports["start"] < tls_ports["count"]:
        raise Fail(f"https rewrite: the backend's peer is {conn.peer}, want {ip_str(INSIDE_IP)} from TLS_PORTS")
    if got != backend_response(want):
        raise Fail(f"https rewrite: the client received {len(got)} bytes, want the backend's response exactly")
    passed.append("https proxy rewrite")
    print("\nPASS [https rewrite: the backend received exactly rewrite's bytes from the inside address]")

    max_body = rust_size(HTTP_WIRE, "MAX_BODY")
    lifetime = rust_const(TLS_CONN, "LIFETIME_NS") / NS
    for length in (0, 1, max_body):
        body = secrets.token_bytes(length)
        head = [b"POST /up HTTP/1.1", host, b"Content-Length: %d" % length]
        # Bytes after the body (a pipelined request) must never go on.
        request = b"".join(line + b"\r\n" for line in head) + b"\r\n" + body + b"GET /smuggled HTTP/1.1\r\n\r\n"
        start = time.monotonic()
        data, got, _ = backend_exchange(ca, backend, request, f"https post {length}", timeout=lifetime)
        if data != forwarded_head(head) + body:
            raise Fail(f"https post: the POST body of {length} bytes reached the backend as {len(data)} bytes, "
                       "not exactly rewrite's head and the body")
        if got != backend_response(forwarded_head(head) + body):
            raise Fail(f"https post: the response to the POST of {length} bytes is not the backend's")
        print(f"\nhttps post: {length} bytes in {time.monotonic() - start:.1f} s", flush=True)
    passed.append("https post bodies")
    print(f"\nPASS [https post: bodies of 0, 1 and {max_body} bytes reached the backend exactly]")

    before, mark = backend.count(), con.mark()
    big = os.path.join(deploy, "post-over-max.bin")
    with open(big, "wb") as f:
        f.write(b"x" * (max_body + 1))
    try:
        r = curl(ca, "-H", "Expect:", "--data-binary", f"@{big}", "--output", "/dev/null",
                 "--write-out", "%{http_code}", https_url())
    finally:
        os.unlink(big)
    # curl may also report its upload cut short once the server closed.
    if r.stdout != b"413":
        raise Fail(f"https post: MAX_BODY + 1 got status {r.stdout!r} (curl exit {r.returncode}), want 413")
    con.wait_for(r"audit: src=tls HttpRefused\(413\) total=1 lost=\d+", since=mark)
    if backend.count() != before:
        raise Fail("https post: MAX_BODY + 1 reached the backend; 413 must be decided at head time")
    passed.append("https body 413 at head time")
    print("\nPASS [https post: MAX_BODY + 1 refused with 413 at head time, no backend connection]")


def https_smuggling_cases(deploy: str, backend: Backend, passed: list):
    """Strategy case 5 (C9): each smuggling or header form gets its status
    and never reaches the backend: after each, a valid request makes the
    backend's log grow by exactly that one connection (the barrier). A
    spoofed Forwarded is not refused: it is forwarded with the field gone."""
    ca = os.path.join(deploy, "devca.pem")
    host = b"Host: " + ip_str(GW_IP).encode() + b"\r\n"
    refused = [
        ("TE+CL", b"POST / HTTP/1.1\r\n" + host + b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n", 501),
        ("duplicate CL", b"POST / HTTP/1.1\r\n" + host + b"Content-Length: 4\r\nContent-Length: 4\r\n\r\n", 400),
        ("obs-fold", b"GET / HTTP/1.1\r\n" + host + b"X-A: a\r\n b\r\n\r\n", 400),
        ("Connection: content-length", b"GET / HTTP/1.1\r\n" + host + b"Connection: content-length\r\n\r\n", 400),
        ("underscore name", b"GET / HTTP/1.1\r\n" + host + b"X_Forwarded_For: 198.51.100.6\r\n\r\n", 400),
    ]
    valid = b"GET /barrier HTTP/1.1\r\n" + host + b"\r\n"
    for name, request, status in refused:
        before = backend.count()
        got = tls_exchange(ca, request, f"https smuggling {name}")
        if not got.startswith(b"HTTP/1.1 %d " % status):
            raise Fail(f"https smuggling: {name} got {got[:40]!r}, want status {status}")
        data, _, _ = backend_exchange(ca, backend, valid, f"https smuggling {name} barrier")
        if backend.count() != before + 1 or not data.startswith(b"GET /barrier "):
            raise Fail(f"https smuggling: {name} reached the backend")
    spoofed = b"GET /fwd HTTP/1.1\r\n" + host + b"Forwarded: for=198.51.100.6;proto=http\r\n\r\n"
    data, got, _ = backend_exchange(ca, backend, spoofed, "https smuggling spoofed Forwarded")
    if not got.startswith(b"HTTP/1.1 200 ") or b"198.51.100.6" in data or b"orwarded:" in data:
        raise Fail(f"https smuggling: a spoofed Forwarded reached the backend as {data!r}")
    passed.append("https smuggling refused")
    print("\nPASS [https smuggling: TE+CL, duplicate CL, obs-fold, Connection: content-length and an underscore "
          "name refused before the backend; a spoofed Forwarded stripped]")


def head_of(length: int) -> bytes:
    """A complete request head of exactly `length` bytes."""
    start = b"GET / HTTP/1.1\r\nHost: " + ip_str(GW_IP).encode() + b"\r\nX-Pad: "
    return start + b"a" * (length - len(start) - 4) + b"\r\n\r\n"


def https_head_limit_case(con: Console, deploy: str, backend: Backend, passed: list):
    """Strategy case 6 (C9): a head of 8 KiB + 1 is refused with 431 before
    any backend connection; one of exactly 8 KiB reaches the backend."""
    ca = os.path.join(deploy, "devca.pem")
    max_head = rust_size(HTTP_WIRE, "MAX_HEAD")
    before, mark = backend.count(), con.mark()
    got = tls_exchange(ca, head_of(max_head + 1), "https head limit")
    if not got.startswith(b"HTTP/1.1 431 "):
        raise Fail(f"https head limit: a head of {max_head + 1} bytes got {got[:40]!r}, want 431")
    con.wait_for(r"audit: src=tls HttpRefused\(431\) total=1 lost=\d+", since=mark)
    data, got, _ = backend_exchange(ca, backend, head_of(max_head), "https head limit (allow side)")
    if backend.count() != before + 1 or not got.startswith(b"HTTP/1.1 200 ") or not data.startswith(b"GET / "):
        raise Fail(f"https head limit: a head of exactly {max_head} bytes did not reach the backend alone")
    passed.append("https head 431")
    print(f"\nPASS [https head limit: {max_head + 1} bytes refused with 431, {max_head} bytes proxied]")


def https_backend_reset_case(con: Console, deploy: str, backend: Backend, sniffer: Sniffer, passed: list):
    """Strategy case 13 (C10, T-R3-9, T-N8): the backend resets the
    connection (SO_LINGER 0) mid-response: s_client sees no close_notify
    and its read fails with ECONNRESET, and the sniffer sees the server's
    RST. Then a client's FIN before the response ends: the backend sees
    its connection aborted."""
    ca = os.path.join(deploy, "devca.pem")
    what = "https backend reset"
    i, start = backend.count(), len(sniffer.since(0))
    backend.hold_next()
    c = SClient("-msg", "-groups", "X25519MLKEM768", "-CAfile", ca, "-verify_return_error")
    try:
        c.handshake(what)
        port = client_port(sniffer, start, what)
        c.send(request_head())
        conn = backend.conn(i, what)
        conn.wait(lambda d, _: d.endswith(b"\r\n\r\n"), f"{what}: the request head")
        conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\npartial-response", what)
        c.wait_for(rb"partial-response", f"{what}: the response's start")
        conn.reset(b"", what)
        end = c.wait_for(rb"read:errno=(\d+)|<<< [^\n]*Alert[^\n]*close_notify", f"{what}: s_client's read ending")
        if end.group(1) is None:
            raise Fail(f"{what}: s_client received close_notify after the backend's RST; the truncation is hidden")
        if int(end.group(1)) != errno.ECONNRESET:
            raise Fail(f"{what}: s_client's read failed with errno {end.group(1).decode()}, want ECONNRESET")
        wait_server_rst(sniffer, start, port, HTTPS_WAIT_S, what)
    finally:
        c.close()
    con.wait_for(r"audit: src=tls TlsClosed\(BackendRst\) total=1 lost=\d+")
    passed.append("https backend reset truncates")
    print("\nPASS [https backend reset: no close_notify, ECONNRESET at the client, the server's RST seen]")

    what = "https client fin"
    i = backend.count()
    backend.hold_next()
    try:
        s = tls_client(ca)
    except OSError as e:
        raise Fail(f"{what}: {type(e).__name__}: {e}") from e
    with s:
        s.sendall(request_head())
        conn = backend.conn(i, what)
        conn.wait(lambda d, _: d.endswith(b"\r\n\r\n"), f"{what}: the request head")
        conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\npartial-response", what)
        got = b""
        while b"partial-response" not in got:
            chunk = s.recv(65536)
            if not chunk:
                raise Fail(f"{what}: the connection ended before the response's start")
            got += chunk
        # A TCP FIN without close_notify (the TLS layer dropped first).
        s.shutdown(socket.SHUT_WR)
        conn.wait(lambda _, ended: ended == "reset", f"{what}: the backend's connection aborted")
    passed.append("https client fin aborts backend")
    print("\nPASS [https client fin: the backend's connection aborted]")


def https_probe_case(con: Console, deploy: str, passed: list):
    """The probe (M6 plan C10, D3) and its canary (T-R3-8, T-N14): every
    handshake of PROBE_HANDSHAKES within a third of the Rust handshake
    timeout, so an eroded margin on a slower host fails by name rather than
    as a flaky timeout. Records the times and `tls`'s TlsSign high-water
    (the SIGN_COST_NS measurement)."""
    ca = os.path.join(deploy, "devca.pem")
    limit = rust_const(TLS_CONN, "HANDSHAKE_TIMEOUT_NS") / NS / 3
    mark = con.mark()
    times = []
    for _ in range(PROBE_HANDSHAKES):
        body, t = curl_get(ca)
        if body != backend_body():
            raise Fail(f"https probe: curl got a body of {len(body)} bytes, want the backend's")
        times.append(t)
    signs = [int(us) for us in con.count(r"audit: src=tls TlsSignHighWater us=(\d+) ")]
    print(f"\nhttps probe: handshake (appconnect - connect) s: {', '.join(f'{t:.3f}' for t in times)}; "
          f"max {max(times):.3f}, limit {limit:.3f}; TlsSignHighWater us: {signs}", flush=True)
    if not signs:
        raise Fail("https probe: tls never audited TlsSignHighWater")
    if max(times) > limit:
        raise Fail(f"https probe: probe margin exceeded: a handshake took {max(times):.3f} s, "
                   f"above a third of HANDSHAKE_TIMEOUT_NS ({limit:.3f} s)")
    if con.count(r"audit: src=tls unknown code", since=mark):
        raise Fail("https probe: tls raised an audit code audit cannot name")
    passed.append("https probe canary")
    print("\nPASS [https probe: every handshake within a third of the handshake timeout]")


def tls_scalar_count_case(mon: Monitor, deploy: str, passed: list):
    """M6 plan T8, F21, C12: after handshakes the client observed (the
    probe's), the TLS scalar occurs exactly once big-endian (`tlskey`'s
    plaintext) and never little-endian (HACL's limbs) in guest RAM; `key`'s
    blob holds none by construction."""
    with open(os.path.join(deploy, "tls-secrets.bin"), "rb") as f:
        scalar = f.read()[TLS_BLOB_TLS_PRIVATE]
    if not any(scalar):
        raise Fail("tls scalar count: the needle is all zero")
    scan_snapshot(mon, os.path.join(deploy, "pmem-tls.bin"), "tls scalar count", {}, {},
                  {"the TLS scalar (big-endian)": (scalar, 1), "the TLS scalar (little-endian)": (scalar[::-1], 0)})
    passed.append("tls scalar count")
    print("\nPASS [tls scalar: once big-endian, never little-endian in guest RAM]")


def tls_stack_headroom_case(con: Console, passed: list):
    """The C8 headroom rule (M4) for `tls`: after the probe's handshakes its
    StackHighWater reaches at least the exchange's scrub depth (else the
    probe is not measuring) and leaves STACK_HEADROOM_MIN of the system
    file's stack_size free. Marks are audited on timer ticks."""
    text = open(os.path.join(ROOT, "crates/tls-core/src/hybrid.rs")).read()
    m = re.search(r"pub const SCRUB_DEPTH_EXCHANGE: usize = (\d+) \* 1024;", text)
    if not m:
        raise Fail("SCRUB_DEPTH_EXCHANGE not found in crates/tls-core/src/hybrid.rs")
    floor, size = int(m.group(1)) * 1024, system_stack_size("tls")
    deadline = time.monotonic() + 3 * TIMER_TICK_S
    while True:
        marks = [int(b) for b in con.count(r"audit: src=tls StackHighWater bytes=(\d+) ")]
        if marks and max(marks) >= floor:
            break
        if time.monotonic() > deadline:
            raise Fail(f"tls: stack high-water {max(marks, default=0)} B is below its scrub depth {floor}; "
                       "the probe is not measuring")
        time.sleep(0.1)
    hw = max(marks)
    print(f"\ntls: stack high-water {hw} B of {size} B, {size - hw} B free", flush=True)
    if size - hw < STACK_HEADROOM_MIN:
        raise Fail(f"tls: {size - hw} B of stack free, want at least {STACK_HEADROOM_MIN}")
    passed.append("tls stack headroom")
    print("\nPASS [tls stack: reaches the exchange scrub, headroom kept]")


def test_https(pkg: "Package", deploy: str, other_ca: str, passed: list):
    """Boot "https" (M6 plan C3, C7, C9, C10): `tls` on the outside tap,
    proxying to the raw backend on the inside tap."""
    tap = Tap()
    inside = backend = sniffer = None
    monitor = os.path.join(deploy, "monitor.sock")
    try:
        inside = InsideTap()
        backend = Backend()
        child, con = boot(pkg, tap.netdev("n0"), inside.netdev("n1"), monitor)
    except BaseException:
        close_all(backend, inside, tap)
        raise
    try:
        sniffer = Sniffer(HTTPS_PORT, proto=6)
        wait_tap_ready(tap, con)
        con.wait_for(r"tls: ready", timeout=BOOT_TIMEOUT_S, strip_ready=True)
        mon = Monitor(monitor)
        https_handshake_cases(con, deploy, other_ca, backend, passed)
        https_rewrite_case(con, deploy, backend, passed)
        https_smuggling_cases(deploy, backend, passed)
        https_head_limit_case(con, deploy, backend, passed)
        https_backend_reset_case(con, deploy, backend, sniffer, passed)
        https_probe_case(con, deploy, passed)
        tls_stack_headroom_case(con, passed)
        tls_scalar_count_case(mon, deploy, passed)
    finally:
        try:
            with signals_held():
                close_all(sniffer)
                kill(child)
                close_all(backend, inside, tap)
        except SystemExit:
            close_all(sniffer)
            kill(child)
            close_all(backend, inside, tap)
            raise


def tcp_fields(frame: bytes):
    """(src ip, sport, dst ip, dport, flags, seq) of an IPv4/TCP frame, or
    None."""
    if len(frame) < 54 or frame[12:14] != b"\x08\x00" or frame[23] != 6:
        return None
    t = 14 + (frame[14] & 0xF) * 4
    sport, dport, seq, _, _, flags = struct.unpack("!HHIIBB", frame[t:t + 14])
    return frame[26:30], sport, frame[30:34], dport, flags, seq


def tcp_payload(frame: bytes) -> bytes:
    """The payload of an IPv4/TCP frame (tcp_fields accepted it)."""
    total = struct.unpack("!H", frame[16:18])[0]
    t = 14 + (frame[14] & 0xF) * 4
    return frame[t + (frame[t + 12] >> 4) * 4:14 + total]


def barrier_tcp(src_ip: bytes, sport: int, flags: int, seq: int, ack: int = 0) -> bytes:
    """A segment from `src_ip` (an address the boot uses for nothing else)
    to the HTTPS port, framed as the router would."""
    seg = struct.pack("!HHIIBBHHH", sport, HTTPS_PORT, seq, ack, 5 << 4, flags, 65535, 0, 0)
    c = csum(src_ip + GW_IP + struct.pack("!BBH", 0, 6, len(seg)) + seg)
    seg = seg[:16] + struct.pack("!H", c) + seg[18:]
    return eth(GW_MAC, PEER_MAC, 0x0800, ip_hdr(src_ip, GW_IP, 6, len(seg)) + seg)


def wait_server_rst(sniffer: "Sniffer", start: int, port: int, timeout: float, what: str, dst: bytes = None):
    """The server's RST to the client's `port` (at `dst`, if given), seen
    on the tap after `start`."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        sniffer.check_drops()
        for _, f, outgoing in sniffer.since(start):
            t = tcp_fields(f)
            if (not outgoing and t and t[0] == GW_IP and t[1] == HTTPS_PORT and t[3] == port
                    and t[4] & TCP_RST and dst in (None, t[2])):
                return
        time.sleep(0.05)
    raise Fail(f"{what}: no RST from the server to port {port}")


def barrier_syn(tap: Tap, sniffer: "Sniffer", what: str):
    """The C8 barrier (T-R3-3, T-R5-3): a SYN to the HTTPS port from an
    address the boot uses for nothing else, retried a bounded number of
    times, answered (SYN-ACK or RST). `tls` handles it in a later pass than
    the one that sent the abort RST, so that socket's release (storage
    wiped) is done. A SYN-ACK is reset so the listener is free again."""
    for i in range(BARRIER_SYN_TRIES):
        start = len(sniffer.since(0))
        sport, isn = 50000 + i, secrets.randbits(32)
        tap.send(barrier_tcp(BARRIER_IP, sport, TCP_SYN, isn))
        deadline = time.monotonic() + BARRIER_SYN_WAIT_S
        while time.monotonic() < deadline:
            sniffer.check_drops()
            for _, f, outgoing in sniffer.since(start):
                t = tcp_fields(f)
                if not outgoing and t and t[2] == BARRIER_IP and t[3] == sport and t[4] & (TCP_SYN | TCP_RST):
                    if t[4] & TCP_SYN:
                        tap.send(barrier_tcp(BARRIER_IP, sport, TCP_RST, (isn + 1) & 0xFFFFFFFF))
                    return
            time.sleep(0.02)
    raise Fail(f"{what}: barrier SYN unanswered")


def client_port(sniffer: "Sniffer", start: int, what: str) -> int:
    """The source port of the first SYN to the HTTPS port from the tap's
    address after `start`."""
    for _, f, outgoing in sniffer.since(start):
        t = tcp_fields(f)
        if outgoing and t and t[0] == PEER_IP and t[3] == HTTPS_PORT and t[4] & (TCP_SYN | TCP_ACK) == TCP_SYN:
            return t[1]
    raise Fail(f"{what}: no SYN from the client seen")


def slowloris_case(con: Console, passed: list):
    """M6 plan case 11 (T12, T-N2, T-R3-1), first in its boot so no earlier
    case raises the code: one byte of a ClientHello record per interval,
    shorter than the handshake timeout, until past it; the connection ends
    (EOF or RST) no later than the timeout plus slack (bounded from above
    only), and the TlsTimeout(Handshake) line has total=1."""
    timeout = rust_const(TLS_CONN, "HANDSHAKE_TIMEOUT_NS") / NS
    # A ClientHello record header announcing 512 bytes, then its handshake
    # header and filler: never complete at this rate.
    trickle = bytes([22, 3, 1, 2, 0, 1, 0, 1, 252]) + b"\0" * 64
    try:
        s = socket.create_connection((ip_str(GW_IP), HTTPS_PORT), timeout=HTTPS_WAIT_S)
    except OSError as e:
        raise Fail(f"slowloris: no TCP connection to port {HTTPS_PORT}: {e}") from e
    start = time.monotonic()
    ended = False
    with s:
        s.settimeout(SLOWLORIS_INTERVAL_S)
        for b in trickle:
            if time.monotonic() - start > timeout + SLOWLORIS_SLACK_S:
                break
            try:
                s.send(bytes([b]))
                if s.recv(1) == b"":
                    ended = True
                    break
            except socket.timeout:
                continue
            except OSError:
                # RST (ECONNRESET) or a send after it (EPIPE).
                ended = True
                break
    if not ended:
        raise Fail(f"slowloris: still open {time.monotonic() - start:.1f} s after connecting "
                   f"(handshake timeout {timeout:.0f} s)")
    con.wait_for(r"audit: src=tls TlsTimeout\(Handshake\) total=1 lost=\d+", timeout=LINE_TIMEOUT_S)
    passed.append("https slowloris")
    print(f"\nPASS [slowloris: closed after {time.monotonic() - start:.1f} s, TlsTimeout(Handshake) total=1]")


def https_residue_case(con: Console, mon: Monitor, tap: Tap, sniffer: "Sniffer", backend: Backend, deploy: str,
                       passed: list):
    """M6 plan C8 cases 1-3 (T6, T7, T-N2, T-N3, T-R3-2, T-N4), one
    connection A whose barriers are the backend's log: a POST head with
    Content-Length and a `Keep-Alive` marker (a field `rewrite` drops, so
    only `tls` ever holds it) and part of the body, logged by the backend
    (the server verified the client Finished and decrypted application
    data): both handshake secrets gone, CLIENT_TRAFFIC_SECRET_0 present,
    the marker already gone (the head is wiped once rewritten). Then `k`
    and more body, logged: client secret 0 gone, client secret 1 present.
    Then `K` and the rest of the body, logged, and the backend's first
    response bytes, which `tls` sends after its own KeyUpdate: server
    secret 0 and client secret 1 gone, server secret 1 and client secret 2
    present. Then the backend finishes: close_notify, the abort RST, a
    fresh SYN from an unused address answered (the socket released, its
    storage wiped); every secret of A, its record keys and IVs, and the
    marker are gone, while a live connection B, held in response streaming
    by the backend, has its CLIENT_TRAFFIC_SECRET_0 present (the control)
    and its own marker gone (rewritten). Neither marker reaches the
    backend."""
    ca = os.path.join(deploy, "devca.pem")
    marker, marker_b = secrets.token_hex(16), secrets.token_hex(16)
    log_a, log_b = (os.path.join(deploy, f"keylog-{n}.txt") for n in "ab")
    pmem = os.path.join(deploy, "pmem-residue.bin")
    idle = rust_const(TLS_CONN, "IDLE_TIMEOUT_NS") / NS
    for p in (log_a, log_b):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(p)
    # Three body parts; s_client takes a write starting with a command
    # letter (k, K, Q, R, ...) as a command, so none does.
    parts = [b"x" * 100, b"y" * 100, b"z" * 100]
    a = b = None
    try:
        i, start = backend.count(), len(sniffer.since(0))
        backend.hold_next()
        a = SClient("-groups", "X25519MLKEM768", "-CAfile", ca, "-verify_return_error", "-keylogfile", log_a)
        a.handshake("residue: connection A")
        port = client_port(sniffer, start, "residue: connection A")
        head = (f"POST /residue HTTP/1.1\r\nHost: {ip_str(GW_IP)}\r\nKeep-Alive: {marker}\r\n"
                f"Content-Length: {sum(map(len, parts))}\r\n\r\n").encode()
        a.send(head + parts[0])
        conn_a = backend.conn(i, "residue: connection A")
        conn_a.wait(lambda d, _: b"\r\n\r\n" in d and d.endswith(parts[0]), "residue: connection A's head logged")
        logged = keylog(log_a)
        need = ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0",
                "SERVER_TRAFFIC_SECRET_0")
        if any(len(logged.get(k, [])) != 1 for k in need):
            raise Fail(f"residue: connection A's keylog lacks one of {need}: {sorted(logged)}")
        c0, s0 = logged["CLIENT_TRAFFIC_SECRET_0"][0], logged["SERVER_TRAFFIC_SECRET_0"][0]
        c1 = hkdf_expand_label(c0, b"traffic upd", 32)
        c2 = hkdf_expand_label(c1, b"traffic upd", 32)
        s1 = hkdf_expand_label(s0, b"traffic upd", 32)
        handshake = {}
        for name, label in (("client handshake secret", "CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
                            ("server handshake secret", "SERVER_HANDSHAKE_TRAFFIC_SECRET")):
            handshake.update(secret_forms(f"connection A's {name}", logged[label][0]))
        scan_snapshot(mon, pmem, "residue after the head", {"marker": marker.encode(), **handshake},
                      {"connection A's client secret 0 (live)": c0})
        passed.append("https residue handshake secrets")
        print("\nPASS [https residue: after the head, the handshake secrets and the marker gone, client secret 0 "
              "held]")

        a.key_update(b"k", "residue: connection A's KeyUpdate")
        a.send(parts[1])
        conn_a.wait(lambda d, _: d.endswith(parts[0] + parts[1]), "residue: connection A's body after k logged")
        scan_snapshot(mon, pmem, "residue after k", secret_forms("connection A's client secret 0", c0),
                      {"connection A's client secret 1 (live)": c1})
        passed.append("https residue client key update")
        print("\nPASS [https residue: after k, client secret 0 gone, client secret 1 held]")

        a.key_update(b"K", "residue: connection A's requested KeyUpdate")
        a.send(parts[2])
        conn_a.wait(lambda d, _: d.endswith(b"".join(parts)), "residue: connection A's body after K logged")
        conn_a.send(b"HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\nresidue-part-1", "residue: connection A")
        a.wait_for(rb"residue-part-1", "residue: connection A's response start (sent under server secret 1)")
        scan_snapshot(mon, pmem, "residue after K",
                      {**secret_forms("connection A's server secret 0", s0),
                       **secret_forms("connection A's client secret 1", c1)},
                      {"connection A's server secret 1 (live)": s1, "connection A's client secret 2 (live)": c2})
        passed.append("https residue server key update")
        print("\nPASS [https residue: after K, server secret 0 and client secret 1 gone, server secret 1 and "
              "client secret 2 held]")
        # OpenSSL logs the updated secrets too: the derivation checked.
        logged = keylog(log_a)
        if logged.get("CLIENT_TRAFFIC_SECRET_N") != [c1, c2] or logged.get("SERVER_TRAFFIC_SECRET_N") != [s1]:
            raise Fail("residue: the traffic upd derivation differs from OpenSSL's keylog")

        # The control, held in response streaming while A closes.
        j = backend.count()
        backend.hold_next()
        b = SClient("-groups", "X25519MLKEM768", "-CAfile", ca, "-verify_return_error", "-keylogfile", log_b)
        b.handshake("residue: connection B")
        b.send(request_head(f"Keep-Alive: {marker_b}\r\n"))
        conn_b = backend.conn(j, "residue: connection B")
        conn_b.wait(lambda d, _: d.endswith(b"\r\n\r\n"), "residue: connection B's head logged")
        conn_b.send(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\nresidue-held", "residue: connection B")
        b.wait_for(rb"residue-held", "residue: connection B's response start")
        b_since = time.monotonic()
        control = keylog(log_b).get("CLIENT_TRAFFIC_SECRET_0", [None])[0]
        if control is None:
            raise Fail("residue: connection B's keylog has no CLIENT_TRAFFIC_SECRET_0")

        conn_a.finish(b"-residue-part-2-", "residue: connection A")
        wait_server_rst(sniffer, start, port, rust_const(TLS_CONN, "CLOSE_LINGER_NS") / NS + HTTPS_WAIT_S,
                        "residue: connection A's abort")
        barrier_syn(tap, sniffer, "residue")
        a.close()
        a = None
        absent = {"marker": marker.encode(), "connection B's marker (rewritten)": marker_b.encode()}
        for name, secret in (("client secret 0", c0), ("client secret 1", c1), ("client secret 2", c2),
                             ("server secret 0", s0), ("server secret 1", s1)):
            absent.update(secret_forms(f"connection A's {name}", secret))
        absent.update(handshake)
        if time.monotonic() - b_since >= idle:
            raise Fail("residue: connection B idled past the idle timeout before the scan; the control "
                       "would prove nothing")
        scan_snapshot(mon, pmem, "residue", absent, {"connection B's CLIENT_TRAFFIC_SECRET_0 (live)": control})
        for name, conn, m in (("A", conn_a, marker), ("B", conn_b, marker_b)):
            if m.encode() in conn.snapshot()[0]:
                raise Fail(f"residue: connection {name}'s Keep-Alive marker reached the backend")
    finally:
        close_all(a, b)
        for p in (log_a, log_b):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(p)
    passed.append("https residue closed connection")
    print("\nPASS [https residue: a closed connection's secrets, keys and marker gone; a live one's secret held, "
          "its marker gone]")


def test_https_residue(pkg: "Package", deploy: str, passed: list):
    """Boot "https-residue" (M6 plan C8, T-N2): slowloris first, then the
    residue cases."""
    tap = Tap()
    inside = backend = sniffer = None
    monitor = os.path.join(deploy, "monitor.sock")
    try:
        inside = InsideTap()
        backend = Backend()
        child, con = boot(pkg, tap.netdev("n0"), inside.netdev("n1"), monitor)
    except BaseException:
        close_all(backend, inside, tap)
        raise
    try:
        sniffer = Sniffer(HTTPS_PORT, proto=6)
        wait_tap_ready(tap, con)
        con.wait_for(r"tls: ready", timeout=BOOT_TIMEOUT_S, strip_ready=True)
        mon = Monitor(monitor)
        slowloris_case(con, passed)
        https_residue_case(con, mon, tap, sniffer, backend, deploy, passed)
    finally:
        try:
            with signals_held():
                close_all(sniffer)
                kill(child)
                close_all(backend, inside, tap)
        except SystemExit:
            close_all(sniffer)
            kill(child)
            close_all(backend, inside, tap)
            raise


def per_source_layout() -> tuple:
    """(MAX_CONNS, MAX_PER_SOURCE) from tls-core; CLIENT_IPS must fill every
    slot at the cap and have one source more."""
    conns, per = rust_usize(TLS_CONN, "MAX_CONNS"), rust_usize(TLS_CONN, "MAX_PER_SOURCE")
    if conns % per or len(CLIENT_IPS) < conns // per + 1:
        raise Fail(f"CLIENT_IPS has {len(CLIENT_IPS)} sources; MAX_CONNS {conns} at MAX_PER_SOURCE {per} needs "
                   f"{conns // per + 1} that fill the table exactly")
    return conns, per


def add_client_ips():
    """CLIENT_IPS on the tap (removed with it): the gateway answers every
    address through the router MAC, so kernel sockets bound to these are
    clients from distinct sources."""
    for ip in CLIENT_IPS:
        sh("ip", "addr", "add", f"{ip_str(ip)}/32", "dev", TAP)


def route_tunnel_replies():
    """The inside tap's host answers pings from peer 1's tunnel address
    through the gateway's inside NIC (removed with the inside tap)."""
    sh("ip", "route", "add", f"{ip_str(PEER1_IP)}/32", "via", ip_str(INSIDE_IP), "dev", INSIDE_TAP)


class HeldConn:
    """A connection from `source` held in response streaming (M6 plan case
    10): the backend logged its request and answered a head announcing
    HELD_BODY_LEN body bytes with the first HELD_FIRST of them, and the
    client read that much. `tick` sends one more body byte (activity, so
    the idle timeout does not end it); `finish` sends the rest and FIN, and
    the client must receive the whole response; `released` waits for the
    server's abort RST that ends the slot's release."""

    def __init__(self, ca: str, backend: Backend, sniffer: Sniffer, source: bytes, what: str):
        self.what, self.source = what, source
        self.head = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % HELD_BODY_LEN
        self.body = secrets.token_bytes(HELD_BODY_LEN)
        self.at = HELD_FIRST
        self.start = len(sniffer.since(0))
        i = backend.count()
        backend.hold_next()
        try:
            self.s = tls_client(ca, source=source)
        except OSError as e:
            raise Fail(f"{what} from {ip_str(source)}: {type(e).__name__}: {e}") from e
        try:
            self.port = self.s.getsockname()[1]
            self.opened = time.monotonic()
            self.s.sendall(request_head())
            self.conn = backend.conn(i, what)
            self.conn.wait(lambda d, _: d.endswith(b"\r\n\r\n"), f"{what}: the request head")
            self.conn.send(self.head + self.body[:HELD_FIRST], what)
            self.got = self._read(len(self.head) + HELD_FIRST)
            self.last = time.monotonic()
        except BaseException:
            self.s.close()
            raise

    def _read(self, n: int) -> bytes:
        got = b""
        try:
            while len(got) < n:
                chunk = self.s.recv(65536)
                if not chunk:
                    raise Fail(f"{self.what}: the connection ended after {len(got)} of {n} bytes")
                got += chunk
        except OSError as e:
            raise Fail(f"{self.what}: {type(e).__name__}: {e}") from e
        return got

    def tick(self, idle: float):
        gap = time.monotonic() - self.last
        if gap >= idle:
            raise Fail(f"{self.what}: went {gap:.1f} s without a byte, past the idle timeout; the case would "
                       "prove nothing")
        self.conn.send(self.body[self.at:self.at + 1], self.what)
        self.at += 1
        self.last = time.monotonic()

    def finish(self, lifetime: float):
        age = time.monotonic() - self.opened
        if age >= lifetime:
            raise Fail(f"{self.what}: {age:.0f} s old, past the connection lifetime; the case would prove nothing")
        self.conn.finish(self.body[self.at:], self.what)
        try:
            got = self.got + read_to_end(self.s)
        except OSError as e:
            raise Fail(f"{self.what} did not survive: {type(e).__name__}: {e}") from e
        if got != self.head + self.body:
            raise Fail(f"{self.what} received {len(got)} bytes, want its response of "
                       f"{len(self.head) + HELD_BODY_LEN} bytes byte for byte")
        self.s.close()

    def released(self, sniffer: Sniffer, linger: float):
        wait_server_rst(sniffer, self.start, self.port, linger + HTTPS_WAIT_S, f"{self.what}: the slot's release",
                        dst=self.source)

    def close(self):
        self.s.close()


def https_recycling_case(con: Console, deploy: str, backend: Backend, sniffer: Sniffer, passed: list):
    """M6 plan case 10, slot recycling and the ninth connection (F4, T-N6,
    T-R3-4, T-R4-2), first in its boot: MAX_CONNS - 1 connections from four
    sources held in response streaming; the free slot then serves
    RECYCLE_CYCLES full requests from the fourth source, each closed by the
    server (the backend's FIN, close_notify, the abort RST, after which the
    slot is released) and each accepted on its first SYN, the backend
    sending every held connection one body byte between cycles so none
    reaches its idle timeout. With that slot held too, a connection from a
    fifth source gets the server's RST. Then every held connection, within
    its idle timeout and lifetime (read from the Rust source), receives its
    whole response."""
    ca = os.path.join(deploy, "devca.pem")
    conns, per = per_source_layout()
    idle = rust_const(TLS_CONN, "IDLE_TIMEOUT_NS") / NS
    lifetime = rust_const(TLS_CONN, "LIFETIME_NS") / NS
    linger = rust_const(TLS_CONN, "CLOSE_LINGER_NS") / NS
    what = "https slot recycling"
    want = backend_response(request_head())
    held = []
    try:
        for k in range(conns - 1):
            held.append(HeldConn(ca, backend, sniffer, CLIENT_IPS[k // per], f"{what}: held connection {k + 1}"))
        source = CLIENT_IPS[(conns - 1) // per]
        took = []
        for c in range(1, RECYCLE_CYCLES + 1):
            cycle = f"{what}: cycle {c} of {RECYCLE_CYCLES}"
            start, t0 = len(sniffer.since(0)), time.monotonic()
            try:
                s = tls_client(ca, source=source)
            except ConnectionRefusedError as e:
                raise Fail(f"{cycle} was refused; the server-closed slot did not return to listening") from e
            except OSError as e:
                raise Fail(f"{cycle}: {type(e).__name__}: {e}") from e
            with s:
                port = s.getsockname()[1]
                try:
                    s.sendall(request_head())
                    got = read_to_end(s)
                except OSError as e:
                    raise Fail(f"{cycle}: {type(e).__name__}: {e}") from e
            if got != want:
                raise Fail(f"{cycle}: the client received {len(got)} bytes, want the backend's response exactly")
            wait_server_rst(sniffer, start, port, linger + HTTPS_WAIT_S, f"{cycle}: the server's abort", dst=source)
            took.append(time.monotonic() - t0)
            for h in held:
                h.tick(idle)
        print(f"\nhttps slot recycling: cycles took {', '.join(f'{t:.1f}' for t in took)} s", flush=True)

        held.append(HeldConn(ca, backend, sniffer, source, f"{what}: held connection {conns}"))
        ninth = CLIENT_IPS[conns // per]
        start, before = len(sniffer.since(0)), backend.count()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with s:
            s.settimeout(HTTPS_WAIT_S)
            s.bind((ip_str(ninth), 0))
            port = s.getsockname()[1]
            try:
                s.connect((ip_str(GW_IP), HTTPS_PORT))
            except ConnectionRefusedError:
                pass
            else:
                raise Fail(f"https ninth connection: a connection from a fifth source was accepted with all "
                           f"{conns} slots held")
        wait_server_rst(sniffer, start, port, HTTPS_WAIT_S, "https ninth connection", dst=ninth)
        if backend.count() != before:
            raise Fail("https ninth connection: the refused connection reached the backend")
        passed.append("https ninth connection refused")
        print(f"\nPASS [https ninth connection: with {conns} held from {conns // per} sources, a fifth source gets RST]")

        for h in held:
            h.finish(lifetime)
        for h in held:
            h.released(sniffer, linger)
    finally:
        close_all(*held)
    passed.append("https slot recycling")
    print(f"\nPASS [https slot recycling: {RECYCLE_CYCLES} server-closed requests through the free slot, each "
          f"accepted; the {conns - 1} held connections alive and answered]")


def https_source_cap_case(con: Console, deploy: str, backend: Backend, sniffer: Sniffer, passed: list):
    """M6 plan case 10, the per-source cap with free slots: two connections
    from source A held, a third from A refused (the server's RST, audited
    TlsClosed(PerSource), nothing reaches the backend), one from B accepted
    and answered (the allow pair)."""
    ca = os.path.join(deploy, "devca.pem")
    _, per = per_source_layout()
    linger = rust_const(TLS_CONN, "CLOSE_LINGER_NS") / NS
    what = "https per-source cap"
    a, b = CLIENT_IPS[0], CLIENT_IPS[1]
    held = []
    try:
        for k in range(per):
            held.append(HeldConn(ca, backend, sniffer, a, f"{what}: held connection {k + 1} from A"))
        start, before, mark = len(sniffer.since(0)), backend.count(), con.mark()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with s:
            s.settimeout(HTTPS_WAIT_S)
            s.bind((ip_str(a), 0))
            port = s.getsockname()[1]
            try:
                s.connect((ip_str(GW_IP), HTTPS_PORT))
                # Connected: the RST may still follow the SYN-ACK, before
                # any TLS; a completed handshake is the cap's failure.
                ctx = ssl.create_default_context(cafile=ca)
                with ctx.wrap_socket(s, server_hostname=ip_str(GW_IP)):
                    pass
            except (ConnectionRefusedError, ConnectionResetError, ssl.SSLEOFError):
                pass
            else:
                raise Fail(f"{what}: a connection from a source holding {per} completed a handshake; the cap did not "
                           "refuse it")
        wait_server_rst(sniffer, start, port, HTTPS_WAIT_S, f"{what}: the refusal", dst=a)
        con.wait_for(r"audit: src=tls TlsClosed\(PerSource\) total=1 lost=\d+", since=mark)
        if backend.count() != before:
            raise Fail(f"{what}: the refused connection reached the backend")

        start = len(sniffer.since(0))
        try:
            with tls_client(ca, source=b) as s:
                port = s.getsockname()[1]
                s.sendall(request_head())
                got = read_to_end(s)
        except OSError as e:
            raise Fail(f"{what}: source B: {type(e).__name__}: {e}") from e
        if got != backend_response(request_head()):
            raise Fail(f"{what}: source B received {len(got)} bytes, want the backend's response exactly")
        wait_server_rst(sniffer, start, port, linger + HTTPS_WAIT_S, f"{what}: source B's release", dst=b)
        for h in held:
            h.finish(rust_const(TLS_CONN, "LIFETIME_NS") / NS)
        for h in held:
            h.released(sniffer, linger)
    finally:
        close_all(*held)
    passed.append("https per-source cap")
    print(f"\nPASS [https per-source cap: a third connection from a source holding {per} refused with RST and "
          "TlsClosed(PerSource), another source accepted]")


def https_concurrent_probe(con: Console, deploy: str, sniffer: Sniffer, passed: list):
    """The 8-concurrent probe (M6 plan C10, D3, RM6-8): MAX_CONNS handshakes
    started together from four sources, each then fetching the backend's
    response. Every connection must get a slot (else the probe measured
    fewer); each handshake's time, and whether it failed (a server-side
    handshake timeout under TCG: sign time × the queue), is recorded, not
    asserted: RM6-8's measured value for D3."""
    ca = os.path.join(deploy, "devca.pem")
    conns, per = per_source_layout()
    timeout = rust_const(TLS_CONN, "HANDSHAKE_TIMEOUT_NS") / NS
    linger = rust_const(TLS_CONN, "CLOSE_LINGER_NS") / NS
    want = backend_response(request_head())
    results = [None] * conns
    go = threading.Event()
    start, mark = len(sniffer.since(0)), con.mark()

    def one(k: int):
        src = CLIENT_IPS[k // per]
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except OSError as e:
            results[k] = ("socket", 0.0, 0, repr(e))
            return
        with raw:
            go.wait()
            try:
                raw.settimeout(timeout + HTTPS_WAIT_S)
                raw.bind((ip_str(src), 0))
                port = raw.getsockname()[1]
                raw.connect((ip_str(GW_IP), HTTPS_PORT))
            except OSError as e:
                results[k] = ("connect", 0.0, 0, f"{type(e).__name__}: {e}")
                return
            ctx = ssl.create_default_context(cafile=ca)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            t0 = time.monotonic()
            try:
                with ctx.wrap_socket(raw, server_hostname=ip_str(GW_IP)) as s:
                    t = time.monotonic() - t0
                    s.sendall(request_head())
                    ok = read_to_end(s) == want
                results[k] = ("ok" if ok else "body", t, port, "")
            except OSError as e:
                results[k] = ("failed", time.monotonic() - t0, port, f"{type(e).__name__}: {e}")

    threads = [threading.Thread(target=one, args=(k,), daemon=True) for k in range(conns)]
    try:
        for t in threads:
            start_without_stop_signals(t)
        go.set()
    finally:
        go.set()
        deadline = time.monotonic() + 2 * (timeout + HTTPS_WAIT_S)
        for t in threads:
            t.join(max(0.0, deadline - time.monotonic()))
    if any(t.is_alive() for t in threads) or None in results:
        raise Fail("https concurrent probe: a client thread did not finish with a result")
    signs = [int(us) for us in con.count(r"audit: src=tls TlsSignHighWater us=(\d+) ", since=mark)]
    timeouts = con.count(r"audit: src=tls TlsTimeout\(Handshake\) total=\d+ ", since=mark)
    print("\nhttps concurrent probe (RM6-8): " + "; ".join(
        f"{ip_str(CLIENT_IPS[k // per])} {r[0]} {r[1]:.3f} s{' ' + r[3] if r[3] else ''}"
        for k, r in enumerate(results)) + f"; failed {sum(r[0] == 'failed' for r in results)} of {conns}; "
        f"TlsTimeout(Handshake) audited: {bool(timeouts)}; TlsSignHighWater us since: {signs}", flush=True)
    for k, r in enumerate(results):
        if r[0] in ("socket", "connect"):
            raise Fail(f"https concurrent probe: client {k + 1} got no slot ({r[3]}); the probe did not hold "
                       f"{conns} at once")
        if r[0] == "body":
            raise Fail(f"https concurrent probe: client {k + 1} did not receive the backend's response exactly")
    for k, r in enumerate(results):
        wait_server_rst(sniffer, start, r[2], linger + HTTPS_WAIT_S, f"https concurrent probe: client {k + 1}'s release",
                        dst=CLIENT_IPS[k // per])
    passed.append("https concurrent probe")
    print(f"\nPASS [https concurrent probe: {conns} handshakes from {conns // per} sources at once, times recorded]")


def capture_client_hello(ca: str, sniffer: Sniffer, what: str) -> bytes:
    """An OpenSSL ClientHello record as it crossed the tap (M6 plan case
    12): one verified exchange from the tap's address, its client's first
    record reassembled from the sniffed segments."""
    start = len(sniffer.since(0))
    try:
        with tls_client(ca) as s:
            port = s.getsockname()[1]
            s.sendall(request_head())
            read_to_end(s)
    except OSError as e:
        raise Fail(f"{what}: the capture exchange failed: {type(e).__name__}: {e}") from e
    sniffer.check_drops()
    segments, first = {}, None
    for _, f, outgoing in sniffer.since(start):
        t = tcp_fields(f)
        if outgoing and t and t[0] == PEER_IP and t[1] == port and t[3] == HTTPS_PORT:
            payload = tcp_payload(f)
            if payload:
                segments.setdefault(t[5], payload)
                first = t[5] if first is None else first
    stream, seq = b"", first
    while seq in segments and (len(stream) < 5 or len(stream) < 5 + struct.unpack("!H", stream[3:5])[0]):
        stream += segments[seq]
        seq = (seq + len(segments[seq])) & 0xFFFFFFFF
    if len(stream) < 6 or stream[0] != 22 or stream[5] != 1:
        raise Fail(f"{what}: no ClientHello record among the client's sniffed segments")
    length = 5 + struct.unpack("!H", stream[3:5])[0]
    if len(stream) < length:
        raise Fail(f"{what}: the sniffed ClientHello is incomplete ({len(stream)} of {length} bytes)")
    return stream[:length]


class HelloFlood:
    """One ClientHello replayed over fresh TCP connections, `per_source` at
    a time from each of `sources` (kernel sockets, so each completes its
    TCP handshake), by helper threads. A connection counts a flight once
    the server's first byte arrives as a handshake record: `tls` builds the
    whole flight, CertificateVerify's signature included, before sending
    any of it. Each connection is then reset (SO_LINGER 0) so its slot
    frees at once. close() shuts any open socket down so the threads end
    promptly."""

    def __init__(self, hello: bytes, sources: list, per_source: int, wait: float):
        self.hello, self.wait = hello, wait
        self.lock = threading.Lock()
        self.flights = self.refused = self.ended = 0
        self.socks = set()
        self.stopped = False
        self.error = None
        self.threads = [threading.Thread(target=self._run, args=(src,), daemon=True)
                        for src in sources for _ in range(per_source)]
        for t in self.threads:
            start_without_stop_signals(t)

    def _count(self, field: str):
        with self.lock:
            setattr(self, field, getattr(self, field) + 1)

    def _run(self, src: bytes):
        try:
            while not self.stopped:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                with self.lock:
                    self.socks.add(s)
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    s.settimeout(self.wait)
                    s.bind((ip_str(src), 0))
                    try:
                        s.connect((ip_str(GW_IP), HTTPS_PORT))
                    except ConnectionRefusedError:
                        # Its previous slot still closing (the per-source
                        # cap), or every slot taken.
                        self._count("refused")
                        continue
                    s.sendall(self.hello)
                    self._count("flights" if s.recv(1) == b"\x16" else "ended")
                except (ConnectionResetError, BrokenPipeError, socket.timeout):
                    # The handshake timeout's RST, or close() below.
                    self._count("ended")
                finally:
                    with self.lock:
                        self.socks.discard(s)
                    s.close()
        except OSError as e:
            if not self.stopped:
                self.error = e

    def counts(self) -> tuple:
        with self.lock:
            return self.flights, self.refused, self.ended

    def verify(self, what: str):
        if self.error is not None:
            raise Fail(f"{what}: the ClientHello flood failed: {self.error!r}")
        if not all(t.is_alive() for t in self.threads):
            raise Fail(f"{what}: the ClientHello flood stopped before the judgment")

    def wait_flights(self, n: int, timeout: float, what: str):
        deadline = time.monotonic() + timeout
        while self.counts()[0] < n:
            self.verify(what)
            if time.monotonic() > deadline:
                raise Fail(f"{what}: the ClientHello flood drew {self.counts()[0]} server flights, not {n}, within "
                           f"{timeout:.0f} s")
            time.sleep(0.05)

    def close(self):
        self.stopped = True
        with self.lock:
            socks = list(self.socks)
        for s in socks:
            with contextlib.suppress(OSError):
                s.shutdown(socket.SHUT_RDWR)
        for t in self.threads:
            t.join(self.wait + 1)


def key_waits(con: Console, since: int = 0) -> list:
    return [int(us) for us in con.count(r"audit: src=hs KeyWaitHighWater us=(\d+) ", since=since)]


def https_hello_flood_case(con: Console, deploy: str, sniffer: Sniffer, gw_pub: bytes, rp: Rosenpass, passed: list):
    """M6 plan case 12 as amended by Re-plan R1 (positive only; R2-T N5,
    R2-F N3): a WireGuard handshake completes while a replayed OpenSSL
    ClientHello floods `tls` from four sources, two connections each, so
    that every one costs a full exchange and a signature. The flood is
    under way (MAX_CONNS server flights drawn) before the handshake starts
    and still drawing flights after it completes. KeyWaitHighWater is
    recorded, not asserted (drivers at 150 preempt `key`)."""
    ca = os.path.join(deploy, "devca.pem")
    conns, per = per_source_layout()
    timeout = rust_const(TLS_CONN, "HANDSHAKE_TIMEOUT_NS") / NS
    what = "https clienthello flood"
    peer1 = open(os.path.join(deploy, "peer-1.conf")).read()
    py = py2 = flood = None
    try:
        # Unloaded first: pq's key reached hs (the baseline wait printed).
        py = py_installed(peer1, gw_pub, rp, time.monotonic() + RP_EXCHANGE_S)
        baseline = key_waits(con)
        hello = capture_client_hello(ca, sniffer, what)
        flood = HelloFlood(hello, CLIENT_IPS[:conns // per], per, timeout + HTTPS_WAIT_S)
        # Each flight at most a third of the handshake timeout (the probe's
        # gate), one after another through `tls`.
        flood.wait_flights(conns, conns * timeout / 3 + LINE_TIMEOUT_S, what)
        mark = con.mark()
        py2 = py_installed(peer1, gw_pub, rp, time.monotonic() + RP_EXCHANGE_S)
        after = flood.counts()[0]
        flood.wait_flights(after + 1, timeout + LINE_TIMEOUT_S, what)
        flood.verify(what)
        flights, refused, ended = flood.counts()
        print(f"\nhttps clienthello flood: a {len(hello)}-byte ClientHello, {flights} flights, {refused} refused, "
              f"{ended} ended without one; KeyWaitHighWater us before {baseline}, during {key_waits(con, mark)}",
              flush=True)
    finally:
        close_all(flood, py, py2)
    passed.append("https clienthello flood")
    print("\nPASS [https clienthello flood: a WireGuard handshake completes while replayed ClientHellos load tls]")


def https_syn_flood_case(con: Console, tap: Tap, deploy: str, gw_pub: bytes, rp: Rosenpass, passed: list):
    """M6 plan case 9 (S4, T11, T-N5, T-R3-1), last in its boot: spoofed
    SYNs to the HTTPS port from SPOOF_SOURCES addresses until the
    TcpLimited(SynGlobal) total crosses a printed point (that line awaited
    first), then, the flood still running, a WireGuard handshake and a ping
    through it. Positive availability: HTTPS may refuse new clients
    meanwhile (RM6-7)."""
    what = "https syn flood"
    src_refill = NS / rust_const(INGRESS_CORE, "SYN_SRC_INTERVAL_NS")
    global_refill = NS / rust_const(LIMITS, "SYN_GLOBAL_INTERVAL_NS")
    if SYN_FLOOD_RATE / SPOOF_SOURCES >= src_refill or SYN_FLOOD_RATE <= 2 * global_refill:
        raise Fail(f"{what}: SYN_FLOOD_RATE {SYN_FLOOD_RATE:.0f}/s does not keep each source under its "
                   f"{src_refill:.0f}/s and the total over twice the global {global_refill:.0f}/s")
    peer1 = open(os.path.join(deploy, "peer-1.conf")).read()
    frames = [barrier_tcp(ip, port, TCP_SYN, secrets.randbits(32)) for ip, port in spoof_ips(SPOOF_SOURCES)]
    mark = con.mark()
    spoof = py = None
    try:
        spoof = Spoof(tap, frames, SYN_FLOOD_RATE)
        # The first second's frames on the tap before any judgment: `verify`
        # right after the start would see none scheduled yet.
        spoof.wait_delivered(int(SYN_FLOOD_RATE), what)
        deadline = time.monotonic() + SYN_GLOBAL_POINT / (SYN_FLOOD_RATE - global_refill) + LINE_TIMEOUT_S
        while True:
            totals = [int(t) for t in con.count(r"audit: src=ingress TcpLimited\(SynGlobal\) total=(\d+) lost=\d+\r*\n",
                                                since=mark)]
            if totals and max(totals) >= SYN_GLOBAL_POINT:
                break
            spoof.verify(what)
            if time.monotonic() > deadline:
                raise Fail(f"{what}: TcpLimited(SynGlobal) never reached total={SYN_GLOBAL_POINT} (lines: {totals}); "
                           "the flood did not cross the global SYN bucket")
            time.sleep(0.05)
        py = py_installed(peer1, gw_pub, rp, time.monotonic() + RP_EXCHANGE_S)
        if not py_ping(py, FLOOD_PING_TRIES, ident=0x5359):
            raise Fail(f"{what}: no ping reply through the tunnel during the flood")
        spoof.verify(what)
    finally:
        close_all(py, spoof)
    passed.append("https syn flood")
    print(f"\nPASS [https syn flood: TcpLimited(SynGlobal) crossed {SYN_GLOBAL_POINT}; a WireGuard handshake and a ping "
          "through it during the flood]")


def test_https_flood(pkg: "Package", deploy: str, passed: list):
    """Boot "https flood" (M6 plan cases 9, 10, 12 and the concurrent probe,
    RM6-4, RM6-7, RM6-8): HTTPS clients from CLIENT_IPS on the outside tap,
    the raw backend on the inside tap, which also answers pings from peer
    1's tunnel address. Case 10 first (fresh slots), the probe, then
    Rosenpass for peer 1, case 12, and the SYN flood last (its spoofed SYNs
    hold listeners until their timeout)."""
    tap = Tap()
    inside = backend = sniffer = rp = None
    try:
        add_client_ips()
        inside = InsideTap()
        route_tunnel_replies()
        backend = Backend()
        child, con = boot(pkg, tap.netdev("n0"), inside.netdev("n1"))
    except BaseException:
        close_all(backend, inside, tap)
        raise
    try:
        sniffer = Sniffer(HTTPS_PORT, proto=6)
        wait_tap_ready(tap, con)
        con.wait_for(r"tls: ready", timeout=BOOT_TIMEOUT_S, strip_ready=True)
        https_recycling_case(con, deploy, backend, sniffer, passed)
        https_source_cap_case(con, deploy, backend, sniffer, passed)
        https_concurrent_probe(con, deploy, sniffer, passed)
        cfg = tomllib.load(open(os.path.join(deploy, "gateway.toml"), "rb"))
        gw_pub = b64(cfg["gateway"]["public_key"])
        con.wait_for(r"pq: ready", timeout=BOOT_TIMEOUT_S, strip_ready=True)
        rp = Rosenpass(deploy, 1, f"{ip_str(GW_IP)}:{RP_PORT}")
        https_hello_flood_case(con, deploy, sniffer, gw_pub, rp, passed)
        https_syn_flood_case(con, tap, deploy, gw_pub, rp, passed)
    finally:
        try:
            with signals_held():
                close_all(sniffer, rp)
                kill(child)
                close_all(backend, inside, tap)
        except SystemExit:
            close_all(sniffer, rp)
            kill(child)
            close_all(backend, inside, tap)
            raise


def test_tls_key_failure(pkg: "Package", deploy: str, passed: list):
    """M6 plan case 8 (C12, C11, S-N3, R1-T T11, T12): the image with a TLS
    blob whose scalar is valid but not the certificate's. `tlskey` is
    Unavailable: `tls`'s boot-seed call at init is answered with its
    Mismatch code, `tls` audits KeyUnavailable and halts before it listens
    (it never prints ready), so HTTPS is refused; `key` and `pqkey` are
    untouched and the VPN completes a handshake. The rejected scalar occurs
    nowhere in guest RAM (`tlskey` wiped its plaintext), while the gateway
    key `key` holds for `hs` does (the control). Every key PD finished, so
    PCR 8 reads as capped."""
    with open(os.path.join(deploy, "tls-secrets-mismatch.bin"), "rb") as f:
        rejected = f.read()[TLS_BLOB_TLS_PRIVATE]
    with open(os.path.join(deploy, "tls-secrets.bin"), "rb") as f:
        if f.read()[TLS_BLOB_TLS_PRIVATE] == rejected:
            raise Fail("tls key failure: the mismatch blob carries the deployment's own TLS scalar")
    with open(os.path.join(deploy, "secrets.bin"), "rb") as f:
        gateway_private = f.read()[KEY_BLOB_GATEWAY_PRIVATE]
    if not any(rejected) or not any(gateway_private):
        raise Fail("tls key failure: a needle is all zero; the scan would prove nothing")
    code, reason = boot_code("tlskey-core", "Mismatch"), halt_reason("tls", "KEY_UNAVAILABLE")
    image, desc = pkg.read("published.img"), pkg.read("boot.desc")
    capped = measure.extend(measure.expected_pcr8(desc, image), cap_digest())
    tap = Tap()
    inside = Wire()
    monitor = os.path.join(deploy, "monitor.sock")
    try:
        child, con = boot(pkg, tap.netdev("n0"), inside.netdev("n1"), monitor)
    except BaseException:
        tap.close()
        raise
    rp = py = None
    try:
        wait_tap_ready(tap, con)
        # Failure-only: tls ready means it listened with tlskey Unavailable.
        m = con.wait_for(r"audit: src=tls KeyUnavailable code=(\d+) lost=\d+\r*\n|tls: ready\r*\n",
                         timeout=BOOT_TIMEOUT_S, strip_ready=True)
        if m.group(1) is None:
            raise Fail("tls key failure: tls became ready (it listens) with tlskey Unavailable")
        if int(m.group(1)) != code:
            raise Fail(f"tls key failure: tls audited KeyUnavailable code={m.group(1)}, want Mismatch ({code})")
        con.wait_for(rf"audit: src=tls Halted reason={reason} lost=\d+\r*\n", since=m.end())
        r = curl(os.path.join(deploy, "devca.pem"), https_url())
        if r.returncode == 0:
            raise Fail("tls key failure: HTTPS completed with tlskey Unavailable")
        cfg = tomllib.load(open(os.path.join(deploy, "gateway.toml"), "rb"))
        con.wait_for(r"pq: ready", timeout=BOOT_TIMEOUT_S, strip_ready=True)
        mark = con.mark()
        rp = Rosenpass(deploy, 0, f"{ip_str(GW_IP)}:{RP_PORT}")
        py = py_installed(open(os.path.join(deploy, "peer-0.conf")).read(), b64(cfg["gateway"]["public_key"]), rp,
                          time.monotonic() + RP_EXCHANGE_S)
        con.wait_for(r"audit: src=hs HandshakeOk total=1 ", since=mark)
        scan_snapshot(Monitor(monitor), os.path.join(deploy, "pmem-tls-key.bin"), "tls key failure",
                      {"the rejected TLS scalar": rejected, "the rejected TLS scalar (little-endian)": rejected[::-1]},
                      {"the gateway key key holds for hs": gateway_private})
        # QEMU killed (no CMD_SHUTDOWN reaches swtpm), its TPM kept: the cap
        # came once tlskey sent Failed, after key and pqkey.
        kill_qemu(child)
        got = read_pcr8(child.tpm)
        if got != capped:
            state = "uncapped" if got == measure.expected_pcr8(desc, image) else "unexpected"
            raise Fail(f"tls key failure: PCR 8 is {got.hex()} ({state}), want the capped {capped.hex()}")
        passed.append("tls key failure")
        print("\nPASS [tls key failure: tls halted before listening, HTTPS refused, the VPN handshakes, PCR 8 capped]")
    finally:
        try:
            with signals_held():
                close_all(rp, py)
                kill(child)
                tap.close()
        except SystemExit:
            close_all(rp, py)
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
    not occur in the published image. Code or tables could match by
    accident: the oracle links some of the same crates."""
    image = open(loader, "rb").read()
    for path in sorted(ORACLE_BINS):
        data = open(path, "rb").read()
        if data[:256] in image:
            raise Fail(f"{loader} contains part of {path}")


def preflight():
    check_rosenpass_oracle()
    missing = [t for t in ("unshare", "setpriv", "wireguard-go", "wg", "ip", "ping", "qemu-system-aarch64", "swtpm",
                           "tpm2_createprimary", "tpm2_readpublic", "openssl", "curl")
               if not shutil.which(t)]
    if not os.path.isfile(UBOOT):
        raise Fail(f"{UBOOT} is missing; `make uboot` builds it")
    if missing:
        raise Fail(f"missing tools: {missing}")
    if not os.path.exists("/dev/net/tun"):
        raise Fail("/dev/net/tun not available")
    # M6 (T21): the HTTPS cases' clients must speak X25519MLKEM768.
    groups = subprocess.run(["openssl", "list", "-tls-groups"], capture_output=True, text=True)
    if groups.returncode != 0 or "X25519MLKEM768" not in groups.stdout.split(":"):
        raise Fail(f"openssl has no X25519MLKEM768 group: {groups.stdout.strip()} {groups.stderr.strip()}")
    curl = subprocess.run(["curl", "--version"], capture_output=True, text=True)
    if curl.returncode != 0 or not re.search(r"\bOpenSSL/3\.([5-9]|\d{2,})\.", curl.stdout):
        raise Fail(f"curl does not link OpenSSL 3.5 or later: {curl.stdout.splitlines()[:1]}")
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


# Every image this suite packages and boots is a release one (M5 plan C7).
MAKE_CONFIG = "MICROKIT_CONFIG=release"


def make(*args, env=None):
    r = subprocess.run(["make", "-C", ROOT, MAKE_CONFIG, *args], env=env, capture_output=True, text=True)
    if r.returncode:
        raise Fail(f"make {' '.join(args)} failed:\n{r.stdout[-2000:]}{r.stderr[-2000:]}")


# The SRK every envelope is sealed to: the TCG storage template, as
# tpm2::envelope pins it (the interop tests check the two agree).
SRK_TEMPLATE = ["-C", "o", "-G", "ecc256:aes128cfb", "-g", "sha256", "-a",
                "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt"]


def read_srk(state: str, out: str):
    """Starts swtpm on `state` with a data socket for tpm2-tools, writes the
    SRK's TPM2B_PUBLIC to `out`, and kills it again (nothing volatile is
    saved, so a boot's TPM2_Startup finds a fresh TPM)."""
    # tpm2-tss's swtpm TCTI finds the control socket at the data path + ".ctrl".
    data = os.path.join(state, "tpm.sock")
    ctrl = data + ".ctrl"
    ctx = out + ".ctx"
    proc = subprocess.Popen(DIE_WITH_PARENT + ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state}",
                                               "--ctrl", f"type=unixio,path={ctrl}", "--server",
                                               f"type=unixio,path={data}", "--flags", "not-need-init,startup-clear"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + SWTPM_SOCKET_WAIT_S
        while not os.path.exists(data):
            if proc.poll() is not None or time.monotonic() > deadline:
                raise Fail("swtpm did not open its data socket for provisioning")
            time.sleep(0.05)
        env = {**os.environ, "TPM2TOOLS_TCTI": f"swtpm:path={data}"}
        subprocess.run(["tpm2_createprimary", "-Q", *SRK_TEMPLATE, "-c", ctx], check=True, env=env,
                       capture_output=True)
        subprocess.run(["tpm2_readpublic", "-Q", "-c", ctx, "-o", out], check=True, env=env, capture_output=True)
    finally:
        proc.kill()
        proc.wait()
        # swtpm's lock file goes too: only the TPM's own state is copied.
        for path in (ctrl, data, ctx, os.path.join(state, ".lock")):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)
    if sorted(os.listdir(state)) != [SWTPM_PERMALL]:
        raise Fail(f"provisioned swtpm state holds {sorted(os.listdir(state))}, want {SWTPM_PERMALL} alone")


def provision_tpm(root: str, name: str) -> tuple:
    """One deployment's TPM (C14): a swtpm state initialised once and its
    SRK public read (state directory, SRK public file). Every boot runs on a
    copy of the state; a copy's SRK must be the same one."""
    state = os.path.join(root, f"tpm-{name}")
    os.mkdir(state, 0o700)
    srk = os.path.join(root, f"tpm-{name}.srk.pub")
    read_srk(state, srk)
    copy = tempfile.mkdtemp(prefix=f"tpm-{name}-copy-", dir=root)
    again = copy + ".srk.pub"
    try:
        shutil.copy2(os.path.join(state, SWTPM_PERMALL), copy)
        read_srk(copy, again)
        if open(again, "rb").read() != open(srk, "rb").read():
            raise Fail(f"TPM {name}: a copy of the provisioned state has another SRK")
    finally:
        shutil.rmtree(copy)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(again)
    return state, srk


def build(tmp: str):
    """Three deployments, each package sealed to a provisioned TPM: A
    (three peers: the third is the Rosenpass 0.2.3 client's), B (only its
    `key` blob, packaged with A's on A's image and TPM for the mismatch
    case) and C (two peers with their Rosenpass keys swapped, its own image
    and TPM: the peer binding case). A is packaged a second time, sealed to
    a third TPM that never boots (the foreign-TPM case)."""
    for name, peers, extra in (("a", "3", ["--tls-mismatch-blob"]), ("b", "3", []), ("c", "2", [])):
        subprocess.run(["cargo", "run", "--locked", "-q", "-p", "mksecrets", "--", "--template",
                        os.path.join(ROOT, "config/gateway.toml"), "--peers", peers, "--out",
                        os.path.join(tmp, name), *extra], check=True, cwd=ROOT)
    swap_rp_records(os.path.join(tmp, "c/gateway.toml"))
    _, srk_a = provision_tpm(tmp, "a")
    _, srk_c = provision_tpm(tmp, "c")
    _, srk_foreign = provision_tpm(tmp, "foreign")
    env = {**os.environ, "SECUREOS_CONFIG": os.path.join(tmp, "a/gateway.toml")}
    make("image", env=env)
    make("package", f"SECRETS={tmp}/a/secrets.bin", f"PQ_SECRETS={tmp}/a/pqkey-secrets.bin",
         f"TLS_SECRETS={tmp}/a/tls-secrets.bin", f"SRK_PUBLIC={srk_a}",
         f"OUT={tmp}/a/pkg", env=env)
    # Only `key`'s blob mismatches: pqkey and tlskey keep A's, so only `key` is
    # Unavailable.
    make("package", f"SECRETS={tmp}/b/secrets.bin", f"PQ_SECRETS={tmp}/a/pqkey-secrets.bin",
         f"TLS_SECRETS={tmp}/a/tls-secrets.bin", f"SRK_PUBLIC={srk_a}",
         f"OUT={tmp}/b/pkg", env=env)
    make("package", f"SECRETS={tmp}/a/secrets.bin", f"PQ_SECRETS={tmp}/a/pqkey-secrets.bin",
         f"TLS_SECRETS={tmp}/a/tls-secrets.bin",
         f"SRK_PUBLIC={srk_foreign}", f"OUT={tmp}/a/pkg-foreign", env=env)
    # Only the TLS blob's scalar differs (M6 plan case 8, C12): `key` and
    # `pqkey` stay Ready, `tlskey` is Unavailable.
    make("package", f"SECRETS={tmp}/a/secrets.bin", f"PQ_SECRETS={tmp}/a/pqkey-secrets.bin",
         f"TLS_SECRETS={tmp}/a/tls-secrets-mismatch.bin",
         f"SRK_PUBLIC={srk_a}", f"OUT={tmp}/a/pkg-tls-mismatch", env=env)
    env_c = {**os.environ, "SECUREOS_CONFIG": os.path.join(tmp, "c/gateway.toml")}
    make("package", f"SECRETS={tmp}/c/secrets.bin", f"PQ_SECRETS={tmp}/c/pqkey-secrets.bin",
         f"TLS_SECRETS={tmp}/c/tls-secrets.bin", f"SRK_PUBLIC={srk_c}",
         f"OUT={tmp}/c/pkg", env=env_c)
    for pkg in ("a/pkg", "b/pkg", "a/pkg-foreign", "a/pkg-tls-mismatch", "c/pkg"):
        if sorted(os.listdir(os.path.join(tmp, pkg))) != sorted(PACKAGE_OUTPUTS):
            raise Fail(f"{pkg} holds {sorted(os.listdir(os.path.join(tmp, pkg)))}, want {sorted(PACKAGE_OUTPUTS)}")
        check_oracle_not_in_image(os.path.join(tmp, pkg, "published.img"))


# What tools/package writes: no image with a secret in it (M5 plan C8 F2).
PACKAGE_OUTPUTS = ("published.img", "boot.desc", "secrets.env", "pq_secrets.env", "tls_secrets.env", "pcr8")


def packages(tmp: str) -> dict:
    """The packages build() made, with the TPM state each boots on."""
    return {"good": Package(os.path.join(tmp, "a/pkg"), os.path.join(tmp, "tpm-a")),
            "mismatched": Package(os.path.join(tmp, "b/pkg"), os.path.join(tmp, "tpm-a")),
            "binding": Package(os.path.join(tmp, "c/pkg"), os.path.join(tmp, "tpm-c")),
            "foreign": Package(os.path.join(tmp, "a/pkg-foreign"), os.path.join(tmp, "tpm-foreign")),
            "tls_mismatch": Package(os.path.join(tmp, "a/pkg-tls-mismatch"), os.path.join(tmp, "tpm-a"))}


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
        "gateway.https_port": (g["https_port"], HTTPS_PORT),
        "gateway.inside_ip": (g["inside_ip"], ip(INSIDE_IP)),
        "gateway.inside_mac": (g["inside_mac"], mac(INSIDE_MAC)),
        "neighbors[0].ip": (cfg["neighbors"][0]["ip"], ip(HOST_IP)),
        # The https boots' raw backend plays neighbors[0] on the inside tap.
        "gateway.backend": (g["backend"], {"ip": ip(HOST_IP), "port": BACKEND_PORT}),
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


def in_netns(tmp: str) -> int:
    guard_thread_starts()
    pkgs = packages(tmp)
    good, mismatched, binding, foreign = pkgs["good"], pkgs["mismatched"], pkgs["binding"], pkgs["foreign"]
    tls_mismatch = pkgs["tls_mismatch"]
    deploy = os.path.join(tmp, "a")
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
             ("key code tables apart", single("key code tables", check_key_code_tables_apart)),
             ("raw frames", single("raw frames", lambda: test_raw(good))),
             ("wireguard", lambda: test_wireguard(good, deploy, passed)),
             ("cookie boot a", lambda: test_cookie_a(good, deploy, passed)),
             ("cookie boot b", lambda: test_cookie_b(good, deploy, passed)),
             ("rp gate boot", lambda: test_rp_gate(good, deploy, passed)),
             ("peer binding", lambda: test_peer_binding(binding, os.path.join(os.path.dirname(deploy), "c"), passed)),
             ("mismatched blob halts key", single("mismatched blob", lambda: test_mismatched_blob(mismatched))),
             ("measured boot", lambda: test_measured_boot(good.dir, passed)),
             ("sealed boot", lambda: test_sealed(good, foreign, passed)),
             ("tpm proxy", lambda: test_tpm_proxy(good, passed)),
             ("https", lambda: test_https(good, deploy, os.path.join(os.path.dirname(deploy), "b", "devca.pem"),
                                         passed)),
             ("https residue", lambda: test_https_residue(good, deploy, passed)),
             ("https flood", lambda: test_https_flood(good, deploy, passed)),
             ("tls key failure", lambda: test_tls_key_failure(tls_mismatch, deploy, passed))]
    # check-selftest's red-proofs need only the boot their injection breaks:
    # SECUREOS_IT_BOOTS names those (comma-separated). A filtered run never
    # prints INTEGRATION-CASES, so it can never pass `make check`'s manifest.
    only = [b for b in os.environ.get("SECUREOS_IT_BOOTS", "").split(",") if b]
    if only:
        unknown = sorted(set(only) - {name for name, _ in cases})
        if unknown:
            print(f"\nFAIL [setup]: SECUREOS_IT_BOOTS names no boot: {unknown}", file=sys.stderr)
            return 1
        cases = [c for c in cases if c[0] in only]
    for name, fn in cases:
        try:
            fn()
        except (Fail, pexpect.TIMEOUT, pexpect.EOF, subprocess.CalledProcessError, OSError) as e:
            print(f"\nFAIL [{name}]: {type(e).__name__}: {e}", file=sys.stderr)
            return 1
        print(f"\nPASS [{name}]")
    print(f"INTEGRATION-CASES{'-PARTIAL' if only else ''} {len(passed)}")
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
        return in_netns(sys.argv[2])
    tmp = tempfile.mkdtemp(prefix="secureos-it-")
    status = 1
    try:
        preflight()
        build(tmp)
        # `unshare` execs the child, so the Popen pid is the netns harness.
        # The outer harness has no threads, so preexec_fn is safe here.
        child = subprocess.Popen(["unshare", "-rn", sys.executable, os.path.abspath(__file__), "--netns", tmp],
                                 preexec_fn=die_with_parent,
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
