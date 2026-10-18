"""Boot the image in QEMU and exercise it end to end.

Usage: run.py <loader.img>

Boot 1 attaches the NIC to a `-netdev dgram` UDP socket, so this script can
inject raw Ethernet frames (ARP, malformed frames, floods) and read replies.
Boot 2 attaches it to user-net with a hostfwd and runs a `nc -u`-style smoke
test through slirp. No sleeps: every wait is on a readiness line or a reply,
with bounded timeouts. Exits non-zero on any failure.
"""

import os
import re
import secrets
import signal
import socket
import struct
import sys

import pexpect

BOOT_TIMEOUT_S = 60
REPLY_TIMEOUT_S = 5
LINE_TIMEOUT_S = 10

GW_MAC = bytes.fromhex("525400123456")
GW_IP = bytes([10, 0, 2, 15])
PEER_MAC = bytes.fromhex("52550a000202")
PEER_IP = bytes([10, 0, 2, 2])
ECHO_PORT = 7
BCAST = b"\xff" * 6

READY = ["eth_out: ready", "ingress: ready", "audit: ready"]


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
    return bytearray(ipv4_udp(PEER_IP, GW_IP, 40000, ECHO_PORT, payload))


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


def check_reason_list_matches_rust():
    src = open(os.path.join(os.path.dirname(__file__), "../../crates/wire/src/lib.rs")).read()
    block = src[src.index("drop_reasons! {"):]
    block = block[: block.index("}")]
    rust = re.findall(r"^\s+(\w+) = \d+,", block, re.M)
    if rust != DROP_REASONS:
        raise Fail(f"DROP_REASONS out of sync with wire: {rust}")


# ---------------------------------------------------------------- harness


def free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def spawn(loader: str, netdev: str) -> pexpect.spawn:
    cmd = [
        "-machine", "virt,virtualization=on", "-cpu", "cortex-a53", "-m", "size=2G",
        "-serial", "mon:stdio", "-nographic",
        "-device", f"loader,file={loader},addr=0x70000000,cpu-num=0",
        "-device", f"virtio-net-device,netdev=n0,mac={GW_MAC.hex(':')}",
        "-netdev", netdev,
    ]
    # pexpect makes the child a session (and process group) leader, so
    # kill() can take down the whole group.
    child = pexpect.spawn("qemu-system-aarch64", cmd, encoding="utf-8", timeout=BOOT_TIMEOUT_S)
    child.logfile_read = sys.stdout
    return child


def kill(child: pexpect.spawn):
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.close(force=True)


def wait_ready(child):
    """PDs start in scheduler order, so accept the ready lines in any order."""
    pending = list(READY)
    while pending:
        i = child.expect_exact(pending)
        pending.pop(i)


def expect_line(child, pattern: str, timeout=LINE_TIMEOUT_S) -> re.Match:
    child.expect(pattern, timeout=timeout)
    return child.match


class Wire:
    """Host end of the dgram netdev."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.qemu_port = free_udp_port()
        self.sock.settimeout(REPLY_TIMEOUT_S)

    def netdev(self) -> str:
        return (f"dgram,id=n0,local.type=inet,local.host=127.0.0.1,local.port={self.qemu_port},"
                f"remote.type=inet,remote.host=127.0.0.1,remote.port={self.port}")

    def send(self, frame: bytes):
        self.sock.sendto(frame, ("127.0.0.1", self.qemu_port))

    def recv_matching(self, pred, child) -> bytes:
        """Returns the first received frame satisfying pred, or raises."""
        deadline_reads = 50
        while deadline_reads:
            deadline_reads -= 1
            try:
                child.expect(pexpect.TIMEOUT, timeout=0)  # keep serial drained
            except pexpect.EOF:
                raise Fail("QEMU exited")
            try:
                data, _ = self.sock.recvfrom(2048)
            except socket.timeout:
                raise Fail("no reply")
            if pred(data):
                return data
        raise Fail("no matching reply")


# ---------------------------------------------------------------- boot 1


def test_raw(loader: str):
    w = Wire()
    child = spawn(loader, w.netdev())
    try:
        wait_ready(child)

        # ARP request for our IP -> exact reply.
        w.send(arp(1, PEER_MAC, PEER_IP, b"\0" * 6, GW_IP))
        r = w.recv_matching(lambda d: d[12:14] == b"\x08\x06", child)
        exp = arp(2, GW_MAC, GW_IP, PEER_MAC, PEER_IP, dst=PEER_MAC)
        if r[:42] != exp:
            raise Fail(f"bad ARP reply {r.hex()}")
        expect_line(child, r"audit: src=ingress ArpReplied total=1 lost=0")

        # UDP echo with a nonce -> exact payload, swapped ports.
        echo(w, child)
        expect_line(child, r"audit: src=ingress UdpEchoed total=1 lost=0")

        # One frame per DropReason -> exact audit line each.
        for reason in DROP_REASONS:
            w.send(frame_for(reason))
            expect_line(child, rf"audit: src=ingress FrameDropped\({reason}\) total=1 lost=0")

        flood(w, child, "Ipv4BadChecksum", k=640)
        echo(w, child)  # liveness after the flood
    finally:
        kill(child)


def echo(w: Wire, child):
    nonce = secrets.token_bytes(16)
    w.send(ipv4_udp(PEER_IP, GW_IP, 40000, ECHO_PORT, nonce))
    r = w.recv_matching(lambda d: d[12:14] == b"\x08\x00" and d[23] == 17, child)
    sport, dport = struct.unpack("!HH", r[34:38])
    if r[42:42 + len(nonce)] != nonce or (sport, dport) != (ECHO_PORT, 40000) or r[:6] != PEER_MAC:
        raise Fail(f"bad echo {r.hex()}")


def flood(w: Wire, child, reason: str, k: int):
    """After k more frames of one reason (total k+1 incl. the earlier one):
    >= 1 and <= k/64 + 2 lines, last total == 1 mod 64, total + lost <= k + 1."""
    frame = frame_for(reason)
    for _ in range(k):
        w.send(frame)
    totals, lost = [], 0
    pat = re.compile(rf"audit: src=ingress FrameDropped\({reason}\) total=(\d+) lost=(\d+)")
    while True:
        i = child.expect([pat.pattern, pexpect.TIMEOUT], timeout=3)
        if i == 1:
            break
        totals.append(int(child.match.group(1)))
        lost = int(child.match.group(2))
    if not totals:
        raise Fail("flood produced no audit line")
    if len(totals) > k // 64 + 2:
        raise Fail(f"flood produced {len(totals)} lines")
    if totals[-1] % 64 != 1 or totals[-1] + lost > k + 1:
        raise Fail(f"flood totals inconsistent: {totals} lost={lost}")


# ---------------------------------------------------------------- boot 2


def test_hostfwd(loader: str):
    port = free_udp_port()
    child = spawn(loader, f"user,id=n0,net=10.0.2.0/24,hostfwd=udp:127.0.0.1:{port}-:{ECHO_PORT}")
    try:
        wait_ready(child)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        nonce = secrets.token_bytes(8)
        for _ in range(REPLY_TIMEOUT_S * 2):
            s.sendto(nonce, ("127.0.0.1", port))
            try:
                child.expect(pexpect.TIMEOUT, timeout=0)
                data, _ = s.recvfrom(64)
            except socket.timeout:
                continue
            if data == nonce:
                return
            raise Fail(f"hostfwd echo mismatch {data!r}")
        raise Fail("hostfwd echo: no reply")
    finally:
        kill(child)


def main() -> int:
    loader = sys.argv[1]
    cases = [("reason list in sync", lambda: check_reason_list_matches_rust()),
             ("raw frames", lambda: test_raw(loader)),
             ("hostfwd smoke", lambda: test_hostfwd(loader))]
    for name, fn in cases:
        try:
            fn()
        except (Fail, pexpect.TIMEOUT, pexpect.EOF) as e:
            print(f"\nFAIL [{name}]: {type(e).__name__}: {e}", file=sys.stderr)
            return 1
        print(f"\nPASS [{name}]")
    print(f"INTEGRATION-CASES {len(cases)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
