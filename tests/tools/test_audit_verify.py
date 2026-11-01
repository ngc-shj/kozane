"""`tools/audit-verify` over synthetic captures (M8 plan C10): a device
model here prints lines with their ` seq=` trailers, keeps the chain and
signs checkpoints with a test Ed25519 key made for the run (never a
committed key), as `audit` and `auditkey` do. Each deny names its cause
and sits beside the nearest allow, which differs from it in that one
respect.

Usage: python3 tests/tools/test_audit_verify.py   (in the dev container)
Prints "AUDIT-VERIFY-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import hashlib
import os
import pathlib
import struct
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/audit-verify"
H0 = hashlib.sha256(b"kozane-audit-v1\0").digest()
SIG_DOMAIN = b"kozane-audit-checkpoint-v1\0"
SRK = bytes.fromhex("000b") + hashlib.sha256(b"test srk").digest()
OTHER_SRK = bytes.fromhex("000b") + hashlib.sha256(b"another srk").digest()
RESET_AT_PROVISION = 4
# Lines the firmware prints between boots: no trailer, skipped.
FIRMWARE = [b"U-Boot 2025.01 (kozane)", b"kozane: measured", b"MON: booting"]


class Key:
    def __init__(self):
        self.private = Ed25519PrivateKey.generate()
        raw = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.pub = raw.hex() + "\n"


class Device:
    """One boot's `audit` and `auditkey`: lines numbered from `start`, the
    chain from `chain`, checkpoints signed by `key` for this identity."""

    def __init__(self, key: Key, boot_id: bytes, reset: int, restart: int = 0, srk: bytes = SRK,
                 start: int = 0, chain: bytes = H0):
        self.key, self.srk, self.boot_id, self.reset, self.restart = key, srk, boot_id, reset, restart
        self.seq, self.chain, self.lost, self.lines = start, chain, 0, []

    def line(self, text: str) -> bytes:
        raw = f"{text} seq={self.seq}".encode()
        self.chain = hashlib.sha256(self.chain + raw).digest()
        self.seq += 1
        self.lines.append(raw)
        return raw

    def signed_text(self, lost=None, identity=None) -> str:
        srk, boot_id, reset, restart = identity or (self.srk, self.boot_id, self.reset, self.restart)
        lost = self.lost if lost is None else lost
        msg = SIG_DOMAIN + srk + boot_id + struct.pack(">IIQ", reset, restart, self.seq) + self.chain + \
            struct.pack(">Q", lost)
        sig = self.key.private.sign(msg)
        return (f"audit: checkpoint srk={srk.hex()} boot={boot_id.hex()} reset={reset} restart={restart} "
                f"chain={self.chain.hex()} lost={lost} sig={sig.hex()}")

    def checkpoint(self, **kw) -> bytes:
        return self.line(self.signed_text(**kw))

    def unsigned(self, reason: int) -> bytes:
        return self.line(f"audit: checkpoint boot=unavailable chain={self.chain.hex()} lost={self.lost} "
                         f"sig=unavailable reason={reason}")

    def events(self, n: int, src: str = "ingress"):
        for i in range(n):
            self.line(f"audit: src={src} ArpReplied total={i + 1} lost=0")


def ready_boot(key: Key, boot_id: bytes, reset: int, restart: int = 0, tail: int = 3, srk: bytes = SRK) -> Device:
    """A healthy boot: audit's and the PDs' ready lines, policy's version
    lines, the ready checkpoint, then `tail` event lines."""
    d = Device(key, boot_id, reset, restart, srk)
    d.line("audit: ready")
    for pd in ("eth_out", "eth_in", "ingress", "inner", "data", "hs", "pq", "tls"):
        d.line(f"{pd}: ready")
    d.line("policy: accepted version=0 slot=A lost=0")
    d.line("policy: release_seq=1 lost=0")
    d.line("policy: ready")
    d.checkpoint()
    d.events(tail)
    return d


def capture(*boots, raw=None) -> bytes:
    """The UART text: firmware lines before each boot, CR CR LF endings as
    QEMU's pty gives them."""
    out = []
    for b in boots:
        out += FIRMWARE
        out += b if isinstance(b, list) else b.lines
    return b"".join(line + b"\r\r\n" for line in (raw if raw is not None else out))


def record(srk: bytes = SRK, reset: int = RESET_AT_PROVISION) -> str:
    return (f"body_sha256={'ab' * 32}\nfleet_id={'cd' * 16}\nnode=n1\nreset_at_provision={reset}\n"
            f"srk_name={srk.hex()}\nv0=0\n")


class Run:
    def __init__(self, d: pathlib.Path):
        self.dir, self.n = d, 0
        self.key, self.other = Key(), Key()

    def verify(self, data: bytes, pub: str = None, rec: str = None, after: bytes = None, flag: bool = True,
               events: bool = False) -> tuple:
        self.n += 1
        cap, pubf, recf = (self.dir / f"{self.n}.{x}" for x in ("cap", "pub", "rec"))
        cap.write_bytes(data)
        pubf.write_text(pub or self.key.pub)
        args = [sys.executable, str(TOOL), "--pub", str(pubf)]
        if after is not None:
            args += ["--after", after.decode()]
        elif flag:
            recf.write_text(rec or record())
            args += ["--from-provisioning", str(recf)]
        if events:
            args.append("--events")
        args.append(str(cap))
        r = subprocess.run(args, capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr


def boot_id(n: int) -> bytes:
    return hashlib.sha256(f"boot {n}".encode()).digest()[:16]


def cases(run: Run) -> list:
    """(name, (rc, text), want rc, needle that must be in text)."""
    k = run.key
    first = ready_boot(k, boot_id(1), RESET_AT_PROVISION + 1)
    clean = capture(first)
    out = []

    def case(name, result, rc, needle):
        out.append((name, result, rc, needle))

    case("allow: a clean first boot with the matching record", run.verify(clean), 0, "audit-verify: ok")
    case("allow: the baseline line from the record", run.verify(clean), 0,
         f"baseline srk={SRK.hex()} reset={RESET_AT_PROVISION} restart=- seq=-")
    case("allow: the C9 lines are extracted, verified", run.verify(clean), 0,
         "c9 boot=0 seq=9 verified=yes: policy: accepted version=0 slot=A lost=0")
    case("allow: the unverified tail is reported", run.verify(clean), 0, "boot 0: 3 unverified lines after the last checkpoint")
    rejected = Device(k, boot_id(1), RESET_AT_PROVISION + 1)
    rejected.line("audit: ready")
    rejected.line("policy: rejected slot=B reason=RolledBack version=3 lost=0")
    rejected.line("policy: accepted version=0 slot=A lost=0")
    rejected.checkpoint()
    rejected.events(1)
    case("allow: --events prints a policy rejection, verified", run.verify(capture(rejected), events=True), 0,
         "event boot=0 seq=1 verified=yes: policy: rejected slot=B reason=RolledBack version=3 lost=0")
    case("allow: --events marks the lines after the last checkpoint unverified", run.verify(capture(rejected), events=True), 0,
         "event boot=0 seq=4 verified=no: audit: src=ingress ArpReplied total=1 lost=0")

    case("allow: a capture cut mid-line skips its unterminated last line",
         run.verify(clean + b"audit: src=ingress ArpReplied total=4 lost=0 seq=1"), 0,
         "note: the capture's unterminated last line was skipped")

    lines = list(first.lines)
    deleted = lines[:4] + lines[5:]
    case("deny: a deleted line", run.verify(capture(deleted)), 1, "sequence hole: seq=5 where seq=4 was due")
    reordered = lines[:4] + [lines[5], lines[4]] + lines[6:]
    case("deny: two lines reordered", run.verify(capture(reordered)), 1, "sequence hole: seq=5 where seq=4 was due")
    edited = list(lines)
    edited[4] = edited[4].replace(b"inner: ready", b"inner: Ready")
    case("deny: an edited line (trailer intact)", run.verify(capture(edited)), 1,
         "checkpoint seq=12: the chain does not match the lines before it (a line edited)")

    forged = list(lines)
    forged[12] = forged[12].replace(b" lost=0 ", b" lost=7 ")
    case("deny: a forged checkpoint (lost changed)", run.verify(capture(forged)), 1,
         "checkpoint seq=12: the signature does not verify under the device key")
    case("deny: the device key is another device's", run.verify(clean, pub=run.other.pub), 1,
         "checkpoint seq=12: the signature does not verify under the device key")

    # Another boot's checkpoint, validly signed (same seq, chain and lost):
    # only its identity differs from this boot's first one.
    two = ready_boot(k, boot_id(1), RESET_AT_PROVISION + 1, tail=0)
    two.events(5)
    spliced = Device(k, boot_id(1), RESET_AT_PROVISION + 1)
    spliced.seq, spliced.chain = two.seq, two.chain
    two.line(spliced.signed_text(identity=(SRK, boot_id(9), RESET_AT_PROVISION + 1, 0)))
    case("deny: a checkpoint from another boot", run.verify(capture(two)), 1,
         f"checkpoint seq=18 is from another boot (boot={boot_id(9).hex()}")
    same = ready_boot(k, boot_id(1), RESET_AT_PROVISION + 1, tail=0)
    same.events(5)
    same.checkpoint()
    case("allow: a second checkpoint of the same boot", run.verify(capture(same)), 0, "signed checkpoints=2")

    lossy = ready_boot(k, boot_id(1), RESET_AT_PROVISION + 1, tail=0)
    lossy.lost = 3
    lossy.events(2)
    lossy.checkpoint()
    case("report: lost > 0", run.verify(capture(lossy)), 0, "boot 0: lost=3: the device dropped events")
    unsigned = ready_boot(k, boot_id(1), RESET_AT_PROVISION + 1, tail=0)
    unsigned.unsigned(2)
    unsigned.events(2)
    unsigned.checkpoint()
    case("report: an unsigned checkpoint", run.verify(capture(unsigned)), 0,
         "boot 0: unsigned checkpoint at seq=13 reason=2")
    none = Device(k, boot_id(1), RESET_AT_PROVISION + 1)
    none.line("audit: ready")
    none.unsigned(142)
    none.events(2)
    case("deny: a boot with no signed checkpoint", run.verify(capture(none)), 1, "boot 0: no signed checkpoint")
    dup = list(lines) + [lines[12]]
    case("deny: a checkpoint seq that does not increase", run.verify(capture(dup)), 1,
         "checkpoint seq=12 does not follow checkpoint seq=12")
    case("deny: no audit lines", run.verify(b"U-Boot 2025.01\r\r\nkozane: measured\r\r\n"), 1,
         "no audit lines (no ` seq=` trailer)")
    case("deny: trailers dropped", run.verify(b"".join(raw.rsplit(b" seq=", 1)[0] + b"\r\r\n" for raw in lines)), 1,
         "no audit lines")

    # Boots in one capture: a TPM Reset or Restart successor, or a gap.
    reset = ready_boot(k, boot_id(2), RESET_AT_PROVISION + 2)
    restart = ready_boot(k, boot_id(2), RESET_AT_PROVISION + 1, restart=1)
    jump = ready_boot(k, boot_id(2), RESET_AT_PROVISION + 3)
    case("allow: a second boot after a TPM Reset", run.verify(capture(first, reset)), 0, "audit-verify: ok")
    case("allow: a second boot after a TPM Restart", run.verify(capture(first, restart)), 0, "audit-verify: ok")
    case("deny: a missing boot (reset jump)", run.verify(capture(first, jump)), 1,
         "boot 1: gap after boot 0: reset=7 restart=0 after reset=5 restart=0")
    again = ready_boot(k, boot_id(1), RESET_AT_PROVISION + 2)
    case("deny: a boot ID that starts again", run.verify(capture(first, again)), 1,
         f"the same boot ID {boot_id(1).hex()} starts again")

    # --from-provisioning.
    case("deny: the record's capture without the flag", run.verify(clean, flag=False), 2,
         "one of the arguments --after --from-provisioning is required")
    case("deny: a record for another TPM", run.verify(clean, rec=record(srk=OTHER_SRK)), 1,
         f"srk_name {SRK.hex()} does not match the provisioning record's {OTHER_SRK.hex()}")
    later = ready_boot(k, boot_id(1), RESET_AT_PROVISION + 2)
    case("deny: the flag on a later cold boot", run.verify(capture(later)), 1,
         "has reset=6, want reset_at_provision + 1 = 5")
    post_restart = ready_boot(k, boot_id(1), RESET_AT_PROVISION + 1, restart=1)
    case("deny: the flag on a post-Restart boot", run.verify(capture(post_restart)), 1,
         "has restart=1, want 0")
    case("deny: the flag on a mid-boot start", run.verify(capture(lines[5:])), 1,
         "the capture starts inside a boot (first seq=5)")
    late = Device(k, boot_id(1), RESET_AT_PROVISION + 1)
    late.line("audit: ready")
    late.unsigned(1)
    late.events(2)
    late.checkpoint()
    case("deny: the flag where the first checkpoint is not the ready one", run.verify(capture(late)), 1,
         "the first boot's first checkpoint (seq=1) is not signed")

    # --after: the anchor is the last signed checkpoint of the previous
    # capture, verified, and the capture is exactly one successor of it.
    anchor = first.lines[12]
    case("allow: the baseline line from the anchor", run.verify(capture(reset), after=anchor), 0,
         f"baseline srk={SRK.hex()} reset={RESET_AT_PROVISION + 1} restart=0 seq=12")
    forged_anchor = anchor.replace(b" lost=0 ", b" lost=1 ")
    case("deny: a forged --after", run.verify(capture(reset), after=forged_anchor), 1,
         "the --after anchor's signature does not verify under the device key")
    case("deny: a --after under another key", run.verify(capture(reset), after=anchor, pub=run.other.pub), 1,
         "the --after anchor's signature does not verify under the device key")
    case("allow: --after, a TPM Reset successor", run.verify(capture(reset), after=anchor), 0, "audit-verify: ok")
    case("allow: --after, a TPM Restart successor", run.verify(capture(restart), after=anchor), 0, "audit-verify: ok")
    case("report: --after, a new boot leaves the anchor's tail unverifiable", run.verify(capture(reset), after=anchor), 0,
         "note: the anchor's boot may have continued past seq=12; its lines after the anchor are not verifiable")
    case("deny: --after, a reset jump", run.verify(capture(jump), after=anchor), 1,
         "gap after the anchor: reset=7 restart=0 after reset=5 restart=0")
    # A capture split inside one boot: the rest of `first`'s boot.
    anchor_chain = bytes.fromhex(anchor.split(b"chain=")[1][:64].decode())
    rest = Device(k, boot_id(1), RESET_AT_PROVISION + 1, start=13,
                  chain=hashlib.sha256(anchor_chain + anchor).digest())
    rest.events(4)
    rest.checkpoint()
    case("allow: --after, the same boot resumed", run.verify(capture(rest.lines), after=anchor), 0,
         "audit-verify: ok")
    case("deny: --after, a line deleted just after the anchor", run.verify(capture(rest.lines[1:]), after=anchor), 1,
         "the capture does not resume at the anchor: first seq=14, want seq=13")
    rc_resumed, out_resumed = run.verify(capture(rest.lines), after=anchor)
    case("allow: --after, the same boot resumed has no unverifiable-tail note",
         (rc_resumed, "no note" if "may have continued past" not in out_resumed else out_resumed), 0, "no note")
    case("allow: the next capture's anchor is printed", run.verify(capture(rest.lines), after=anchor), 0,
         f"anchor: {rest.lines[-1].decode()}")
    return out


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="audit-verify-") as d:
        results = cases(Run(pathlib.Path(d)))
    failures = 0
    for name, (rc, text), want_rc, needle in results:
        ok = rc == want_rc and needle in text
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f"\n  rc={rc}, want {want_rc}; needle "
                                                                   f"{needle!r}\n{text}"))
    print(f"AUDIT-VERIFY-FIXTURES {len(results)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
