"""tools/timer-scan (M9 plan D13, C14 I14.2): on synthetic PD ELFs, the
counter reads pass, every other timer-class register access outside the
timer fails by name, and a timer without one fails the positive control.

Usage: python3 tests/tools/test_timer_scan.py
Prints "TIMER-SCAN-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import pathlib
import struct
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/timer-scan"
PF_X, PF_W, PF_R = 1, 2, 4
NOP = 0xD503201F


def sysreg(l: int, op1: int, crn: int, crm: int, op2: int, rt: int = 0) -> int:
    """MRS (l=1) or MSR (l=0), register form, op0=3."""
    return 0xD5100000 | l << 21 | 1 << 19 | op1 << 16 | crn << 12 | crm << 8 | op2 << 5 | rt


MRS_CNTPCT = sysreg(1, 3, 14, 0, 1)
MRS_CNTFRQ = sysreg(1, 3, 14, 0, 0)
MSR_CNTP_CVAL = sysreg(0, 3, 14, 2, 2)
MSR_CNTP_CTL = sysreg(0, 3, 14, 2, 1)
MRS_CNTVCT = sysreg(1, 3, 14, 0, 2)
MRS_CNTVCTSS = sysreg(1, 3, 14, 0, 6)
MRS_CNTKCTL_EL1 = sysreg(1, 0, 14, 1, 0)
MSR_CNTKCTL_EL1 = sysreg(0, 0, 14, 1, 0)
# An EL2 timer control (op1 4): CNTHP_CTL_EL2.
MSR_CNTHP_CTL_EL2 = sysreg(0, 4, 14, 2, 1)


def elf(segments: list) -> bytes:
    """An ELF64 AArch64 executable of PT_LOAD (flags, vaddr, words)."""
    phoff, phentsize = 64, 56
    offset = phoff + phentsize * len(segments)
    headers, body = b"", b""
    for flags, vaddr, words in segments:
        data = b"".join(struct.pack("<I", w) for w in words)
        headers += struct.pack("<IIQQQQQQ", 1, flags, offset + len(body), vaddr, vaddr, len(data), len(data), 0x1000)
        body += data
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    ehdr = ident + struct.pack("<HHIQQQIHHHHHH", 2, 183, 1, segments[0][1], phoff, 0, 0, 64, phentsize,
                               len(segments), 64, 0, 0)
    return ehdr + headers + body


def code(*words) -> list:
    return [(PF_R | PF_X, 0x200000, [NOP, *words, NOP])]


TIMER = code(MRS_CNTFRQ, MSR_CNTP_CVAL, MSR_CNTP_CTL)


def run(pds: dict) -> tuple:
    """(exit status, stdout, the result file or None) for one system of
    `pds` (ELF name -> segments)."""
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        images = "".join(f'<protection_domain name="p{i}"><program_image path="{n}" /></protection_domain>'
                         for i, n in enumerate(pds))
        (d / "s.system").write_text(f"<system>{images}</system>")
        for name, segments in pds.items():
            (d / name).write_bytes(elf(segments))
        out = d / "timer-scan.txt"
        out.write_text("stale\n")
        r = subprocess.run([sys.executable, str(TOOL), "--system", str(d / "s.system"), "--search-path", str(d),
                            "--out", str(out)], capture_output=True, text=True)
        return r.returncode, r.stdout, out.read_text() if out.exists() else None


DENY_OUTSIDE = "timer-scan: rejected instruction outside timer: pd=pd-ingress.elf"
CONTROL = "timer-scan: no timer access in timer"

# (name, PD ELFs, expected exit, a needle in stdout)
CASES = [
    ("allow: cntpct and cntfrq reads outside the timer",
     {"pd-timer.elf": TIMER, "pd-ingress.elf": code(MRS_CNTPCT, MRS_CNTFRQ)}, 0, "TIMER-SCAN-PDS 1"),
    ("allow: the class's words in a non-executable segment",
     {"pd-timer.elf": TIMER, "pd-ingress.elf": code() + [(PF_R | PF_W, 0x300000, [MSR_CNTP_CVAL])]}, 0,
     "TIMER-SCAN-PDS 1"),
    ("allow: a class encoding at an unaligned address is no instruction",
     {"pd-timer.elf": TIMER, "pd-ingress.elf": [(PF_R | PF_X, 0x200002, [NOP, MSR_CNTP_CVAL, NOP])]}, 0,
     "TIMER-SCAN-PDS 1"),
    ("deny: msr cntp_cval_el0 outside the timer",
     {"pd-timer.elf": TIMER, "pd-ingress.elf": code(MRS_CNTPCT, MSR_CNTP_CVAL)}, 1,
     f"{DENY_OUTSIDE} offset=0x{64 + 56 + 8:x} encoding=0xd51be240 (msr s3_3_c14_c2_2, x0)"),
    ("deny: mrs cntvctss_el0 outside the timer",
     {"pd-timer.elf": TIMER, "pd-ingress.elf": code(MRS_CNTVCTSS)}, 1, f"{DENY_OUTSIDE} offset="),
    ("deny: mrs cntvct_el0 outside the timer",
     {"pd-timer.elf": TIMER, "pd-ingress.elf": code(MRS_CNTVCT)}, 1, f"{DENY_OUTSIDE} offset="),
    ("deny: a cntkctl_el1 read outside the timer",
     {"pd-timer.elf": TIMER, "pd-ingress.elf": code(MRS_CNTKCTL_EL1)}, 1, "(mrs x0, s3_0_c14_c1_0)"),
    ("deny: a cntkctl_el1 write outside the timer",
     {"pd-timer.elf": TIMER, "pd-ingress.elf": code(MSR_CNTKCTL_EL1)}, 1, "(msr s3_0_c14_c1_0, x0)"),
    ("deny: a cnthp_ctl_el2 write (an EL2 timer control) outside the timer",
     {"pd-timer.elf": TIMER, "pd-ingress.elf": code(MSR_CNTHP_CTL_EL2)}, 1,
     f"{DENY_OUTSIDE} offset=0x{64 + 56 + 4:x} encoding=0xd51ce220 (msr s3_4_c14_c2_1, x0)"),
    ("deny: the class in a second executable segment",
     {"pd-timer.elf": TIMER, "pd-ingress.elf": code() + [(PF_R | PF_X, 0x300000, [MSR_CNTP_CTL])]}, 1,
     f"{DENY_OUTSIDE} offset="),
    ("control: a timer with only counter reads",
     {"pd-timer.elf": code(MRS_CNTPCT, MRS_CNTFRQ), "pd-ingress.elf": code(MRS_CNTPCT)}, 1, CONTROL),
    ("control: no timer PD in the system", {"pd-ingress.elf": code(MRS_CNTPCT)}, 1, CONTROL),
    ("deny: a PD ELF without an executable segment",
     {"pd-timer.elf": TIMER, "pd-ingress.elf": [(PF_R, 0x200000, [NOP])]}, 1, "no executable segment"),
]


def main() -> int:
    failures = 0
    for name, pds, want, needle in CASES:
        status, stdout, result = run(pds)
        # A failed scan leaves no result; a clean one writes the count it prints.
        ok = status == want and needle in stdout and (result is None if want else needle in result)
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f": exit {status}, stdout {stdout!r}"))
    print(f"TIMER-SCAN-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
