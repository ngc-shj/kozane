"""tools/provision (M7 plan C5, M8 plan C3) against real swtpms and a CA made
for the run.

Allow: a TPM whose EK certificate chains to the CA gets its SRK record,
byte-equal to the SRK public the TPM reports. Deny, each exiting non-zero
with no record and a needle naming the cause: an EK certificate from
another CA, one that does not certify this TPM's EK, no EK certificate,
an SRK public from another TPM (activation fails in the TPM), an SRK
public with fixedTPM clear. The last three read a substituted file through
a PATH shim for one tpm2-tools command; the comparison, the template check
and the activation stay the real ones.

M8 plan C3: every provisioning clears the TPM (the SRK changes); the `nv`
step defines the two indices only from a ledger `tools/policy verify
--ledger` accepts (a build pinned to this run's roster, as
tests/tools/test_policy.py builds it) and a provisioning record two pinned
record keys signed for this TPM's SRK and resetCount. Its denies (each
naming its cause, writing no slot and defining nothing) pair with the
allow, which also checks the logical version, the Names against
tools/measure.py's twin and reset_at_provision. Existing indices are refused without the two delete
authorizations and replaced with them.

Everything lives in one per-run directory, removed in `finally`; a
directory that survives fails the run.

Usage: python3 tests/tools/test_provision.py
Prints "PROVISION-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/provision"
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests/tools"))
import measure  # noqa: E402  (after the sys.path insert above, by design)
import test_policy  # noqa: E402  (its pinned tools/policy build and ledger fixture)

# Runs tools/provision with its pinned record keys pointed at a run's file:
# the tool has no flag for that (M8 plan C3), so the test sets the module
# global, as tests/tools/test_package.py loads tools/package.
LAUNCH = ("import pathlib, sys; src = sys.argv[1]; g = {'__file__': src, '__name__': 'provision'}; "
          "exec(compile(open(src).read(), src, 'exec'), g); g['RECORD_KEYS'] = pathlib.Path(sys.argv[2]); "
          "sys.argv = [src] + sys.argv[3:]; sys.exit(g['main']())")
RECORD_DOMAIN = b"kozane-reprovision-v1\0"
FIXTURES = 28


def make_ca(run_dir: pathlib.Path, name: str) -> pathlib.Path:
    """A swtpm-localca configuration whose CA is created in `run_dir`."""
    ca = run_dir / f"ca-{name}"
    ca.mkdir()
    (run_dir / f"localca-{name}.conf").write_text(
        f"statedir = {ca}\nsigningkey = {ca}/signkey.pem\nissuercert = {ca}/issuercert.pem\n"
        f"certserial = {ca}/certserial\n")
    (run_dir / f"setup-{name}.conf").write_text(
        "create_certs_tool= /usr/bin/swtpm_localca\n"
        f"create_certs_tool_config = {run_dir}/localca-{name}.conf\n"
        "create_certs_tool_options = /etc/swtpm-localca.options\nactive_pcr_banks = sha256\n")
    return ca


def make_tpm(run_dir: pathlib.Path, name: str, ca: str = None) -> pathlib.Path:
    """A swtpm state, with an EK certificate from CA `ca` unless None."""
    state = run_dir / f"tpm-{name}"
    state.mkdir()
    args = ["swtpm_setup", "--tpm2", "--tpmstate", str(state), "--overwrite"]
    if ca is not None:
        args += ["--create-ek-cert", "--config", str(run_dir / f"setup-{ca}.conf")]
    else:
        args += ["--config", str(run_dir / "setup-a.conf")]
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"swtpm_setup {name}: {r.stdout}{r.stderr}")
    return state


class Swtpm:
    def __init__(self, state: pathlib.Path):
        self.sock = state.parent / f"{state.name}.sock"
        self.proc = subprocess.Popen(["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state}", "--server",
                                      f"type=unixio,path={self.sock}", "--ctrl",
                                      f"type=unixio,path={self.sock}.ctrl", "--flags",
                                      "not-need-init,startup-clear"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 10
        while not self.sock.exists():
            if self.proc.poll() is not None or time.monotonic() > deadline:
                raise SystemExit("swtpm did not listen")
            time.sleep(0.05)
        self.tcti = f"swtpm:path={self.sock}"

    def close(self):
        self.proc.kill()
        self.proc.wait()


def tool_out(tcti: str, *args) -> bytes:
    r = subprocess.run(list(args), env={**os.environ, "TPM2TOOLS_TCTI": tcti}, capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"{args[0]}: {r.stderr.decode(errors='replace')}")
    return r.stdout


def shim(run_dir: pathlib.Path, command: str, substitute: pathlib.Path) -> dict:
    """PATH with `command` replaced by a script that runs the real one, then
    puts `substitute` where its output file (the argument after -o) went."""
    bin_dir = run_dir / f"shim-{command}"
    bin_dir.mkdir(exist_ok=True)
    real = shutil.which(command)
    script = bin_dir / command
    script.write_text(f"""#!/bin/sh
set -e
{real} "$@"
out=""
prev=""
for a in "$@"; do
    if [ "$prev" = "-o" ]; then out="$a"; fi
    prev="$a"
done
cp {substitute} "$out"
""")
    script.chmod(0o755)
    return {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}


def tool(record_keys: pathlib.Path, *args) -> tuple:
    r = subprocess.run([sys.executable, "-c", LAUNCH, str(TOOL), str(record_keys), *map(str, args)],
                       capture_output=True, text=True, cwd=ROOT)
    return r.returncode, r.stdout + r.stderr


def openssl(*args) -> bytes:
    r = subprocess.run(["openssl", *map(str, args)], capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"openssl {args[0]}: {r.stderr.decode(errors='replace')}")
    return r.stdout


def name_of(tcti: str, run_dir: pathlib.Path) -> str:
    """The SRK Name the storage template gives in this TPM now."""
    ctx, name = run_dir / "name.ctx", run_dir / "name.bin"
    tool_out(tcti, "tpm2_createprimary", "-Q", "-C", "o", "-G", "ecc256:aes128cfb", "-g", "sha256", "-a",
             "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt", "-c", str(ctx))
    tool_out(tcti, "tpm2_readpublic", "-Q", "-c", str(ctx), "-n", str(name))
    tool_out(tcti, "tpm2_flushcontext", "-t")
    return name.read_bytes().hex()


def record(**fields) -> bytes:
    return "".join(f"{k}={fields[k]}\n" for k in ("body_sha256", "fleet_id", "node", "reset_at_provision", "srk_name",
                                                  "v0")).encode()


def raw_sig(run_dir: pathlib.Path, name: str, body: bytes, key: pathlib.Path, domain: bytes = RECORD_DOMAIN,
            ecdsa: bool = False) -> pathlib.Path:
    """A `sig=` line made outside the tool: another domain, or an ECDSA key."""
    msg = run_dir / f"{name}.msg"
    msg.write_bytes(domain + body)
    spki = openssl("pkey", "-in", key, "-pubout", "-outform", "DER")
    sig = openssl("dgst", "-sha256", "-sign", key, msg) if ecdsa else \
        openssl("pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", msg)
    out = run_dir / f"{name}.sig"
    out.write_text(f"sig={spki.hex()}:{sig.hex()}\n")
    return out


class Ledger:
    """test_policy's fixture: a pinned tools/policy, a ledger whose head is
    version 1 (v0 for this node), its keys and the head's bytes."""

    def __init__(self, d: pathlib.Path):
        base = test_policy.build_binary()
        session = d / "approvers"
        session.mkdir(parents=True)
        for a in ("alice", "bob", "carol", "dave"):
            rc, out = test_policy.run(base, "approver-keygen", "--dir", session / a, "--forbid", ROOT)
            assert rc == 0, out
        roster = session / "roster.toml"
        roster.write_text(test_policy.roster_toml({a: test_policy.pubkey(session, a)
                                                   for a in ("alice", "bob", "carol")}))
        test_policy.APPROVERS = session
        test_policy.BIN = test_policy.build_binary(test_policy._digest(base, roster))
        self.bin = test_policy.BIN
        (d / "fixture").mkdir()
        self.ctx = test_policy.Ctx(d / "fixture")
        rc, out = self.ctx.sign(self.ctx.draft1, [self.ctx.a1, self.ctx.b1], d / "slot1.bin")
        assert rc == 0, out
        self.dir, self.keys, self.fleet_id = self.ctx.ledger, self.ctx.keys, test_policy.FLEET_ID
        self.head = (self.dir / "entries/0000000001.bin").read_bytes()
        self.body = {v: self.approval_field(v, "body_sha256") for v in (0, 1)}

    def approval_field(self, version: int, key: str) -> str:
        path = sorted((self.dir / "approvals" / f"{version:010}").glob("*"))[0]
        return dict(line.split("=", 1) for line in path.read_text().splitlines())[key]


def provision(tcti: str, ca: pathlib.Path, out: pathlib.Path, env=None):
    r = subprocess.run([sys.executable, str(TOOL), "--tcti", tcti, "--ek-root", str(ca / "swtpm-localca-rootca-cert.pem"),
                        "--ek-intermediates", str(ca / "issuercert.pem"), "--out", str(out)],
                       env=env, capture_output=True, text=True, cwd=ROOT)
    return r.returncode, r.stdout + r.stderr


def nv_fixtures(run_dir: pathlib.Path, ca: pathlib.Path, other: Swtpm, tpms: list, results: list):
    tpm = Swtpm(make_tpm(run_dir, "n", "a"))
    tpms.append(tpm)
    env = {**os.environ, "TPM2TOOLS_TCTI": tpm.tcti}

    # D5, S18: provisioning clears the TPM first, so the same TPM provisioned
    # again holds another SRK, and the SRK it wrote is the one it now holds.
    first, second = run_dir / "srk-n1.pub", run_dir / "srk-n2.pub"
    rc1, text1 = provision(tpm.tcti, ca, first)
    rc2, text2 = provision(tpm.tcti, ca, second)
    results.append(("allow: each provisioning clears the TPM, so the SRK changes",
                    rc1 == 0 and rc2 == 0 and first.read_bytes() != second.read_bytes(), text1 + text2))

    ledger = Ledger(run_dir / "ledger-fixture")
    keys = {}
    for k in ("r1", "r2", "r3"):
        keys[k] = run_dir / f"{k}.pem"
        openssl("genpkey", "-algorithm", "ed25519", "-out", keys[k])
    for k in ("op1", "op2"):
        keys[k] = run_dir / f"{k}.pem"
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", keys[k])
        keys[f"{k}.pub"] = run_dir / f"{k}.pub.pem"
        openssl("ec", "-in", keys[k], "-pubout", "-out", keys[f"{k}.pub"])
    pinned = run_dir / "record-keys"
    pinned.write_text("# the run's fleet\n" + "".join(
        f"{ledger.fleet_id} {openssl('pkey', '-in', keys[k], '-pubout', '-outform', 'DER')[-32:].hex()}\n"
        for k in ("r1", "r2")))

    def make_record(name: str) -> pathlib.Path:
        out = run_dir / f"{name}.record"
        rc, text = tool(pinned, "record", "--tcti", tpm.tcti, "--ledger", ledger.dir, "--keys-pub", ledger.keys,
                        "--node", "n1", "--out", out, "--policy-bin", ledger.bin)
        if rc != 0:
            raise SystemExit(f"provision record: {text}")
        return out

    def sign(rec: pathlib.Path, key: str, name: str) -> pathlib.Path:
        out = run_dir / f"{name}.sig"
        rc, text = tool(pinned, "record-sign", "--record", rec, "--key", keys[key], "--out", out)
        if rc != 0:
            raise SystemExit(f"provision record-sign: {text}")
        return out

    def nv(rec, sigs, slot, ledger_dir=None, delete_keys=()):
        extra = ["--delete-keys", *delete_keys] if delete_keys else []
        return tool(pinned, "nv", "--tcti", tpm.tcti, "--ledger", ledger_dir or ledger.dir, "--keys-pub",
                    ledger.keys, "--node", "n1", "--record", rec, "--record-sigs", *sigs, "--delete-pub",
                    keys["op1.pub"], keys["op2.pub"], "--slot-a", slot, "--policy-bin", ledger.bin, *extra)

    def nv_defined() -> set:
        out = tool_out(tpm.tcti, "tpm2_getcap", "handles-nv-index").decode()
        return {int(h, 16) for h in re.findall(r"^- (0x[0-9a-f]+)$", out, re.M)} \
            & {measure.NV_POLICY_CTR, measure.NV_POLICY_BASE}

    def nv_deny(name, rec, sigs, needle, ledger_dir=None):
        slot = run_dir / f"slot-{len(results)}.bin"
        rc, text = nv(rec, sigs, slot, ledger_dir)
        results.append((name, rc != 0 and needle in text and not slot.exists() and not nv_defined(), text))

    # A record signed before the second Clear: replayed after it.
    replayed = make_record("replayed")
    replayed_sigs = [sign(replayed, "r1", "replayed-r1"), sign(replayed, "r2", "replayed-r2")]
    rc, text = provision(tpm.tcti, ca, run_dir / "srk-n3.pub")
    assert rc == 0, text

    good = make_record("good")
    body = good.read_bytes()
    fields = dict(line.split("=", 1) for line in body.decode().splitlines())
    s1, s2 = sign(good, "r1", "good-r1"), sign(good, "r2", "good-r2")

    def signed(name: str, **change) -> tuple:
        path = run_dir / f"{name}.record"
        path.write_bytes(record(**{**fields, **change}))
        return path, [sign(path, "r1", f"{name}-r1"), sign(path, "r2", f"{name}-r2")]

    tampered = run_dir / "ledger-tampered"
    shutil.copytree(ledger.dir, tampered)
    entry = tampered / "entries/0000000001.bin"
    data = bytearray(entry.read_bytes())
    data[100] ^= 1
    entry.write_bytes(bytes(data))
    nv_deny("deny: v0 from a ledger tools/policy does not verify", good, [s1, s2],
            "failed: policy: ledger: version 1:", tampered)
    nv_deny("deny: a record with one signature", good, [s1], "needs two signatures, has 1")
    nv_deny("deny: a record signed twice by the same key", good, [s1, s1], "signed twice by the same key")
    nv_deny("deny: a record signed by a delete key", good,
            [s1, raw_sig(run_dir, "by-delete", body, keys["op1"], ecdsa=True)], "signed by a delete key")
    nv_deny("deny: a record signed by an unpinned key", good, [s1, sign(good, "r3", "good-r3")],
            "not a pinned record key")
    nv_deny("deny: a record bound to another TPM's SRK", *signed("other-srk", srk_name=name_of(other.tcti, run_dir)),
            "the record's srk_name")
    nv_deny("deny: a record replayed from an earlier provisioning", replayed, replayed_sigs, "the record's srk_name")
    nv_deny("deny: a record for another fleet", *signed("other-fleet", fleet_id="cd" * 16), "the record's fleet_id")
    nv_deny("deny: a record signed under another domain", good,
            [s1, raw_sig(run_dir, "other-domain", body, keys["r2"], domain=b"kozane-policy-approval-v1\0")],
            "does not verify")
    nv_deny("deny: a record whose v0 is not the ledger head", *signed("old-v0", v0="0", body_sha256=ledger.body[0]),
            "the record's v0 0 is not the ledger head")
    nv_deny("deny: a record whose body is not the ledger head's", *signed("other-body", body_sha256="00" * 32),
            "the record's body_sha256")
    nv_deny("deny: a record not read right after a Clear (reset_at_provision 1)",
            *signed("other-reset", reset_at_provision=str(int(fields["reset_at_provision"]) + 1)),
            "the record's reset_at_provision 1 is not 0")

    # Allow, then what it left in the TPM.
    slot = run_dir / "slot-a.bin"
    rc, text = nv(good, [s1, s2], slot)
    printed = dict(line.split("=", 1) for line in text.splitlines() if re.fullmatch(r"[a-z_]+=\w+", line))
    reset = re.search(r"reset_count: (\d+)", tool_out(tpm.tcti, "tpm2_readclock").decode()).group(1)
    results.append(("allow: nv defines the indices and writes the ledger head into slot A",
                    rc == 0 and slot.read_bytes() == ledger.head and nv_defined() == {measure.NV_POLICY_CTR,
                                                                                         measure.NV_POLICY_BASE}
                    and printed.get("reset_at_provision") == reset == fields["reset_at_provision"], text))

    def logical() -> int:
        out = run_dir / "nv.bin"
        values = []
        for index in (measure.NV_POLICY_CTR, measure.NV_POLICY_BASE):
            out.unlink(missing_ok=True)
            tool_out(tpm.tcti, "tpm2_nvread", f"{index:#x}", "-C", f"{index:#x}", "-s", "8", "-o", str(out))
            values.append(struct.unpack(">Q", out.read_bytes())[0])
        return (values[0] - values[1]) % 2**64

    def names_match() -> bool:
        names = []
        for k in ("op1", "op2"):
            tool_out(tpm.tcti, "tpm2_loadexternal", "-Q", "-C", "n", "-G", "ecc", "-u", str(keys[f"{k}.pub"]),
                     "-c", str(run_dir / "op.ctx"), "-n", str(run_dir / "op.name"))
            tool_out(tpm.tcti, "tpm2_flushcontext", "-t")
            names.append((run_dir / "op.name").read_bytes())
        want = [n.hex() for n in measure.expected_nv_names(measure.delete_policy(names))]
        got = [re.search(r"name: ([0-9a-f]+)", tool_out(tpm.tcti, "tpm2_nvreadpublic", f"{i:#x}").decode()).group(1)
               for i in (measure.NV_POLICY_CTR, measure.NV_POLICY_BASE)]
        return got == want == [printed.get("nv_ctr_name"), printed.get("nv_base_name")]

    results.append(("allow: the logical version after provisioning is v0", logical() == 1, ""))
    results.append(("allow: both Names are tools/measure.py's twin and what nv printed", names_match(), text))

    before = [tool_out(tpm.tcti, "tpm2_nvreadpublic", f"{i:#x}") for i in (measure.NV_POLICY_CTR,
                                                                           measure.NV_POLICY_BASE)]
    again = run_dir / "slot-again.bin"
    rc, text = nv(good, [s1, s2], again)
    results.append(("deny: existing indices without the two delete authorizations",
                    rc != 0 and "already exists; deleting it needs" in text and not again.exists()
                    and before == [tool_out(tpm.tcti, "tpm2_nvreadpublic", f"{i:#x}")
                                   for i in (measure.NV_POLICY_CTR, measure.NV_POLICY_BASE)], text))
    tool_out(tpm.tcti, "tpm2_nvincrement", f"{measure.NV_POLICY_CTR:#x}", "-C", f"{measure.NV_POLICY_CTR:#x}")
    rc, text = nv(good, [s1, s2], again, delete_keys=(keys["op1"], keys["op2"]))
    printed = dict(line.split("=", 1) for line in text.splitlines() if re.fullmatch(r"[a-z_]+=\w+", line))
    results.append(("allow: with both delete authorizations the indices are deleted and redefined at v0",
                    rc == 0 and again.read_bytes() == ledger.head and logical() == 1 and names_match(), text))

    # The operator's delete signer refuses a digest without a session nonce
    # (S23): its allow is the delete above.
    g = {"__file__": str(TOOL), "__name__": "provision"}
    exec(compile(TOOL.read_text(), str(TOOL), "exec"), g)
    name = bytes.fromhex(printed.get("nv_ctr_name", "00"))
    tbs = bytes(4) + measure.undefine_special_cphash(name) + measure.NV_DELETE_REF
    try:
        g["sign_delete"](tbs, str(keys["op1"]), name, run_dir / "empty-nonce.sig")
        why = "signed"
    except g["Refused"] as e:
        why = str(e)
    results.append(("deny: the delete signer refuses an empty session nonce",
                    why == "provision: delete signing refused: the session nonce is empty", why))

    # D5, S18: a Clear zeroes resetCount and restartCount, so a TPM reset
    # since the SRK flow's Clear is one that was not cleared in this
    # session; record and nv refuse it (their allows are the ones above).
    # restartCount alone first: a TPM Resume (Shutdown(STATE), then
    # Startup(STATE)) leaves resetCount at 0, as a Restart would.
    tool_out(tpm.tcti, "tpm2_shutdown")
    subprocess.run(["swtpm_ioctl", "--unix", f"{tpm.sock}.ctrl", "-i"], check=True, capture_output=True)
    tool_out(tpm.tcti, "tpm2_startup")
    restarted = run_dir / "restarted.record"
    rc, text = tool(pinned, "record", "--tcti", tpm.tcti, "--ledger", ledger.dir, "--keys-pub", ledger.keys,
                    "--node", "n1", "--out", restarted, "--policy-bin", ledger.bin)
    results.append(("deny: record on a TPM restarted since its Clear",
                    rc != 0 and "record: the TPM shows reset_count=0 restart_count=1" in text and not restarted.exists(),
                    text))
    subprocess.run(["swtpm_ioctl", "--unix", f"{tpm.sock}.ctrl", "-i"], check=True, capture_output=True)
    tool_out(tpm.tcti, "tpm2_startup", "-c")
    late = run_dir / "late.record"
    rc, text = tool(pinned, "record", "--tcti", tpm.tcti, "--ledger", ledger.dir, "--keys-pub", ledger.keys,
                    "--node", "n1", "--out", late, "--policy-bin", ledger.bin)
    results.append(("deny: record on a TPM reset since its Clear",
                    rc != 0 and "record: the TPM shows reset_count=1 restart_count=0" in text and not late.exists(),
                    text))
    late_slot = run_dir / "slot-late.bin"
    # Even with both delete keys in hand, the existing indices stay as they
    # were: the refusal comes before any delete.
    publics = [tool_out(tpm.tcti, "tpm2_nvreadpublic", f"{i:#x}") for i in (measure.NV_POLICY_CTR, measure.NV_POLICY_BASE)]
    version = logical()
    rc, text = nv(good, [s1, s2], late_slot, delete_keys=(keys["op1"], keys["op2"]))
    results.append(("deny: nv on a TPM reset since its Clear, with a record read right after it",
                    rc != 0 and "nv: the TPM shows reset_count=1 restart_count=0" in text and not late_slot.exists()
                    and publics == [tool_out(tpm.tcti, "tpm2_nvreadpublic", f"{i:#x}")
                                    for i in (measure.NV_POLICY_CTR, measure.NV_POLICY_BASE)]
                    and logical() == version, text))


def main() -> int:
    run_dir = pathlib.Path(tempfile.mkdtemp(prefix="test-provision-"))
    run_dir.chmod(0o700)
    results = []
    tpms = []
    try:
        ca_a, ca_b = make_ca(run_dir, "a"), make_ca(run_dir, "b")
        tpm_a = Swtpm(make_tpm(run_dir, "a", "a"))
        tpm_b = Swtpm(make_tpm(run_dir, "b", "a"))
        tpm_other_ca = Swtpm(make_tpm(run_dir, "c", "b"))
        tpm_bare = Swtpm(make_tpm(run_dir, "d"))
        tpms += [tpm_a, tpm_b, tpm_other_ca, tpm_bare]

        def deny(name, rc, out, path, needle):
            ok = rc != 0 and not path.exists() and needle in out
            results.append((name, ok, out))

        # Allow.
        out = run_dir / "srk-a.pub"
        rc, text = provision(tpm_a.tcti, ca_a, out)
        reported = run_dir / "srk-a.reported"
        ctx = run_dir / "srk-a.ctx"
        tool_out(tpm_a.tcti, "tpm2_createprimary", "-Q", "-C", "o", "-G", "ecc256:aes128cfb", "-g", "sha256", "-a",
                 "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt", "-c", str(ctx))
        tool_out(tpm_a.tcti, "tpm2_readpublic", "-Q", "-c", str(ctx), "-o", str(reported))
        tool_out(tpm_a.tcti, "tpm2_flushcontext", "-t")
        results.append(("allow: the record is the SRK public the TPM reports",
                        rc == 0 and out.exists() and out.read_bytes() == reported.read_bytes(), text))

        # Deny: the EK certificate chains to another CA.
        out = run_dir / "srk-c.pub"
        rc, text = provision(tpm_other_ca.tcti, ca_a, out)
        deny("deny: an EK certificate from another CA", rc, text, out, "EK certificate chain")

        # Deny: no EK certificate.
        out = run_dir / "srk-d.pub"
        rc, text = provision(tpm_bare.tcti, ca_a, out)
        deny("deny: no EK certificate", rc, text, out, "EK certificate: tpm2_nvread failed")

        # Deny: a certificate (from the right CA) for TPM b's EK, read on a.
        cert_b = run_dir / "ek-b.der"
        tool_out(tpm_b.tcti, "tpm2_nvread", "0x01c00002", "-C", "o", "-o", str(cert_b))
        out = run_dir / "srk-mismatch.pub"
        rc, text = provision(tpm_a.tcti, ca_a, out, shim(run_dir, "tpm2_nvread", cert_b))
        deny("deny: an EK certificate that is not this TPM's EK", rc, text, out, "is not this TPM's EK")

        # Deny: TPM b's SRK public, read on a: the template passes, and the
        # TPM refuses to activate a credential naming a key it does not hold.
        srk_b = run_dir / "srk-b.reported"
        ctx_b = run_dir / "srk-b.ctx"
        tool_out(tpm_b.tcti, "tpm2_createprimary", "-Q", "-C", "o", "-G", "ecc256:aes128cfb", "-g", "sha256", "-a",
                 "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt", "-c", str(ctx_b))
        tool_out(tpm_b.tcti, "tpm2_readpublic", "-Q", "-c", str(ctx_b), "-o", str(srk_b))
        tool_out(tpm_b.tcti, "tpm2_flushcontext", "-t")
        out = run_dir / "srk-foreign.pub"
        rc, text = provision(tpm_a.tcti, ca_a, out, shim(run_dir, "tpm2_readpublic", srk_b))
        deny("deny: another TPM's SRK public", rc, text, out, "ActivateCredential")

        # Deny: fixedTPM clear (objectAttributes' bit 1, in the u32 after
        # type and nameAlg).
        loose = run_dir / "srk-loose.pub"
        data = bytearray(reported.read_bytes())
        data[2 + 4 + 3] &= ~0x02
        loose.write_bytes(bytes(data))
        out = run_dir / "srk-loose-out.pub"
        rc, text = provision(tpm_a.tcti, ca_a, out, shim(run_dir, "tpm2_readpublic", loose))
        deny("deny: an SRK public with fixedTPM clear", rc, text, out, "not the SRK storage template")

        nv_fixtures(run_dir, ca_a, tpm_b, tpms, results)
    finally:
        for t in tpms:
            t.close()
        shutil.rmtree(run_dir, ignore_errors=True)
    failures = 0
    for name, ok, text in results:
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f"\n{text}"))
    if run_dir.exists():
        print(f"FAIL the run directory {run_dir} survived")
        failures += 1
    print(f"PROVISION-FIXTURES {len(results)}")
    return 1 if failures or len(results) != FIXTURES else 0


if __name__ == "__main__":
    sys.exit(main())
