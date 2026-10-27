"""tools/provision (M7 plan C5) against real swtpms and a CA made for the run.

Allow: a TPM whose EK certificate chains to the CA gets its SRK record,
byte-equal to the SRK public the TPM reports. Deny, each exiting non-zero
with no record and a needle naming the cause: an EK certificate from
another CA, one that does not certify this TPM's EK, no EK certificate,
an SRK public from another TPM (activation fails in the TPM), an SRK
public with fixedTPM clear. The last three read a substituted file through
a PATH shim for one tpm2-tools command; the comparison, the template check
and the activation stay the real ones.

Everything lives in one per-run directory, removed in `finally`; a
directory that survives fails the run.

Usage: python3 tests/tools/test_provision.py
Prints "PROVISION-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/provision"


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


def provision(tcti: str, ca: pathlib.Path, out: pathlib.Path, env=None):
    r = subprocess.run([sys.executable, str(TOOL), "--tcti", tcti, "--ek-root", str(ca / "swtpm-localca-rootca-cert.pem"),
                        "--ek-intermediates", str(ca / "issuercert.pem"), "--out", str(out)],
                       env=env, capture_output=True, text=True, cwd=ROOT)
    return r.returncode, r.stdout + r.stderr


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
    return 1 if failures or len(results) != 6 else 0


if __name__ == "__main__":
    sys.exit(main())
