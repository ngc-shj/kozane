"""Each property tools/mkcert promises (M6 plan C11, T-N10) has a fixture:
the dev CA's constraints in both name modes, the leaf's extensions, OpenSSL
accepting the configured name and refusing a leaf for any other name the
CA signed, and no key ever written.

Usage: python3 tests/tools/test_mkcert.py   (in the dev container: OpenSSL)
Prints "MKCERT-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import datetime
import importlib.machinery
import importlib.util
import ipaddress
import pathlib
import subprocess
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/mkcert"
loader = importlib.machinery.SourceFileLoader("mkcert", str(TOOL))
spec = importlib.util.spec_from_loader("mkcert", loader)
mkcert = importlib.util.module_from_spec(spec)
loader.exec_module(mkcert)

NAME = "gw.example"
IP = "10.0.2.15"


def run(name: str, negative: bool = True, public_key=None) -> dict:
    """mkcert run as a program in a fresh directory: {file: bytes}, and the
    leaf's key pair's public half."""
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        public = public_key or ec.generate_private_key(ec.SECP256R1()).public_key()
        (d / "tls.pub").write_bytes(public.public_bytes(serialization.Encoding.PEM,
                                                        serialization.PublicFormat.SubjectPublicKeyInfo))
        out = d / "out"
        out.mkdir()
        args = [sys.executable, str(TOOL), "--public", str(d / "tls.pub"), "--name", name, "--out", str(out)]
        r = subprocess.run(args + (["--test-negative"] if negative else []), capture_output=True, text=True)
        if r.returncode != 0:
            raise AssertionError(f"mkcert failed: {r.stderr}")
        files = {p.name: p.read_bytes() for p in out.iterdir()}
        files["_public"] = public
        return files


def cert(files: dict, name: str) -> x509.Certificate:
    data = files[name]
    return x509.load_pem_x509_certificate(data) if name.endswith(".pem") else x509.load_der_x509_certificate(data)


def openssl_verify(files: dict, leaf: str, check: list) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        (d / "ca.pem").write_bytes(files["devca.pem"])
        (d / "leaf.pem").write_bytes(cert(files, leaf).public_bytes(serialization.Encoding.PEM))
        return subprocess.run(["openssl", "verify", "-CAfile", str(d / "ca.pem"), "-purpose", "sslserver",
                               "-x509_strict", *check, str(d / "leaf.pem")], capture_output=True, text=True)


def accepted(files, leaf, check):
    r = openssl_verify(files, leaf, check)
    assert r.returncode == 0 and r.stdout.strip().endswith(": OK"), r.stdout + r.stderr


def refused(files, leaf, needle):
    r = openssl_verify(files, leaf, [])
    assert r.returncode != 0, f"{leaf} verified: {r.stdout}"
    assert needle in r.stdout + r.stderr, r.stdout + r.stderr


NAME_RUN = run(NAME)
IP_RUN = run(IP)


def nc(files) -> x509.Extension:
    return cert(files, "devca.pem").extensions.get_extension_for_class(x509.NameConstraints)


def name_mode_constraints():
    e = nc(NAME_RUN)
    assert e.critical
    assert e.value.permitted_subtrees == [x509.DNSName(NAME)]
    assert e.value.excluded_subtrees == [x509.IPAddress(ipaddress.IPv4Network("0.0.0.0/0")),
                                         x509.IPAddress(ipaddress.IPv6Network("::/0"))]


def ip_mode_constraints():
    e = nc(IP_RUN)
    assert e.critical
    assert e.value.permitted_subtrees == [x509.IPAddress(ipaddress.IPv4Network(f"{IP}/32")), x509.DNSName("invalid")]
    assert e.value.excluded_subtrees == [x509.IPAddress(ipaddress.IPv6Network("::/0"))]


def ca_path_len_zero():
    for files in (NAME_RUN, IP_RUN):
        bc = cert(files, "devca.pem").extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.critical and bc.value.ca and bc.value.path_length == 0, bc


def thirty_day_validity():
    for files in (NAME_RUN, IP_RUN):
        for c in (cert(files, "devca.pem"), cert(files, "tls.der")):
            assert c.not_valid_after_utc - c.not_valid_before_utc == datetime.timedelta(days=30), c
            assert abs(datetime.datetime.now(datetime.timezone.utc) - c.not_valid_before_utc) < datetime.timedelta(minutes=5)


def leaf_extensions():
    for files in (NAME_RUN, IP_RUN):
        ext = cert(files, "tls.der").extensions
        bc = ext.get_extension_for_class(x509.BasicConstraints)
        assert bc.critical and not bc.value.ca
        ku = ext.get_extension_for_class(x509.KeyUsage).value
        assert ku.digital_signature and not ku.key_cert_sign and not ku.key_encipherment
        assert list(ext.get_extension_for_class(x509.ExtendedKeyUsage).value) == [ExtendedKeyUsageOID.SERVER_AUTH]


def leaf_carries_the_given_key_and_name():
    leaf = cert(NAME_RUN, "tls.der")
    assert leaf.public_key() == NAME_RUN["_public"]
    assert leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName) == [NAME]
    assert leaf.public_key() != cert(NAME_RUN, "devca.pem").public_key()


def ip_mode_leaf_has_empty_subject_and_critical_san():
    leaf = cert(IP_RUN, "tls.der")
    assert len(leaf.subject) == 0
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.critical
    assert san.value.get_values_for_type(x509.IPAddress) == [ipaddress.IPv4Address(IP)]
    assert san.value.get_values_for_type(x509.DNSName) == []


def openssl_accepts_the_name_mode_leaf():
    accepted(NAME_RUN, "tls.der", ["-verify_hostname", NAME])


def openssl_accepts_the_ip_mode_leaf():
    accepted(IP_RUN, "tls.der", ["-verify_ip", IP])


def openssl_refuses_another_name_in_name_mode():
    assert cert(NAME_RUN, "negative-name.der").extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == [f"not-{NAME}"]
    refused(NAME_RUN, "negative-name.der", "permitted subtree violation")


def openssl_refuses_the_other_form_in_name_mode():
    assert cert(NAME_RUN, "negative-form.der").extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress)
    refused(NAME_RUN, "negative-form.der", "excluded subtree violation")


def openssl_refuses_another_address_in_ip_mode():
    refused(IP_RUN, "negative-name.der", "permitted subtree violation")


def openssl_refuses_the_other_form_in_ip_mode():
    names = cert(IP_RUN, "negative-form.der").extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    assert names == ["gateway.example"], names
    refused(IP_RUN, "negative-form.der", "permitted subtree violation")


def no_key_file_written():
    for files in (NAME_RUN, IP_RUN):
        assert sorted(f for f in files if f != "_public") == sorted(mkcert.OUTPUTS + mkcert.NEGATIVES), files.keys()
        assert not any(b"PRIVATE" in v for f, v in files.items() if f != "_public")
    without = run(NAME, negative=False)
    assert sorted(f for f in without if f != "_public") == sorted(mkcert.OUTPUTS)


def ca_key_never_serialized():
    """Every serializer of a private key raises during an in-process run;
    the run still succeeds, so none was called."""
    saved = {}
    calls = []
    for cls in {type(ec.generate_private_key(ec.SECP256R1()))}:
        for attr in ("private_bytes", "private_bytes_raw"):
            if hasattr(cls, attr):
                saved[(cls, attr)] = getattr(cls, attr)

                def boom(*_a, _attr=attr, **_k):
                    calls.append(_attr)
                    raise AssertionError(f"{_attr} called")
                setattr(cls, attr, boom)
    try:
        public = ec.generate_private_key(ec.SECP256R1()).public_key()
        out = mkcert.issue(public, NAME, True)
    finally:
        for (cls, attr), f in saved.items():
            setattr(cls, attr, f)
    assert saved and not calls and set(out) == set(mkcert.OUTPUTS + mkcert.NEGATIVES)


def refuses_a_key_on_another_curve():
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        k = ec.generate_private_key(ec.SECP384R1()).public_key()
        (d / "p.pem").write_bytes(k.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        r = subprocess.run([sys.executable, str(TOOL), "--public", str(d / "p.pem"), "--name", NAME, "--out", str(d)],
                           capture_output=True, text=True)
        assert r.returncode == 1 and "not a P-256 public key" in r.stderr, r.stderr
        assert sorted(p.name for p in d.iterdir()) == ["p.pem"]


def refuses_a_malformed_name():
    for bad in ("Gw.example", "-gw.example", "gw_x.example", "gw..example", "10.0.2", "1.2.3.4.5", ""):
        try:
            mkcert.parse_name(bad)
        except mkcert.Refused:
            continue
        raise AssertionError(f"{bad!r} accepted")


def refuses_to_replace_an_output():
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        (d / "tls.der").write_bytes(b"keep")
        try:
            mkcert.write_all(d, {"devca.pem": b"x", "tls.der": b"y"})
        except mkcert.Refused as e:
            assert "tls.der already exist" in str(e)
        else:
            raise AssertionError("replaced tls.der")
        assert (d / "tls.der").read_bytes() == b"keep" and not (d / "devca.pem").exists()


CASES = [
    name_mode_constraints,
    ip_mode_constraints,
    ca_path_len_zero,
    thirty_day_validity,
    leaf_extensions,
    leaf_carries_the_given_key_and_name,
    ip_mode_leaf_has_empty_subject_and_critical_san,
    openssl_accepts_the_name_mode_leaf,
    openssl_accepts_the_ip_mode_leaf,
    openssl_refuses_another_name_in_name_mode,
    openssl_refuses_the_other_form_in_name_mode,
    openssl_refuses_another_address_in_ip_mode,
    openssl_refuses_the_other_form_in_ip_mode,
    no_key_file_written,
    ca_key_never_serialized,
    refuses_a_key_on_another_curve,
    refuses_a_malformed_name,
    refuses_to_replace_an_output,
]


def main() -> int:
    failures = 0
    for case in CASES:
        try:
            case()
            print(f"ok   {case.__name__}")
        except Exception as e:  # noqa: BLE001  (any failure is the case's)
            failures += 1
            print(f"FAIL {case.__name__}: {type(e).__name__}: {e}")
    print(f"MKCERT-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
