"""`tools/policy` end to end: draft, approve, sign, verify and the ledger
(M8 plan C2, D11). Every case starts from a fresh fixture (its own temp
directory, its own keys, roster and ledger) so failures never depend on
order.

Usage: python3 tests/tools/test_policy.py   (after `make policy-tool`, or
the harness builds the release binary itself if it is missing)
Prints "POLICY-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import base64
import os
import pathlib
import shutil
import re
import subprocess
import sys
import tempfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build/policy/target/release/policy"
APPROVERS = pathlib.Path()
SPK_LEN = 524_160

# The wire header's fixed offsets (M8 plan C1 layout; `wire_header.rs`
# reads the same ones). Used only to poke a specific field directly, the
# same way tests/tools/test_release.py flips a known byte offset.
FLEET_ID_AT, FLEET_ID_LEN = 6, 16
VERSION_AT = 22
MIN_RELEASE_AT = 26
PREV_SHA256_AT, PREV_SHA256_LEN = 30, 32
ROSTER_SHA256_AT, ROSTER_SHA256_LEN = 62, 32

GATEWAY_BASE = (ROOT / "config/gateway.toml").read_text() \
    .replace('rp_pub_path = "keys/', f'rp_pub_path = "{ROOT}/config/keys/') \
    .replace('tls_cert = "keys/', f'tls_cert = "{ROOT}/config/keys/')


def run(*args) -> tuple:
    r = subprocess.run([str(a) for a in args], cwd=ROOT, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def build_binary(pin: str = "") -> pathlib.Path:
    """The release binary; with `pin`, a separate build whose compiled-in
    genesis-roster pin is the test roster's digest (a build-time input, as
    the shipped file is)."""
    target = "build/policy/target-pinned" if pin else "build/policy/target"
    env = dict(os.environ, KOZANE_POLICY_GENESIS_PIN=pin) if pin else dict(os.environ)
    env.pop("KOZANE_POLICY_GENESIS_PIN", None) if not pin else None
    r = subprocess.run(
        ["cargo", "build", "--locked", "--release", "--manifest-path", "tools/policy/Cargo.toml", "--target-dir", target],
        cwd=ROOT, capture_output=True, text=True, env=env,
    )
    if r.returncode != 0:
        raise SystemExit(f"building tools/policy failed:\n{r.stdout}\n{r.stderr}")
    return ROOT / target / "release/policy"


def wg_pub(n: int) -> str:
    return base64.b64encode(bytes([n]) * 32).decode()


def write_rp_key(path: pathlib.Path, n: int) -> None:
    path.write_bytes(bytes([n]) * SPK_LEN)


def flip(path: pathlib.Path, at: int) -> None:
    b = bytearray(path.read_bytes())
    b[at] ^= 1
    path.write_bytes(bytes(b))


def gateway_variant(path: pathlib.Path, *, inside_prefix: str, inside_ip: str, outside_ip: str, neighbor_ip: str) -> None:
    text = GATEWAY_BASE
    text = text.replace('inside_prefix = "10.99.0.0/24"', f'inside_prefix = "{inside_prefix}"')
    text = text.replace('inside_ip = "10.99.0.1"', f'inside_ip = "{inside_ip}"')
    text = text.replace('outside_ip = "10.0.2.15"', f'outside_ip = "{outside_ip}"')
    text = text.replace('ip = "10.99.0.2"', f'ip = "{neighbor_ip}"')
    text = text.replace('backend = { ip = "10.99.0.2"', f'backend = {{ ip = "{neighbor_ip}"')
    path.write_text(text)


FLEET_ID = "ab" * 16


def peers_toml(d: pathlib.Path, *, peers: list, groups: list, min_release: int = 0, fleet_id: str = FLEET_ID) -> str:
    out = [f'fleet_id = "{fleet_id}"', f"min_release = {min_release}", ""]
    for p in peers:
        out.append("[[peers]]")
        out.append(f'wg_pub = "{wg_pub(p["n"])}"')
        out.append(f'rp_pub_path = "{p["rp"]}"')
        out.append("allowed_ips = [" + ", ".join(f'"{a}"' for a in p["allowed"]) + "]")
        if p.get("groups"):
            out.append("groups = [" + ", ".join(f'"{g}"' for g in p["groups"]) + "]")
        out.append("")
    for g in groups:
        out.append("[[groups]]")
        out.append(f'name = "{g["name"]}"')
        for r in g["rules"]:
            out.append("[[groups.rules]]")
            out.append(f'dst = "{r["dst"]}"')
            out.append(f'proto = "{r["proto"]}"')
            out.append(f'port_lo = {r["port_lo"]}')
            out.append(f'port_hi = {r["port_hi"]}')
        out.append("")
    return "\n".join(out) + "\n"


def default_peers_toml(d: pathlib.Path, min_release: int = 0, fleet_id: str = FLEET_ID) -> pathlib.Path:
    write_rp_key(d / "p1.pk", 1)
    write_rp_key(d / "p2.pk", 2)
    text = peers_toml(
        d,
        peers=[
            {"n": 1, "rp": "p1.pk", "allowed": ["10.1.0.0/24"], "groups": ["eng"]},
            {"n": 2, "rp": "p2.pk", "allowed": ["10.1.1.0/24"], "groups": []},
        ],
        groups=[{"name": "eng", "rules": [{"dst": "10.2.0.0/24", "proto": "tcp", "port_lo": 443, "port_hi": 443}]}],
        min_release=min_release,
        fleet_id=fleet_id,
    )
    path = d / "peers.toml"
    path.write_text(text)
    return path


def roster_toml(approvers: dict) -> str:
    out = []
    for aid, pub in approvers.items():
        out.append("[[approver]]")
        out.append(f'id = "{aid}"')
        out.append(f'ed25519_pub = "{pub}"')
        out.append("")
    return "\n".join(out) + "\n"


def pubkey(d: pathlib.Path, name: str) -> str:
    return (d / name / "ed25519.pub").read_text().strip()


def reviewed(ledger, draft) -> str:
    """The diff_sha256 `policy diff` prints for `draft` against `ledger`:
    what an approver passes to `approve` after reading that diff."""
    rc, out = run(BIN, "diff", "--ledger", ledger, "--draft", draft)
    assert rc == 0, out
    return re.search(r"^diff_sha256=([0-9a-f]{64})$", out, re.M).group(1)


def blank_head(path: pathlib.Path) -> pathlib.Path:
    """An approver head that records nothing yet: a restore approver whose
    head predates every version a case cares about."""
    path.write_text("approved_body_sha256=-\napproved_version=-\nbody_sha256=-\nversion=-\n")
    return path


class Ctx:
    """A fresh fixture: dev keys, a 3-approver roster, an initialised
    ledger, a 2-node fleet, and version 0 already signed."""

    def __init__(self, d: pathlib.Path, fleet_id: str = FLEET_ID):
        self.d = d
        self.keys = d / "policy-keys"
        run(BIN, "keygen", "--dir", self.keys, "--forbid", ROOT)
        # The session's approver keys: one roster, so one compiled-in pin.
        for a in ("alice", "bob", "carol", "dave"):
            shutil.copytree(APPROVERS / a, d / a)
        self.approver_key = {a: d / a / "ed25519.key" for a in ("alice", "bob", "carol", "dave")}
        self.roster_path = d / "roster.toml"
        # dave starts outside the roster (used to build a roster-change
        # fixture and as an always-unknown approver).
        self.roster_path.write_text(roster_toml({a: pubkey(d, a) for a in ("alice", "bob", "carol")}))
        self.ledger = d / "ledger"
        rc, out = run(BIN, "ledger", "init", "--dir", self.ledger, "--genesis-roster", self.roster_path)
        assert rc == 0, out

        gw1 = d / "gw1.toml"
        gateway_variant(gw1, inside_prefix="10.99.0.0/24", inside_ip="10.99.0.1", outside_ip="10.0.2.15", neighbor_ip="10.99.0.2")
        gw2 = d / "gw2.toml"
        gateway_variant(gw2, inside_prefix="10.199.0.0/24", inside_ip="10.199.0.1", outside_ip="10.0.3.15", neighbor_ip="10.199.0.2")
        self.gw1, self.gw2 = gw1, gw2
        self.fleet = d / "fleet.toml"
        rc, out = run(BIN, "fleet", "--out", self.fleet, "--fleet-id", fleet_id, gw1, gw2)
        assert rc == 0, out

        self.peers_dir = d / "v0"
        self.peers_dir.mkdir()
        peers0 = default_peers_toml(self.peers_dir, fleet_id=fleet_id)
        self.draft0 = d / "draft0.bin"
        rc, out = run(BIN, "render", "--input", peers0, "--fleet", self.fleet, "--ledger", self.ledger, "--out", self.draft0)
        assert rc == 0, out
        a0 = self.approve("alice", self.draft0, d / "alice0.head", out=d / "a0.approval")
        b0 = self.approve("bob", self.draft0, d / "bob0.head", out=d / "b0.approval")
        self.slot0 = d / "slot0.bin"
        rc, out = run(BIN, "sign", "--ledger", self.ledger, "--draft", self.draft0, "--approvals", a0, b0, "--keys", self.keys, "--out", self.slot0)
        assert rc == 0, out

        # A version-1 draft, approved and ready to sign, for most cases.
        self.peers_dir1 = d / "v1"
        self.peers_dir1.mkdir()
        peers1 = default_peers_toml(self.peers_dir1, min_release=1, fleet_id=fleet_id)
        self.draft1 = d / "draft1.bin"
        rc, out = run(BIN, "render", "--input", peers1, "--fleet", self.fleet, "--ledger", self.ledger, "--out", self.draft1)
        assert rc == 0, out
        self.a1 = self.approve("alice", self.draft1, d / "alice1.head", out=d / "a1.approval")
        self.b1 = self.approve("bob", self.draft1, d / "bob1.head", out=d / "b1.approval")

    def approve(self, approver: str, draft: pathlib.Path, head: pathlib.Path, out: pathlib.Path) -> pathlib.Path:
        rc, o = run(BIN, "approve", "--ledger", self.ledger, "--draft", draft, "--diff-sha256", reviewed(self.ledger, draft), "--approver-key", self.approver_key[approver],
                    "--approver-id", approver, "--head", head, "--out", out)
        assert rc == 0, o
        return out

    def sign(self, draft: pathlib.Path, approvals: list, out: pathlib.Path) -> tuple:
        return run(BIN, "sign", "--ledger", self.ledger, "--draft", draft, "--approvals", *approvals, "--keys", self.keys, "--out", out)

    def ledger_snapshot(self) -> list:
        """The whole ledger tree, contents included: `append` writes the
        roster and the approvals before the entry."""
        return sorted((str(p.relative_to(self.ledger)), p.read_bytes() if p.is_file() else b"")
                      for p in self.ledger.rglob("*"))

    def sign_refused(self, draft: pathlib.Path, approvals: list, needle: str) -> tuple:
        """A refused `sign`: non-zero for `needle`'s reason, and nothing
        written, neither a slot nor anything in the ledger (the reason alone would
        stay green if the entry were committed before the check)."""
        before = self.ledger_snapshot()
        out_slot = self.d / "refused-slot.bin"
        rc, out = self.sign(draft, approvals, out_slot)
        wrote = out_slot.exists() or self.ledger_snapshot() != before
        return rc != 0 and needle in out and not wrote, out + ("\nrefused sign wrote a slot or ledger entry" if wrote else "")

    def tampered_copy(self, src: pathlib.Path, dst_name: str, at: int, nbytes: int, value: bytes) -> pathlib.Path:
        b = bytearray(src.read_bytes())
        b[at:at + nbytes] = value
        dst = self.d / dst_name
        dst.write_bytes(bytes(b))
        return dst


# --- cases -----------------------------------------------------------------

def case_allow_sign_v1(d):
    ctx = Ctx(d)
    slot1 = d / "slot1.bin"
    rc, out = ctx.sign(ctx.draft1, [ctx.a1, ctx.b1], slot1)
    rc2, out2 = run(BIN, "verify", "--keys-pub", ctx.keys, "--slot", slot1, "--fleet", ctx.fleet)
    rc3, out3 = run(BIN, "verify", "--ledger", ctx.ledger, "--keys-pub", ctx.keys)
    ok = rc == 0 and rc2 == 0 and rc3 == 0 and "version 1" in out3
    return ok, out + out2 + out3


def case_payload_swapped_after_approval(d):
    """A14: the draft's peer section is edited after both approvals."""
    ctx = Ctx(d)
    swapped = ctx.tampered_copy(ctx.draft1, "swapped.bin", 200, 1, bytes([ctx.draft1.read_bytes()[200] ^ 1]))
    return ctx.sign_refused(swapped, [ctx.a1, ctx.b1], "another body")


def case_same_approver_twice(d):
    ctx = Ctx(d)
    return ctx.sign_refused(ctx.draft1, [ctx.a1, ctx.a1], "approved twice")


def case_one_approval_only(d):
    ctx = Ctx(d)
    return ctx.sign_refused(ctx.draft1, [ctx.a1], "at least two")


def case_approver_not_in_roster(d):
    ctx = Ctx(d)
    mallory = ctx.approve("dave", ctx.draft1, d / "dave.head", out=d / "dave.approval")
    return ctx.sign_refused(ctx.draft1, [ctx.a1, mallory], "is not in the roster")


def case_forged_approval_signature(d):
    ctx = Ctx(d)
    forged = d / "forged.approval"
    b = bytearray(ctx.a1.read_bytes())
    # Inside the trailing sig_ed25519 hex line: another valid hex digit, so
    # the record still parses and only the signature is wrong.
    b[-5] = ord("1") if b[-5] != ord("1") else ord("2")
    forged.write_bytes(bytes(b))
    return ctx.sign_refused(ctx.draft1, [forged, ctx.b1], "signature does not verify")


def case_wrong_approval_domain(d):
    """A restore-approval record (its own domain and field set) handed to
    `sign` as if it were a bundle approval. A same-fields/wrong-domain
    forgery is proved directly in src/tests.rs, where the signing
    primitive is reachable; the CLI never signs an approval under the
    wrong domain to hand it one."""
    ctx = Ctx(d)
    restore = d / "restore.approval"
    rc0, out0 = run(BIN, "ledger", "approve-restore", "--head", blank_head(d / "restore-1.head"), "--from", ctx.ledger, "--approver-key", ctx.approver_key["alice"],
                     "--approver-id", "alice", "--out", restore)
    assert rc0 == 0, out0
    return ctx.sign_refused(ctx.draft1, [restore, ctx.b1], "record key head_body_sha256 is unknown")


def case_record_for_another_version(d):
    ctx = Ctx(d)
    bumped = ctx.tampered_copy(ctx.draft1, "bumped.bin", VERSION_AT, 4, (2).to_bytes(4, "big"))
    a_bumped = ctx.approve("alice", bumped, d / "alice_b.head", out=d / "a_bumped.approval")
    return ctx.sign_refused(ctx.draft1, [a_bumped, ctx.b1], "bound to version")


def case_record_for_another_fleet(d):
    ctx = Ctx(d)
    other_fleet = bytes.fromhex("cd" * 16)
    bumped = ctx.tampered_copy(ctx.draft1, "otherfleet.bin", FLEET_ID_AT, FLEET_ID_LEN, other_fleet)
    a_bumped = ctx.approve("alice", bumped, d / "alice_f.head", out=d / "a_fleet.approval")
    return ctx.sign_refused(ctx.draft1, [a_bumped, ctx.b1], "another fleet_id")


def case_record_for_another_prev(d):
    ctx = Ctx(d)
    bumped = ctx.tampered_copy(ctx.draft1, "otherprev.bin", PREV_SHA256_AT, PREV_SHA256_LEN, bytes([0x55] * PREV_SHA256_LEN))
    a_bumped = ctx.approve("alice", bumped, d / "alice_p.head", out=d / "a_prev.approval")
    return ctx.sign_refused(ctx.draft1, [a_bumped, ctx.b1], "another prev_sha256")


def case_record_for_another_roster(d):
    ctx = Ctx(d)
    bumped = ctx.tampered_copy(ctx.draft1, "otherroster.bin", ROSTER_SHA256_AT, ROSTER_SHA256_LEN, bytes([0x66] * ROSTER_SHA256_LEN))
    a_bumped = ctx.approve("alice", bumped, d / "alice_r.head", out=d / "a_roster.approval")
    return ctx.sign_refused(ctx.draft1, [a_bumped, ctx.b1], "another roster_sha256")


def case_record_for_another_diff(d):
    """`approve` run against a different (empty) ledger computes the diff
    against "no previous bundle" instead of the real v0, so the recorded
    diff_sha256 disagrees with what `sign` recomputes, even though every
    other field matches the real draft."""
    ctx = Ctx(d)
    other_ledger = d / "other-ledger"
    rc0, out0 = run(BIN, "ledger", "init", "--dir", other_ledger, "--genesis-roster", ctx.roster_path)
    assert rc0 == 0, out0
    rc1, out1 = run(BIN, "approve", "--ledger", other_ledger, "--draft", ctx.draft1, "--diff-sha256", reviewed(other_ledger, ctx.draft1), "--approver-key", ctx.approver_key["alice"],
                     "--approver-id", "alice", "--head", d / "alice-other.head", "--out", d / "a_diff.approval")
    assert rc1 == 0, out1
    return ctx.sign_refused(ctx.draft1, [d / "a_diff.approval", ctx.b1], "another diff")


def case_version_equal_to_head(d):
    ctx = Ctx(d)
    bumped = ctx.tampered_copy(ctx.draft1, "v0again.bin", VERSION_AT, 4, (0).to_bytes(4, "big"))
    a = ctx.approve("alice", bumped, d / "a.head", out=d / "a_eq.approval")
    b = ctx.approve("bob", bumped, d / "b.head", out=d / "b_eq.approval")
    return ctx.sign_refused(bumped, [a, b], "does not match the ledger head+1")


def case_version_below_head(d):
    """A version that underflows below any sane head (max u32) — the same
    head+1 guard as "equal", exercised at the other boundary."""
    ctx = Ctx(d)
    bumped = ctx.tampered_copy(ctx.draft1, "vhigh.bin", VERSION_AT, 4, (0xFFFFFFFF).to_bytes(4, "big"))
    a = ctx.approve("alice", bumped, d / "a.head", out=d / "a_lo.approval")
    b = ctx.approve("bob", bumped, d / "b.head", out=d / "b_lo.approval")
    return ctx.sign_refused(bumped, [a, b], "does not match the ledger head+1")


def case_version_skips(d):
    ctx = Ctx(d)
    bumped = ctx.tampered_copy(ctx.draft1, "v2.bin", VERSION_AT, 4, (2).to_bytes(4, "big"))
    a = ctx.approve("alice", bumped, d / "a.head", out=d / "a_sk.approval")
    b = ctx.approve("bob", bumped, d / "b.head", out=d / "b_sk.approval")
    return ctx.sign_refused(bumped, [a, b], "does not match the ledger head+1")


def case_genesis_with_nonempty_ledger(d):
    """A genesis (version 0) draft, rendered from a fresh empty ledger,
    signed against the real ledger which already has v0."""
    ctx = Ctx(d)
    fresh = d / "fresh-ledger"
    rc0, out0 = run(BIN, "ledger", "init", "--dir", fresh, "--genesis-roster", ctx.roster_path)
    assert rc0 == 0, out0
    genesis_dir = d / "genesis-peers"
    genesis_dir.mkdir()
    g0 = default_peers_toml(genesis_dir)
    draft_g = d / "draft_genesis.bin"
    rc1, out1 = run(BIN, "render", "--input", g0, "--fleet", ctx.fleet, "--ledger", fresh, "--out", draft_g)
    assert rc1 == 0, out1
    a = ctx.approve("alice", draft_g, d / "a.head", out=d / "a_g.approval")
    b = ctx.approve("bob", draft_g, d / "b.head", out=d / "b_g.approval")
    return ctx.sign_refused(draft_g, [a, b], "does not match the ledger head+1")


def case_prev_not_ledger_head(d):
    ctx = Ctx(d)
    bumped = ctx.tampered_copy(ctx.draft1, "badprev.bin", PREV_SHA256_AT, PREV_SHA256_LEN, bytes([0x77] * PREV_SHA256_LEN))
    a = ctx.approve("alice", bumped, d / "a.head", out=d / "a_pv.approval")
    b = ctx.approve("bob", bumped, d / "b.head", out=d / "b_pv.approval")
    return ctx.sign_refused(bumped, [a, b], "prev_sha256 is not the ledger head")


def case_second_body_for_signed_version(d):
    """A second, distinct body also claiming version 1, drafted and
    approved while the ledger was still at height 0 (so `render` itself
    could not yet see a collision), presented to `sign` only after the
    first version 1 is already in the ledger."""
    ctx = Ctx(d)
    other_dir = d / "v1b"
    other_dir.mkdir()
    other_peers = default_peers_toml(other_dir, min_release=5)
    other_draft = d / "draft1b.bin"
    rc0, out0 = run(BIN, "render", "--input", other_peers, "--fleet", ctx.fleet, "--ledger", ctx.ledger, "--out", other_draft)
    assert rc0 == 0, out0
    a = ctx.approve("alice", other_draft, d / "a2.head", out=d / "a_2nd.approval")
    b = ctx.approve("bob", other_draft, d / "b2.head", out=d / "b_2nd.approval")
    rc1, out1 = ctx.sign(ctx.draft1, [ctx.a1, ctx.b1], d / "slot1.bin")
    assert rc1 == 0, out1
    return ctx.sign_refused(other_draft, [a, b], "does not match the ledger head+1")


def case_tampered_roster(d):
    ctx = Ctx(d)
    rc0, out0 = run(BIN, "verify", "--ledger", ctx.ledger, "--keys-pub", ctx.keys)
    assert rc0 == 0, out0
    roster_files = list((ctx.ledger / "roster").glob("*.toml"))
    assert roster_files, "no roster stored"
    f = roster_files[0]
    f.write_text(f.read_text() + '\n[[approver]]\nid = "mallory"\ned25519_pub = "' + "11" * 32 + '"\n')
    rc, out = run(BIN, "verify", "--ledger", ctx.ledger, "--keys-pub", ctx.keys)
    return rc != 0 and "tampered" in out, out


def case_truncated_ledger(d):
    ctx = Ctx(d)
    rc0, out0 = ctx.sign(ctx.draft1, [ctx.a1, ctx.b1], d / "slot1.bin")
    assert rc0 == 0, out0
    (ctx.ledger / "entries" / "0000000000.bin").unlink()
    rc, out = run(BIN, "verify", "--ledger", ctx.ledger, "--keys-pub", ctx.keys)
    return rc != 0 and ("truncated" in out or "gap" in out), out


def case_re_genesis(d):
    ctx = Ctx(d)
    rc, out = run(BIN, "ledger", "init", "--dir", ctx.ledger, "--genesis-roster", ctx.roster_path)
    return rc != 0 and "already exists" in out, out


def case_broken_chain_link(d):
    ctx = Ctx(d)
    rc0, out0 = ctx.sign(ctx.draft1, [ctx.a1, ctx.b1], d / "slot1.bin")
    assert rc0 == 0, out0
    flip(ctx.ledger / "entries" / "0000000000.bin", 500)
    rc, out = run(BIN, "verify", "--ledger", ctx.ledger, "--keys-pub", ctx.keys)
    return rc != 0 and ("broken chain link" in out or "signature does not verify" in out), out


def approve_refused(rc: int, out: str, head: pathlib.Path, head_was: str, record: pathlib.Path, needle: str) -> tuple:
    """A refused `approve`: non-zero for `needle`'s reason, no approval
    record written and the approver's head left as it was."""
    wrote = record.exists() or head.read_text() != head_was
    return rc != 0 and needle in out and not wrote, out + ("\nrefused approve wrote a record or moved the head" if wrote else "")


def case_approver_head_ahead_of_ledger(d):
    ctx = Ctx(d)
    ahead = d / "ahead.head"
    ahead.write_text("approved_body_sha256=-\napproved_version=-\nbody_sha256=" + "ab" * 32 + "\nversion=5\n")
    rc, out = run(BIN, "approve", "--ledger", ctx.ledger, "--draft", ctx.draft1, "--diff-sha256", reviewed(ctx.ledger, ctx.draft1), "--approver-key", ctx.approver_key["carol"],
                  "--approver-id", "carol", "--head", ahead, "--out", d / "c1.approval")
    return approve_refused(rc, out, ahead, "approved_body_sha256=-\napproved_version=-\nbody_sha256=" + "ab" * 32 + "\nversion=5\n", d / "c1.approval", "behind this approver's recorded head")


def case_approver_head_same_version_different_digest(d):
    ctx = Ctx(d)
    wrong = d / "wrong.head"
    wrong.write_text("approved_body_sha256=-\napproved_version=-\nbody_sha256=" + "cd" * 32 + "\nversion=0\n")
    rc, out = run(BIN, "approve", "--ledger", ctx.ledger, "--draft", ctx.draft1, "--diff-sha256", reviewed(ctx.ledger, ctx.draft1), "--approver-key", ctx.approver_key["carol"],
                  "--approver-id", "carol", "--head", wrong, "--out", d / "c1.approval")
    return approve_refused(rc, out, wrong, "approved_body_sha256=-\napproved_version=-\nbody_sha256=" + "cd" * 32 + "\nversion=0\n", d / "c1.approval", "tampered or forked ledger")


def case_head_file_follows_the_ledger_across_versions(d):
    """One head file kept across versions (as the runbook has it): it
    records the verified ledger head, so after v1 is signed the same file
    lets the approver approve v2."""
    ctx = Ctx(d)
    head = d / "carol.head"
    ctx.approve("carol", ctx.draft1, head, out=d / "c1.approval")
    rc0, out0 = ctx.sign(ctx.draft1, [ctx.a1, ctx.b1], d / "slot1.bin")
    assert rc0 == 0, out0
    peers_dir = d / "v2"
    peers_dir.mkdir()
    draft2 = d / "draft2.bin"
    rc1, out1 = run(BIN, "render", "--input", default_peers_toml(peers_dir, min_release=2), "--fleet", ctx.fleet,
                     "--ledger", ctx.ledger, "--out", draft2)
    assert rc1 == 0, out1
    rc, out = run(BIN, "approve", "--ledger", ctx.ledger, "--draft", draft2, "--diff-sha256", reviewed(ctx.ledger, draft2), "--approver-key", ctx.approver_key["carol"],
                  "--approver-id", "carol", "--head", head, "--out", d / "c2.approval")
    return rc == 0, out


def revised_v1(ctx, d):
    peers_dir = d / "v1-revised"
    peers_dir.mkdir()
    revised = d / "draft1-revised.bin"
    rc, out = run(BIN, "render", "--input", default_peers_toml(peers_dir, min_release=5), "--fleet", ctx.fleet,
                  "--ledger", ctx.ledger, "--out", revised)
    assert rc == 0, out
    return revised


def approve_carol(ctx, d, draft, out_name, head, *extra):
    return run(BIN, "approve", "--ledger", ctx.ledger, "--draft", draft, "--diff-sha256", reviewed(ctx.ledger, draft),
               "--approver-key", ctx.approver_key["carol"], "--approver-id", "carol", "--head", head,
               "--out", d / out_name, *extra)


def case_an_abandoned_draft_is_superseded_explicitly(d):
    """A draft approved and then abandoned (never signed) does not move the
    approver's ledger head; a revised draft for the same version is
    approved once the approver hands back the abandoned approval."""
    ctx = Ctx(d)
    head = d / "carol.head"
    ctx.approve("carol", ctx.draft1, head, out=d / "c1.approval")
    rc, out = approve_carol(ctx, d, revised_v1(ctx, d), "c1r.approval", head, "--supersede", d / "c1.approval")
    return rc == 0 and "superseding your approval of version 1" in out, out


def case_an_unsigned_earlier_approval_is_not_skipped_silently(d):
    """Without --supersede, an approval the ledger does not hold is refused:
    the ledger may have been cut below it (D11)."""
    ctx = Ctx(d)
    head = d / "carol.head"
    ctx.approve("carol", ctx.draft1, head, out=d / "c1.approval")
    revised, head_was = revised_v1(ctx, d), head.read_text()
    rc, out = approve_carol(ctx, d, revised, "c1r.approval", head)
    return approve_refused(rc, out, head, head_was, d / "c1r.approval", "which this ledger does not hold")


def case_a_truncated_replica_below_an_approved_version(d):
    """S2-1: v1 is approved and signed, then cut off the approver's replica,
    and a different v1 is drafted against v0: the approver's head (v0) still
    matches, but their recorded approval of v1 is missing, so approve
    refuses."""
    ctx = Ctx(d)
    head = d / "carol.head"
    ctx.approve("carol", ctx.draft1, head, out=d / "c1.approval")
    rc0, out0 = ctx.sign(ctx.draft1, [ctx.a1, ctx.b1], d / "slot1.bin")
    assert rc0 == 0, out0
    for f in sorted(ctx.ledger.rglob("*0000000001*"), reverse=True):
        f.unlink() if f.is_file() else shutil.rmtree(f)
    rc1, out1 = run(BIN, "verify", "--ledger", ctx.ledger, "--keys-pub", ctx.keys)
    assert rc1 == 0 and "version 0" in out1, out1
    revised, head_was = revised_v1(ctx, d), head.read_text()
    rc, out = approve_carol(ctx, d, revised, "c1r.approval", head)
    return approve_refused(rc, out, head, head_was, d / "c1r.approval", "if it was signed, this ledger is truncated")


def case_supersede_with_someone_elses_approval(d):
    ctx = Ctx(d)
    head = d / "carol.head"
    ctx.approve("carol", ctx.draft1, head, out=d / "c1.approval")
    revised, head_was = revised_v1(ctx, d), head.read_text()
    rc, out = approve_carol(ctx, d, revised, "c1r.approval", head, "--supersede", ctx.a1)
    return approve_refused(rc, out, head, head_was, d / "c1r.approval", "is not your approval of version 1")


def case_supersede_with_your_approval_of_another_body(d):
    """T3-4: carol's own approval, but of another body at v1 (approved with
    a separate head file), does not stand in for the one her head records."""
    ctx = Ctx(d)
    head = d / "carol.head"
    ctx.approve("carol", ctx.draft1, head, out=d / "c1.approval")
    revised = revised_v1(ctx, d)
    rc0, out0 = approve_carol(ctx, d, revised, "c1-other.approval", d / "carol-other.head")
    assert rc0 == 0, out0
    head_was = head.read_text()
    rc, out = approve_carol(ctx, d, revised, "c1r.approval", head, "--supersede", d / "c1-other.approval")
    return approve_refused(rc, out, head, head_was, d / "c1r.approval", "is not your approval of version 1")


def case_approve_with_a_stale_diff_digest(d):
    """S8: the digest an approver reviewed is this draft's diff against this
    ledger: the same draft's diff read against an older copy of the ledger
    (before v1) does not approve it against the current one, and nothing
    is written (no record, no head)."""
    ctx = Ctx(d)
    older = d / "ledger-at-v0"
    shutil.copytree(ctx.ledger, older)
    rc0, out0 = ctx.sign(ctx.draft1, [ctx.a1, ctx.b1], d / "slot1.bin")
    assert rc0 == 0, out0
    peers_dir = d / "v2"
    peers_dir.mkdir()
    draft2 = d / "draft2.bin"
    rc1, out1 = run(BIN, "render", "--input", default_peers_toml(peers_dir, min_release=2), "--fleet", ctx.fleet,
                     "--ledger", ctx.ledger, "--out", draft2)
    assert rc1 == 0, out1
    stale = reviewed(older, draft2)
    head = d / "carol.head"
    rc, out = run(BIN, "approve", "--ledger", ctx.ledger, "--draft", draft2, "--diff-sha256", stale,
                  "--approver-key", ctx.approver_key["carol"], "--approver-id", "carol", "--head", head,
                  "--out", d / "c2.approval")
    return rc != 0 and "is not this draft's diff against this ledger" in out and not (d / "c2.approval").exists() \
        and not head.exists(), out


def case_approve_without_a_head_file_argument(d):
    ctx = Ctx(d)
    rc, out = run(BIN, "approve", "--ledger", ctx.ledger, "--draft", ctx.draft1, "--diff-sha256",
                  reviewed(ctx.ledger, ctx.draft1), "--approver-key", ctx.approver_key["carol"],
                  "--approver-id", "carol", "--out", d / "c1.approval")
    return rc != 0 and "missing --head" in out and not (d / "c1.approval").exists(), out


def case_diff_shows_the_changed_peer(d):
    """S8: v1's diff names v1's changed item, not only body_sha256: the
    second peer's rp key changes, so its old line goes and its new one
    comes, while the first peer stays unchanged."""
    ctx = Ctx(d)
    peers_dir = d / "v1-rekey"
    peers_dir.mkdir()
    path = default_peers_toml(peers_dir)
    write_rp_key(peers_dir / "p2.pk", 9)
    draft = d / "rekey.bin"
    rc0, out0 = run(BIN, "render", "--input", path, "--fleet", ctx.fleet, "--ledger", ctx.ledger, "--out", draft)
    assert rc0 == 0, out0
    rc, out = run(BIN, "diff", "--ledger", ctx.ledger, "--draft", draft)
    p1, p2 = f"peer {wg_pub(1)} ", f"peer {wg_pub(2)} "
    lines = out.splitlines()
    ok = rc == 0 and sum(l.startswith("  " + p1) for l in lines) == 1 \
        and sum(l.startswith("- " + p2) for l in lines) == 1 and sum(l.startswith("+ " + p2) for l in lines) == 1
    return ok, out


def case_rp_digest_is_the_diffs_rp(d):
    """Runbook step 3: an approver checks each peer's `rp=` with `policy
    rp-digest` on that peer's key file; `approve` prints the same diff."""
    ctx = Ctx(d)
    rc0, diff = run(BIN, "diff", "--ledger", ctx.ledger, "--draft", ctx.draft1)
    line = next((l for l in diff.splitlines() if l.startswith(f"  peer {wg_pub(1)} ")), "")
    shown = re.search(r" rp=([0-9a-f]{64}) ", line)
    rc1, digest = run(BIN, "rp-digest", ctx.peers_dir1 / "p1.pk")
    short = d / "short.pk"
    short.write_bytes(bytes(10))
    rc2, refused = run(BIN, "rp-digest", short)
    rc3, approved = run(BIN, "approve", "--ledger", ctx.ledger, "--draft", ctx.draft1, "--diff-sha256",
                        reviewed(ctx.ledger, ctx.draft1), "--approver-key", ctx.approver_key["carol"],
                        "--approver-id", "carol", "--head", d / "carol.head", "--out", d / "c1.approval")
    ok = rc0 == 0 and shown is not None and rc1 == 0 and digest.strip() == shown.group(1) \
        and rc2 != 0 and f"not {SPK_LEN} bytes" in refused and rc3 == 0 and line in approved
    return ok, diff + digest + refused + approved


def case_overlap_with_one_node_of_fleet(d):
    """A peer's allowed IP overlaps node gw2's inside network only;
    `render` must refuse, naming that node."""
    ctx = Ctx(d)
    peers_dir = d / "overlap"
    peers_dir.mkdir()
    write_rp_key(peers_dir / "p1.pk", 1)
    text = peers_toml(peers_dir, peers=[{"n": 1, "rp": "p1.pk", "allowed": ["10.199.0.0/24"], "groups": []}], groups=[])
    peers_path = peers_dir / "peers.toml"
    peers_path.write_text(text)
    draft = d / "overlap_draft.bin"
    rc, out = run(BIN, "render", "--input", peers_path, "--fleet", ctx.fleet, "--ledger", ctx.ledger, "--out", draft)
    return rc != 0 and "node gw2" in out, out


def case_fleet_digest_differs(d):
    ctx = Ctx(d)
    text = ctx.fleet.read_text()
    text = re.sub(r'node_sha256 = "[0-9a-f]{64}"', lambda m: m.group(0)[:-3] + "00\"", text, count=1)
    ctx.fleet.write_text(text)
    rc, out = run(BIN, "render", "--input", d / "v1" / "peers.toml", "--fleet", ctx.fleet, "--ledger", ctx.ledger, "--out", d / "bad.bin")
    return rc != 0 and "does not match its stored node_sha256" in out, out


# --- the package's node digest (C2: the fleet file vs tools/package) --------

MLDSA65_PUB_LEN = 1952


def with_policy(gateway: pathlib.Path, fleet_id: str = FLEET_ID) -> None:
    """The [policy] section a provisioned node's gateway.toml carries (the
    image compiles its fleet_id in); keys and Names are stand-ins."""
    (gateway.parent / "mldsa65.pub").write_bytes(bytes([1]) * MLDSA65_PUB_LEN)
    with gateway.open("a") as f:
        f.write(f'\n[policy]\nfleet_id = "{fleet_id}"\ned25519_pub = "{"11" * 32}"\nmldsa65_pub = "mldsa65.pub"\n'
                f'nv_ctr_name = "000b{"aa" * 32}"\nnv_base_name = "000b{"bb" * 32}"\n')


def node_digest(d: pathlib.Path, gateway: pathlib.Path) -> tuple:
    out = d / f"{gateway.stem}.node.sha256"
    rc, o = run(BIN, "node-digest", "--out", out, gateway)
    return rc, o, out


def case_package_node_in_fleet(d):
    """Allow: the digest node-digest records for gw1 (as tools/package does)
    is the fleet file's node_sha256 for gw1, so verify accepts it, alone
    and beside a slot check."""
    ctx = Ctx(d)
    with_policy(ctx.gw1)
    rc, out, digest = node_digest(d, ctx.gw1)
    if rc != 0:
        return False, out
    stored = [n["node_sha256"] for n in tomllib.loads(ctx.fleet.read_text())["node"] if n["name"] == "gw1"]
    same = digest.read_text() in [h + "\n" for h in stored]
    rc1, out1 = run(BIN, "verify", "--fleet", ctx.fleet, "--package-node", digest)
    rc2, out2 = run(BIN, "verify", "--keys-pub", ctx.keys, "--slot", ctx.slot0, "--fleet", ctx.fleet, "--package-node", digest)
    ok = same and rc1 == 0 and "node is gw1" in out1 and rc2 == 0 and "node is gw1" in out2
    return ok, out + out1 + out2 + ("" if same else "node-digest differs from the fleet file's node_sha256")


def case_package_node_differs(d):
    """Deny: gw1's gateway.toml changed after the fleet file was made (its
    outside address), so the package's digest is no fleet node's."""
    ctx = Ctx(d)
    ctx.gw1.write_text(ctx.gw1.read_text().replace('outside_ip = "10.0.2.15"', 'outside_ip = "10.0.2.16"'))
    with_policy(ctx.gw1)
    rc, out, digest = node_digest(d, ctx.gw1)
    if rc != 0:
        return False, out
    rc1, out1 = run(BIN, "verify", "--fleet", ctx.fleet, "--package-node", digest)
    rc2, out2 = run(BIN, "verify", "--keys-pub", ctx.keys, "--slot", ctx.slot0, "--fleet", ctx.fleet, "--package-node", digest)
    msg = "is no node's in the fleet file"
    return rc1 != 0 and msg in out1 and rc2 != 0 and msg in out2, out1 + out2


def case_fleet_refuses_a_node_of_another_fleet(d):
    """A provisioned node's gateway.toml names its own fleet_id; `fleet`
    refuses to stamp it with another (its image would refuse every bundle)."""
    ctx = Ctx(d)
    with_policy(ctx.gw1, fleet_id="cd" * 16)
    rc, out = run(BIN, "fleet", "--out", d / "fleet2.toml", "--fleet-id", FLEET_ID, ctx.gw1, ctx.gw2)
    return rc != 0 and "[policy] fleet_id" in out and not (d / "fleet2.toml").exists(), out


def case_fleet_takes_a_node_of_this_fleet(d):
    ctx = Ctx(d)
    with_policy(ctx.gw1)
    rc, out = run(BIN, "fleet", "--out", d / "fleet2.toml", "--fleet-id", FLEET_ID, ctx.gw1, ctx.gw2)
    return rc == 0, out


def case_node_digest_without_policy(d):
    """Deny: a gateway.toml without [policy] compiles a zero fleet_id and
    keys into its image, which accepts no bundle; node-digest refuses it."""
    ctx = Ctx(d)
    rc, out, digest = node_digest(d, ctx.gw1)
    return rc != 0 and "no [policy] section" in out and not digest.exists(), out


# --- restore fixtures ------------------------------------------------------

def case_restore_allow(d):
    ctx = Ctx(d)
    rc0, out0 = ctx.sign(ctx.draft1, [ctx.a1, ctx.b1], d / "slot1.bin")
    assert rc0 == 0, out0
    r1 = d / "r1.approval"
    r2 = d / "r2.approval"
    rc1, out1 = run(BIN, "ledger", "approve-restore", "--head", blank_head(d / "restore-2.head"), "--from", ctx.ledger, "--approver-key", ctx.approver_key["alice"],
                     "--approver-id", "alice", "--out", r1)
    rc2, out2 = run(BIN, "ledger", "approve-restore", "--head", blank_head(d / "restore-3.head"), "--from", ctx.ledger, "--approver-key", ctx.approver_key["bob"],
                     "--approver-id", "bob", "--out", r2)
    assert rc1 == 0 and rc2 == 0, out1 + out2
    restored = d / "restored"
    rc, out = run(BIN, "ledger", "restore", "--from", ctx.ledger, "--dir", restored, "--approvals", r1, r2,
                  "--keys-pub", ctx.keys)
    rc3, out3 = run(BIN, "verify", "--ledger", restored, "--keys-pub", ctx.keys)
    return rc == 0 and rc3 == 0 and "version 1" in out3, out + out3


def case_restore_missing_approver_head(d):
    """A replica behind an approver's own recorded head is refused."""
    ctx = Ctx(d)
    stale_copy = d / "stale-copy"
    import shutil
    shutil.copytree(ctx.ledger, stale_copy)  # only has version 0 at this point
    rc0, out0 = ctx.sign(ctx.draft1, [ctx.a1, ctx.b1], d / "slot1.bin")
    assert rc0 == 0, out0
    ahead_head = d / "ahead.head"
    ahead_head.write_text("approved_body_sha256=-\napproved_version=-\nbody_sha256=" + "ab" * 32 + "\nversion=1\n")
    r1 = d / "r1.approval"
    r2 = d / "r2.approval"
    run(BIN, "ledger", "approve-restore", "--head", blank_head(d / "restore-4.head"), "--from", stale_copy, "--approver-key", ctx.approver_key["alice"], "--approver-id", "alice", "--out", r1)
    run(BIN, "ledger", "approve-restore", "--head", blank_head(d / "restore-5.head"), "--from", stale_copy, "--approver-key", ctx.approver_key["bob"], "--approver-id", "bob", "--out", r2)
    rc, out = run(BIN, "ledger", "restore", "--from", stale_copy, "--dir", d / "restored", "--approvals", r1, r2,
                  "--keys-pub", ctx.keys, "--head", ahead_head)
    return rc != 0 and "behind the head" in out, out


def case_restore_approval_under_bundle_domain(d):
    ctx = Ctx(d)
    rc, out = run(BIN, "ledger", "restore", "--from", ctx.ledger, "--dir", d / "restored", "--approvals", ctx.a1, ctx.b1,
                  "--keys-pub", ctx.keys)
    return rc != 0 and "record key body_sha256 is unknown" in out, out


def case_restore_below_recorded_head(d):
    ctx = Ctx(d)
    rc0, out0 = ctx.sign(ctx.draft1, [ctx.a1, ctx.b1], d / "slot1.bin")
    assert rc0 == 0, out0
    ahead_head = d / "ahead.head"
    ahead_head.write_text("approved_body_sha256=-\napproved_version=-\nbody_sha256=" + "ab" * 32 + "\nversion=5\n")
    r1 = d / "r1.approval"
    r2 = d / "r2.approval"
    run(BIN, "ledger", "approve-restore", "--head", blank_head(d / "restore-6.head"), "--from", ctx.ledger, "--approver-key", ctx.approver_key["alice"], "--approver-id", "alice", "--out", r1)
    run(BIN, "ledger", "approve-restore", "--head", blank_head(d / "restore-7.head"), "--from", ctx.ledger, "--approver-key", ctx.approver_key["bob"], "--approver-id", "bob", "--out", r2)
    rc, out = run(BIN, "ledger", "restore", "--from", ctx.ledger, "--dir", d / "restored", "--approvals", r1, r2,
                  "--keys-pub", ctx.keys, "--head", ahead_head)
    return rc != 0 and "behind the head" in out, out


def v0_copy_after_v1(ctx, d):
    """carol approves v1 (her head records it), v1 is signed, and a copy of
    the ledger cut back to v0 is offered for restore."""
    head = d / "carol.head"
    ctx.approve("carol", ctx.draft1, head, out=d / "c1.approval")
    rc0, out0 = ctx.sign(ctx.draft1, [ctx.a1, ctx.b1], d / "slot1.bin")
    assert rc0 == 0, out0
    copy = d / "copy"
    shutil.copytree(ctx.ledger, copy)
    for f in sorted(copy.rglob("*0000000001*"), reverse=True):
        f.unlink() if f.is_file() else shutil.rmtree(f)
    return copy, head


def carol_approves_restore(ctx, d, copy, head, *extra):
    return run(BIN, "ledger", "approve-restore", "--from", copy, "--approver-key", ctx.approver_key["carol"],
               "--approver-id", "carol", "--head", head, "--out", d / "rc.approval", *extra)


def case_restore_below_an_approved_version(d):
    """S3-1: carol, on her own device, refuses to approve restoring a copy
    that lacks v1, which she approved and which was signed."""
    ctx = Ctx(d)
    copy, head = v0_copy_after_v1(ctx, d)
    rc, out = carol_approves_restore(ctx, d, copy, head)
    return rc != 0 and "does not hold: if it was signed, this ledger is truncated" in out \
        and not (d / "rc.approval").exists(), out


def case_restore_with_the_approval_superseded(d):
    """The allow twin: carol hands back her own approval (by her account the
    draft was abandoned), and approves restoring the same copy."""
    ctx = Ctx(d)
    copy, head = v0_copy_after_v1(ctx, d)
    rc, out = carol_approves_restore(ctx, d, copy, head, "--supersede", d / "c1.approval")
    ra = d / "ra.approval"
    rc1, out1 = run(BIN, "ledger", "approve-restore", "--from", copy, "--approver-key", ctx.approver_key["alice"],
                    "--approver-id", "alice", "--head", blank_head(d / "alice-r.head"), "--out", ra)
    # carol's head now names the copy's head, so restore takes it.
    rc2, out2 = run(BIN, "ledger", "restore", "--from", copy, "--dir", d / "restored", "--approvals", d / "rc.approval", ra,
                    "--keys-pub", ctx.keys, "--head", head)
    return rc == 0 and rc1 == 0 and rc2 == 0, out + out1 + out2


def case_restore_refuses_a_given_head_with_a_newer_approval(d):
    """S4-1: v1 is approved by alice and bob and signed; the copy is cut back
    to v0; carol and dave (heads that predate v1) approve the restore. bob's
    head, passed to restore, records his approval of v1: refused."""
    ctx = Ctx(d)
    copy, _ = v0_copy_after_v1(ctx, d)
    approvals = []
    for who in ("carol", "alice"):
        out = d / f"r-{who}.approval"
        rc, o = run(BIN, "ledger", "approve-restore", "--from", copy, "--approver-key", ctx.approver_key[who],
                    "--approver-id", who, "--head", blank_head(d / f"{who}-blank.head"), "--out", out)
        assert rc == 0, o
        approvals.append(out)
    rc, out = run(BIN, "ledger", "restore", "--from", copy, "--dir", d / "restored", "--approvals", *approvals,
                  "--keys-pub", ctx.keys, "--head", d / "bob1.head")
    return rc != 0 and "records an approval of version 1, which the copy (version 0) does not hold" in out \
        and not (d / "restored").exists(), out


def case_approve_restore_without_a_head_file(d):
    """S4-2: an approver without a head file has nothing to check the copy
    against, so cannot vouch for a restore."""
    ctx = Ctx(d)
    rc, out = run(BIN, "ledger", "approve-restore", "--from", ctx.ledger, "--approver-key", ctx.approver_key["alice"],
                  "--approver-id", "alice", "--head", d / "no-such.head", "--out", d / "r.approval")
    return rc != 0 and "no head file at" in out and not (d / "r.approval").exists(), out


def case_restore_supersede_with_someone_elses_approval(d):
    """S3-1/F3-1: an approval of v1 found in any replica (alice's) does not
    stand in for carol's own."""
    ctx = Ctx(d)
    copy, head = v0_copy_after_v1(ctx, d)
    rc, out = carol_approves_restore(ctx, d, copy, head, "--supersede", ctx.a1)
    return rc != 0 and "is not your approval of version 1" in out and not (d / "rc.approval").exists(), out


def case_reapproving_the_same_draft(d):
    """F3-2: the same draft approved again (a lost approval file) needs no
    --supersede."""
    ctx = Ctx(d)
    head = d / "carol.head"
    ctx.approve("carol", ctx.draft1, head, out=d / "c1.approval")
    rc, out = approve_carol(ctx, d, ctx.draft1, "c1-again.approval", head)
    return rc == 0, out


def case_unneeded_supersede(d):
    ctx = Ctx(d)
    head = d / "carol.head"
    ctx.approve("carol", ctx.draft1, head, out=d / "c1.approval")
    head_was = head.read_text()
    rc, out = approve_carol(ctx, d, ctx.draft1, "c1-again.approval", head, "--supersede", d / "c1.approval")
    return approve_refused(rc, out, head, head_was, d / "c1-again.approval", "nothing recorded needs superseding")


def case_approve_to_an_existing_out(d):
    """S3-3/T4-3: an existing --out is refused before the head moves (the
    head records v0, so approving v1 would visibly change it)."""
    ctx = Ctx(d)
    head = d / "carol.head"
    ctx.approve("carol", ctx.draft0, head, out=d / "c0.approval")
    taken = d / "taken.approval"
    taken.write_text("someone else's file\n")
    head_was = head.read_text()
    rc, out = approve_carol(ctx, d, ctx.draft1, "taken.approval", head)
    return rc != 0 and f"{taken}:" in out and head.read_text() == head_was \
        and taken.read_text() == "someone else's file\n", out


def fork_v1(ctx, d):
    """carol approves v1 (draft1); alice and bob approve and sign a revised
    v1 instead: the ledger holds another body at carol's approved version."""
    head = d / "carol.head"
    ctx.approve("carol", ctx.draft1, head, out=d / "c1.approval")
    revised = revised_v1(ctx, d)
    ar = ctx.approve("alice", revised, d / "alice-r.head", out=d / "ar.approval")
    br = ctx.approve("bob", revised, d / "bob-r.head", out=d / "br.approval")
    rc, out = ctx.sign(revised, [ar, br], d / "slot1r.bin")
    assert rc == 0, out
    return head


def case_approve_restore_of_a_forked_ledger(d):
    """S3-2/T4-1: the ledger holds another body at carol's approved version:
    refused as forked, until she supersedes her approval."""
    ctx = Ctx(d)
    head = fork_v1(ctx, d)
    rc, out = carol_approves_restore(ctx, d, ctx.ledger, head)
    rc2, out2 = carol_approves_restore(ctx, d, ctx.ledger, head, "--supersede", d / "c1.approval")
    ok = rc != 0 and "this ledger is forked" in out and rc2 == 0 and (d / "rc.approval").exists()
    return ok, out + out2


def case_approve_after_a_fork_at_the_approved_version(d):
    """S3-2/T4-1 through approve: carol drafts v2 on the forked ledger and is
    refused (nothing written) until she hands back her v1 approval."""
    ctx = Ctx(d)
    head = fork_v1(ctx, d)
    peers_dir = d / "v2"
    peers_dir.mkdir()
    draft2 = d / "draft2.bin"
    rc0, out0 = run(BIN, "render", "--input", default_peers_toml(peers_dir, min_release=2), "--fleet", ctx.fleet,
                     "--ledger", ctx.ledger, "--out", draft2)
    assert rc0 == 0, out0
    head_was = head.read_text()
    rc, out = approve_carol(ctx, d, draft2, "c2.approval", head)
    refused, why = approve_refused(rc, out, head, head_was, d / "c2.approval", "this ledger is forked")
    rc2, out2 = approve_carol(ctx, d, draft2, "c2.approval", head, "--supersede", d / "c1.approval")
    return refused and rc2 == 0, why + out2


def case_approve_restore_with_a_satisfied_head(d):
    """T4-2: the common recovery: carol's head (v1 approved and signed) is
    held by the copy, so she approves the restore with nothing to hand back,
    and her head then names the copy's head."""
    ctx = Ctx(d)
    head = d / "carol.head"
    ctx.approve("carol", ctx.draft1, head, out=d / "c1.approval")
    rc0, out0 = ctx.sign(ctx.draft1, [ctx.a1, ctx.b1], d / "slot1.bin")
    assert rc0 == 0, out0
    rc, out = carol_approves_restore(ctx, d, ctx.ledger, head)
    rewritten = "approved_version=-" in head.read_text() and "version=1" in head.read_text()
    return rc == 0 and (d / "rc.approval").exists() and rewritten, out + head.read_text()


def case_single_restore_approval(d):
    ctx = Ctx(d)
    r1 = d / "r1.approval"
    run(BIN, "ledger", "approve-restore", "--head", blank_head(d / "restore-8.head"), "--from", ctx.ledger, "--approver-key", ctx.approver_key["alice"], "--approver-id", "alice", "--out", r1)
    rc, out = run(BIN, "ledger", "restore", "--from", ctx.ledger, "--dir", d / "restored", "--approvals", r1,
                  "--keys-pub", ctx.keys)
    return rc != 0 and "at least two" in out, out


def case_same_restore_approver_twice(d):
    ctx = Ctx(d)
    r1 = d / "r1.approval"
    run(BIN, "ledger", "approve-restore", "--head", blank_head(d / "restore-9.head"), "--from", ctx.ledger, "--approver-key", ctx.approver_key["alice"], "--approver-id", "alice", "--out", r1)
    rc, out = run(BIN, "ledger", "restore", "--from", ctx.ledger, "--dir", d / "restored", "--approvals", r1, r1,
                  "--keys-pub", ctx.keys)
    return rc != 0 and "approved twice" in out, out


def case_restore_approver_not_in_roster(d):
    ctx = Ctx(d)
    r1 = d / "r1.approval"
    r2 = d / "r2.approval"
    run(BIN, "ledger", "approve-restore", "--head", blank_head(d / "restore-10.head"), "--from", ctx.ledger, "--approver-key", ctx.approver_key["alice"], "--approver-id", "alice", "--out", r1)
    run(BIN, "ledger", "approve-restore", "--head", blank_head(d / "restore-11.head"), "--from", ctx.ledger, "--approver-key", ctx.approver_key["dave"], "--approver-id", "dave", "--out", r2)
    rc, out = run(BIN, "ledger", "restore", "--from", ctx.ledger, "--dir", d / "restored", "--approvals", r1, r2,
                  "--keys-pub", ctx.keys)
    return rc != 0 and "is not in the roster" in out, out


def case_removed_by_roster_change_approver(d):
    """Carol is in the genesis roster; version 1 changes the roster to
    drop her. A restore approval she signs for the (post-change) head must
    be refused: she is no longer in the roster in force there."""
    ctx = Ctx(d)
    new_roster = d / "new-roster.toml"
    new_roster.write_text(roster_toml({"alice": pubkey(d, "alice"), "bob": pubkey(d, "bob")}))
    rc0, out0 = run(BIN, "render", "--input", d / "v1" / "peers.toml", "--fleet", ctx.fleet, "--ledger", ctx.ledger,
                     "--out", d / "draft1_rc.bin", "--set-roster", new_roster)
    assert rc0 == 0, out0
    a = ctx.approve("alice", d / "draft1_rc.bin", d / "a.head", out=d / "a_rc.approval")
    b = ctx.approve("bob", d / "draft1_rc.bin", d / "b.head", out=d / "b_rc.approval")
    rc1, out1 = run(BIN, "sign", "--ledger", ctx.ledger, "--draft", d / "draft1_rc.bin", "--approvals", a, b,
                     "--keys", ctx.keys, "--out", d / "slot1_rc.bin", "--new-roster", new_roster)
    assert rc1 == 0, out1
    carol_restore = d / "carol.approval"
    rc2, out2 = run(BIN, "ledger", "approve-restore", "--head", blank_head(d / "restore-12.head"), "--from", ctx.ledger, "--approver-key", ctx.approver_key["carol"],
                     "--approver-id", "carol", "--out", carol_restore)
    assert rc2 == 0, out2
    alice_restore = d / "alice.approval"
    run(BIN, "ledger", "approve-restore", "--head", blank_head(d / "restore-13.head"), "--from", ctx.ledger, "--approver-key", ctx.approver_key["alice"], "--approver-id", "alice", "--out", alice_restore)
    rc, out = run(BIN, "ledger", "restore", "--from", ctx.ledger, "--dir", d / "restored", "--approvals", carol_restore, alice_restore,
                  "--keys-pub", ctx.keys)
    return rc != 0 and "is not in the roster" in out, out


def case_restore_approval_bound_to_another_head(d):
    ctx = Ctx(d)
    # A restore approval signed against the ledger while it was still at
    # version 0 (an earlier, legitimately-reached head).
    stale_restore = d / "stale.approval"
    run(BIN, "ledger", "approve-restore", "--head", blank_head(d / "restore-14.head"), "--from", ctx.ledger, "--approver-key", ctx.approver_key["alice"], "--approver-id", "alice", "--out", stale_restore)
    rc0, out0 = ctx.sign(ctx.draft1, [ctx.a1, ctx.b1], d / "slot1.bin")
    assert rc0 == 0, out0
    fresh_restore = d / "fresh.approval"
    run(BIN, "ledger", "approve-restore", "--head", blank_head(d / "restore-15.head"), "--from", ctx.ledger, "--approver-key", ctx.approver_key["bob"], "--approver-id", "bob", "--out", fresh_restore)
    rc, out = run(BIN, "ledger", "restore", "--from", ctx.ledger, "--dir", d / "restored", "--approvals", stale_restore, fresh_restore,
                  "--keys-pub", ctx.keys)
    return rc != 0 and "bound to head version" in out, out


def case_restore_approval_bound_to_another_fleet(d):
    ctx = Ctx(d)
    other = d / "other"
    other.mkdir()
    # Same roster and version, so only the fleet binding differs.
    other_ctx = Ctx(other, fleet_id="cd" * 16)
    other_restore = other / "r.approval"
    run(BIN, "ledger", "approve-restore", "--head", blank_head(d / "restore-16.head"), "--from", other_ctx.ledger, "--approver-key", other_ctx.approver_key["alice"], "--approver-id", "alice", "--out", other_restore)
    alice_restore = d / "alice.approval"
    run(BIN, "ledger", "approve-restore", "--head", blank_head(d / "restore-17.head"), "--from", ctx.ledger, "--approver-key", ctx.approver_key["bob"], "--approver-id", "bob", "--out", alice_restore)
    rc, out = run(BIN, "ledger", "restore", "--from", ctx.ledger, "--dir", d / "restored", "--approvals", other_restore, alice_restore,
                  "--keys-pub", ctx.keys)
    return rc != 0 and "another fleet_id" in out, out


CASES = [
    ("version 1 is drafted, approved, signed and verifies (allow)", case_allow_sign_v1),
    ("a payload swapped after approval is refused", case_payload_swapped_after_approval),
    ("the same approver twice is refused", case_same_approver_twice),
    ("one approval only is refused", case_one_approval_only),
    ("rp-digest prints the rp= that diff and approve show", case_rp_digest_is_the_diffs_rp),
    ("restore below an approved version is refused", case_restore_below_an_approved_version),
    ("restore with that approval superseded", case_restore_with_the_approval_superseded),
    ("restore refuses a given head with a newer approval", case_restore_refuses_a_given_head_with_a_newer_approval),
    ("approve-restore needs a head file", case_approve_restore_without_a_head_file),
    ("restore supersede with someone else's approval is refused", case_restore_supersede_with_someone_elses_approval),
    ("re-approving the same draft needs no supersede", case_reapproving_the_same_draft),
    ("an unneeded supersede is refused", case_unneeded_supersede),
    ("approve to an existing --out is refused before the head moves", case_approve_to_an_existing_out),
    ("approve-restore of a forked ledger needs a supersede", case_approve_restore_of_a_forked_ledger),
    ("approve after a fork at the approved version needs a supersede", case_approve_after_a_fork_at_the_approved_version),
    ("approve-restore with a satisfied head", case_approve_restore_with_a_satisfied_head),
    ("fleet refuses a provisioned node of another fleet", case_fleet_refuses_a_node_of_another_fleet),
    ("fleet takes a provisioned node of this fleet", case_fleet_takes_a_node_of_this_fleet),
    ("approve refuses a stale reviewed diff digest", case_approve_with_a_stale_diff_digest),
    ("approve needs --head", case_approve_without_a_head_file_argument),
    ("diff shows the changed peer, not only body_sha256", case_diff_shows_the_changed_peer),
    ("a head file follows the ledger across versions", case_head_file_follows_the_ledger_across_versions),
    ("an abandoned draft is superseded explicitly", case_an_abandoned_draft_is_superseded_explicitly),
    ("an earlier approval the ledger lacks is not skipped silently", case_an_unsigned_earlier_approval_is_not_skipped_silently),
    ("a truncated replica below an approved version is refused", case_a_truncated_replica_below_an_approved_version),
    ("supersede with someone else's approval is refused", case_supersede_with_someone_elses_approval),
    ("supersede with your approval of another body is refused", case_supersede_with_your_approval_of_another_body),
    ("an approver not in the roster is refused", case_approver_not_in_roster),
    ("a forged approval signature is refused", case_forged_approval_signature),
    ("a restore record used as a bundle approval is refused (wrong domain)", case_wrong_approval_domain),
    ("an approval bound to another version is refused", case_record_for_another_version),
    ("an approval bound to another fleet_id is refused", case_record_for_another_fleet),
    ("an approval bound to another prev_sha256 is refused", case_record_for_another_prev),
    ("an approval bound to another roster_sha256 is refused", case_record_for_another_roster),
    ("an approval bound to another diff is refused", case_record_for_another_diff),
    ("a version equal to the ledger head is refused", case_version_equal_to_head),
    ("a version far below the ledger head is refused", case_version_below_head),
    ("a version that skips ahead is refused", case_version_skips),
    ("a genesis draft signed against a non-empty ledger is refused", case_genesis_with_nonempty_ledger),
    ("prev_sha256 not the ledger head is refused", case_prev_not_ledger_head),
    ("a second body for an already-signed version is refused", case_second_body_for_signed_version),
    ("a tampered roster file is refused", case_tampered_roster),
    ("a truncated ledger is refused", case_truncated_ledger),
    ("re-running ledger init on an existing ledger is refused", case_re_genesis),
    ("a broken chain link is refused", case_broken_chain_link),
    ("an approver head ahead of the ledger is refused", case_approver_head_ahead_of_ledger),
    ("an approver head at the same version with a different digest is refused", case_approver_head_same_version_different_digest),
    ("a peer overlapping one fleet node's network is refused", case_overlap_with_one_node_of_fleet),
    ("a tampered fleet digest is refused", case_fleet_digest_differs),
    ("a package node digest equal to the fleet file's (allow)", case_package_node_in_fleet),
    ("a package node digest differing from the fleet file's is refused", case_package_node_differs),
    ("node-digest refuses a gateway.toml without [policy]", case_node_digest_without_policy),
    ("a verified ledger restore (allow)", case_restore_allow),
    ("restoring from a replica missing an approver's head is refused", case_restore_missing_approver_head),
    ("a bundle approval used as a restore approval is refused", case_restore_approval_under_bundle_domain),
    ("restoring below a recorded approver head is refused", case_restore_below_recorded_head),
    ("a single restore approval is refused", case_single_restore_approval),
    ("the same restore approver twice is refused", case_same_restore_approver_twice),
    ("a restore approver not in the roster is refused", case_restore_approver_not_in_roster),
    ("a restore approval from an approver removed by a roster change is refused", case_removed_by_roster_change_approver),
    ("a restore approval bound to another head version is refused", case_restore_approval_bound_to_another_head),
    ("a restore approval bound to another fleet is refused", case_restore_approval_bound_to_another_fleet),
]


def main() -> int:
    global BIN, APPROVERS
    base = build_binary()
    session = pathlib.Path(tempfile.mkdtemp(prefix="policy-approvers-"))
    try:
        for a in ("alice", "bob", "carol", "dave"):
            rc, out = run(base, "approver-keygen", "--dir", session / a, "--forbid", ROOT)
            assert rc == 0, out
        roster = session / "roster.toml"
        roster.write_text(roster_toml({a: pubkey(session, a) for a in ("alice", "bob", "carol")}))
        rc, out = run(base, "roster-digest", roster)
        assert rc == 0, out
        # The unpinned build refuses this roster (its pin is the zero
        # placeholder): the pin is a build input, not something a run can set.
        rc, out = run(base, "ledger", "init", "--dir", session / "ledger", "--genesis-roster", roster)
        assert rc != 0 and "pin" in out, f"the unpinned build accepted a genesis roster: {out}"
        APPROVERS = session
        BIN = build_binary(_digest(base, roster))
        return run_cases()
    finally:
        shutil.rmtree(session, ignore_errors=True)


def _digest(binary: pathlib.Path, roster: pathlib.Path) -> str:
    rc, out = run(binary, "roster-digest", roster)
    assert rc == 0, out
    return out.strip()


def run_cases() -> int:
    failures = 0
    for name, case in CASES:
        with tempfile.TemporaryDirectory(prefix="policy-fixture-") as d:
            try:
                ok, out = case(pathlib.Path(d))
            except AssertionError as e:
                ok, out = False, f"setup failed: {e}"
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f": {out.strip()[-400:]}"))
    print(f"POLICY-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
