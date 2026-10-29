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
        rc, o = run(BIN, "approve", "--ledger", self.ledger, "--draft", draft, "--approver-key", self.approver_key[approver],
                    "--approver-id", approver, "--head", head, "--out", out)
        assert rc == 0, o
        return out

    def sign(self, draft: pathlib.Path, approvals: list, out: pathlib.Path) -> tuple:
        return run(BIN, "sign", "--ledger", self.ledger, "--draft", draft, "--approvals", *approvals, "--keys", self.keys, "--out", out)

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
    out_slot = d / "slot_swapped.bin"
    rc, out = ctx.sign(swapped, [ctx.a1, ctx.b1], out_slot)
    return rc != 0 and "another body" in out, out


def case_same_approver_twice(d):
    ctx = Ctx(d)
    rc, out = ctx.sign(ctx.draft1, [ctx.a1, ctx.a1], d / "slot.bin")
    return rc != 0 and "approved twice" in out, out


def case_one_approval_only(d):
    ctx = Ctx(d)
    rc, out = ctx.sign(ctx.draft1, [ctx.a1], d / "slot.bin")
    return rc != 0 and "at least two" in out, out


def case_approver_not_in_roster(d):
    ctx = Ctx(d)
    mallory = ctx.approve("dave", ctx.draft1, d / "dave.head", out=d / "dave.approval")
    rc, out = ctx.sign(ctx.draft1, [ctx.a1, mallory], d / "slot.bin")
    return rc != 0 and "is not in the roster" in out, out


def case_forged_approval_signature(d):
    ctx = Ctx(d)
    forged = d / "forged.approval"
    b = bytearray(ctx.a1.read_bytes())
    # Inside the trailing sig_ed25519 hex line: another valid hex digit, so
    # the record still parses and only the signature is wrong.
    b[-5] = ord("1") if b[-5] != ord("1") else ord("2")
    forged.write_bytes(bytes(b))
    rc, out = ctx.sign(ctx.draft1, [forged, ctx.b1], d / "slot.bin")
    return rc != 0 and "signature does not verify" in out, out


def case_wrong_approval_domain(d):
    """A restore-approval record (its own domain and field set) handed to
    `sign` as if it were a bundle approval. A same-fields/wrong-domain
    forgery is proved directly in src/tests.rs, where the signing
    primitive is reachable; the CLI never signs an approval under the
    wrong domain to hand it one."""
    ctx = Ctx(d)
    restore = d / "restore.approval"
    rc0, out0 = run(BIN, "ledger", "approve-restore", "--from", ctx.ledger, "--approver-key", ctx.approver_key["alice"],
                     "--approver-id", "alice", "--out", restore)
    assert rc0 == 0, out0
    rc, out = ctx.sign(ctx.draft1, [restore, ctx.b1], d / "slot.bin")
    return rc != 0 and "record key head_body_sha256 is unknown" in out, out


def case_record_for_another_version(d):
    ctx = Ctx(d)
    bumped = ctx.tampered_copy(ctx.draft1, "bumped.bin", VERSION_AT, 4, (2).to_bytes(4, "big"))
    a_bumped = ctx.approve("alice", bumped, d / "alice_b.head", out=d / "a_bumped.approval")
    rc, out = ctx.sign(ctx.draft1, [a_bumped, ctx.b1], d / "slot.bin")
    return rc != 0 and "bound to version" in out, out


def case_record_for_another_fleet(d):
    ctx = Ctx(d)
    other_fleet = bytes.fromhex("cd" * 16)
    bumped = ctx.tampered_copy(ctx.draft1, "otherfleet.bin", FLEET_ID_AT, FLEET_ID_LEN, other_fleet)
    a_bumped = ctx.approve("alice", bumped, d / "alice_f.head", out=d / "a_fleet.approval")
    rc, out = ctx.sign(ctx.draft1, [a_bumped, ctx.b1], d / "slot.bin")
    return rc != 0 and "another fleet_id" in out, out


def case_record_for_another_prev(d):
    ctx = Ctx(d)
    bumped = ctx.tampered_copy(ctx.draft1, "otherprev.bin", PREV_SHA256_AT, PREV_SHA256_LEN, bytes([0x55] * PREV_SHA256_LEN))
    a_bumped = ctx.approve("alice", bumped, d / "alice_p.head", out=d / "a_prev.approval")
    rc, out = ctx.sign(ctx.draft1, [a_bumped, ctx.b1], d / "slot.bin")
    return rc != 0 and "another prev_sha256" in out, out


def case_record_for_another_roster(d):
    ctx = Ctx(d)
    bumped = ctx.tampered_copy(ctx.draft1, "otherroster.bin", ROSTER_SHA256_AT, ROSTER_SHA256_LEN, bytes([0x66] * ROSTER_SHA256_LEN))
    a_bumped = ctx.approve("alice", bumped, d / "alice_r.head", out=d / "a_roster.approval")
    rc, out = ctx.sign(ctx.draft1, [a_bumped, ctx.b1], d / "slot.bin")
    return rc != 0 and "another roster_sha256" in out, out


def case_record_for_another_diff(d):
    """`approve` run against a different (empty) ledger computes the diff
    against "no previous bundle" instead of the real v0, so the recorded
    diff_sha256 disagrees with what `sign` recomputes, even though every
    other field matches the real draft."""
    ctx = Ctx(d)
    other_ledger = d / "other-ledger"
    rc0, out0 = run(BIN, "ledger", "init", "--dir", other_ledger, "--genesis-roster", ctx.roster_path)
    assert rc0 == 0, out0
    rc1, out1 = run(BIN, "approve", "--ledger", other_ledger, "--draft", ctx.draft1, "--approver-key", ctx.approver_key["alice"],
                     "--approver-id", "alice", "--out", d / "a_diff.approval")
    assert rc1 == 0, out1
    rc, out = ctx.sign(ctx.draft1, [d / "a_diff.approval", ctx.b1], d / "slot.bin")
    return rc != 0 and "another diff" in out, out


def case_version_equal_to_head(d):
    ctx = Ctx(d)
    bumped = ctx.tampered_copy(ctx.draft1, "v0again.bin", VERSION_AT, 4, (0).to_bytes(4, "big"))
    a = ctx.approve("alice", bumped, d / "a.head", out=d / "a_eq.approval")
    b = ctx.approve("bob", bumped, d / "b.head", out=d / "b_eq.approval")
    rc, out = ctx.sign(bumped, [a, b], d / "slot.bin")
    return rc != 0 and "does not match the ledger head+1" in out, out


def case_version_below_head(d):
    """A version that underflows below any sane head (max u32) — the same
    head+1 guard as "equal", exercised at the other boundary."""
    ctx = Ctx(d)
    bumped = ctx.tampered_copy(ctx.draft1, "vhigh.bin", VERSION_AT, 4, (0xFFFFFFFF).to_bytes(4, "big"))
    a = ctx.approve("alice", bumped, d / "a.head", out=d / "a_lo.approval")
    b = ctx.approve("bob", bumped, d / "b.head", out=d / "b_lo.approval")
    rc, out = ctx.sign(bumped, [a, b], d / "slot.bin")
    return rc != 0 and "does not match the ledger head+1" in out, out


def case_version_skips(d):
    ctx = Ctx(d)
    bumped = ctx.tampered_copy(ctx.draft1, "v2.bin", VERSION_AT, 4, (2).to_bytes(4, "big"))
    a = ctx.approve("alice", bumped, d / "a.head", out=d / "a_sk.approval")
    b = ctx.approve("bob", bumped, d / "b.head", out=d / "b_sk.approval")
    rc, out = ctx.sign(bumped, [a, b], d / "slot.bin")
    return rc != 0 and "does not match the ledger head+1" in out, out


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
    rc, out = ctx.sign(draft_g, [a, b], d / "slot.bin")
    return rc != 0 and "does not match the ledger head+1" in out, out


def case_prev_not_ledger_head(d):
    ctx = Ctx(d)
    bumped = ctx.tampered_copy(ctx.draft1, "badprev.bin", PREV_SHA256_AT, PREV_SHA256_LEN, bytes([0x77] * PREV_SHA256_LEN))
    a = ctx.approve("alice", bumped, d / "a.head", out=d / "a_pv.approval")
    b = ctx.approve("bob", bumped, d / "b.head", out=d / "b_pv.approval")
    rc, out = ctx.sign(bumped, [a, b], d / "slot.bin")
    return rc != 0 and "prev_sha256 is not the ledger head" in out, out


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
    rc, out = ctx.sign(other_draft, [a, b], d / "slot1b.bin")
    return rc != 0 and "does not match the ledger head+1" in out, out


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


def case_approver_head_ahead_of_ledger(d):
    ctx = Ctx(d)
    ahead = d / "ahead.head"
    ahead.write_text("body_sha256=" + "ab" * 32 + "\nversion=5\n")
    rc, out = run(BIN, "approve", "--ledger", ctx.ledger, "--draft", ctx.draft1, "--approver-key", ctx.approver_key["carol"],
                  "--approver-id", "carol", "--head", ahead, "--out", d / "c1.approval")
    return rc != 0 and "behind this approver's recorded head" in out, out


def case_approver_head_same_version_different_digest(d):
    ctx = Ctx(d)
    wrong = d / "wrong.head"
    wrong.write_text("body_sha256=" + "cd" * 32 + "\nversion=0\n")
    rc, out = run(BIN, "approve", "--ledger", ctx.ledger, "--draft", ctx.draft1, "--approver-key", ctx.approver_key["carol"],
                  "--approver-id", "carol", "--head", wrong, "--out", d / "c1.approval")
    return rc != 0 and "tampered or forked ledger" in out, out


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


# --- restore fixtures ------------------------------------------------------

def case_restore_allow(d):
    ctx = Ctx(d)
    rc0, out0 = ctx.sign(ctx.draft1, [ctx.a1, ctx.b1], d / "slot1.bin")
    assert rc0 == 0, out0
    r1 = d / "r1.approval"
    r2 = d / "r2.approval"
    rc1, out1 = run(BIN, "ledger", "approve-restore", "--from", ctx.ledger, "--approver-key", ctx.approver_key["alice"],
                     "--approver-id", "alice", "--out", r1)
    rc2, out2 = run(BIN, "ledger", "approve-restore", "--from", ctx.ledger, "--approver-key", ctx.approver_key["bob"],
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
    ahead_head.write_text("body_sha256=" + "ab" * 32 + "\nversion=1\n")
    r1 = d / "r1.approval"
    r2 = d / "r2.approval"
    run(BIN, "ledger", "approve-restore", "--from", stale_copy, "--approver-key", ctx.approver_key["alice"], "--approver-id", "alice", "--out", r1)
    run(BIN, "ledger", "approve-restore", "--from", stale_copy, "--approver-key", ctx.approver_key["bob"], "--approver-id", "bob", "--out", r2)
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
    ahead_head.write_text("body_sha256=" + "ab" * 32 + "\nversion=5\n")
    r1 = d / "r1.approval"
    r2 = d / "r2.approval"
    run(BIN, "ledger", "approve-restore", "--from", ctx.ledger, "--approver-key", ctx.approver_key["alice"], "--approver-id", "alice", "--out", r1)
    run(BIN, "ledger", "approve-restore", "--from", ctx.ledger, "--approver-key", ctx.approver_key["bob"], "--approver-id", "bob", "--out", r2)
    rc, out = run(BIN, "ledger", "restore", "--from", ctx.ledger, "--dir", d / "restored", "--approvals", r1, r2,
                  "--keys-pub", ctx.keys, "--head", ahead_head)
    return rc != 0 and "behind the head" in out, out


def case_single_restore_approval(d):
    ctx = Ctx(d)
    r1 = d / "r1.approval"
    run(BIN, "ledger", "approve-restore", "--from", ctx.ledger, "--approver-key", ctx.approver_key["alice"], "--approver-id", "alice", "--out", r1)
    rc, out = run(BIN, "ledger", "restore", "--from", ctx.ledger, "--dir", d / "restored", "--approvals", r1,
                  "--keys-pub", ctx.keys)
    return rc != 0 and "at least two" in out, out


def case_same_restore_approver_twice(d):
    ctx = Ctx(d)
    r1 = d / "r1.approval"
    run(BIN, "ledger", "approve-restore", "--from", ctx.ledger, "--approver-key", ctx.approver_key["alice"], "--approver-id", "alice", "--out", r1)
    rc, out = run(BIN, "ledger", "restore", "--from", ctx.ledger, "--dir", d / "restored", "--approvals", r1, r1,
                  "--keys-pub", ctx.keys)
    return rc != 0 and "approved twice" in out, out


def case_restore_approver_not_in_roster(d):
    ctx = Ctx(d)
    r1 = d / "r1.approval"
    r2 = d / "r2.approval"
    run(BIN, "ledger", "approve-restore", "--from", ctx.ledger, "--approver-key", ctx.approver_key["alice"], "--approver-id", "alice", "--out", r1)
    run(BIN, "ledger", "approve-restore", "--from", ctx.ledger, "--approver-key", ctx.approver_key["dave"], "--approver-id", "dave", "--out", r2)
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
    rc2, out2 = run(BIN, "ledger", "approve-restore", "--from", ctx.ledger, "--approver-key", ctx.approver_key["carol"],
                     "--approver-id", "carol", "--out", carol_restore)
    assert rc2 == 0, out2
    alice_restore = d / "alice.approval"
    run(BIN, "ledger", "approve-restore", "--from", ctx.ledger, "--approver-key", ctx.approver_key["alice"], "--approver-id", "alice", "--out", alice_restore)
    rc, out = run(BIN, "ledger", "restore", "--from", ctx.ledger, "--dir", d / "restored", "--approvals", carol_restore, alice_restore,
                  "--keys-pub", ctx.keys)
    return rc != 0 and "is not in the roster" in out, out


def case_restore_approval_bound_to_another_head(d):
    ctx = Ctx(d)
    # A restore approval signed against the ledger while it was still at
    # version 0 (an earlier, legitimately-reached head).
    stale_restore = d / "stale.approval"
    run(BIN, "ledger", "approve-restore", "--from", ctx.ledger, "--approver-key", ctx.approver_key["alice"], "--approver-id", "alice", "--out", stale_restore)
    rc0, out0 = ctx.sign(ctx.draft1, [ctx.a1, ctx.b1], d / "slot1.bin")
    assert rc0 == 0, out0
    fresh_restore = d / "fresh.approval"
    run(BIN, "ledger", "approve-restore", "--from", ctx.ledger, "--approver-key", ctx.approver_key["bob"], "--approver-id", "bob", "--out", fresh_restore)
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
    run(BIN, "ledger", "approve-restore", "--from", other_ctx.ledger, "--approver-key", other_ctx.approver_key["alice"], "--approver-id", "alice", "--out", other_restore)
    alice_restore = d / "alice.approval"
    run(BIN, "ledger", "approve-restore", "--from", ctx.ledger, "--approver-key", ctx.approver_key["bob"], "--approver-id", "bob", "--out", alice_restore)
    rc, out = run(BIN, "ledger", "restore", "--from", ctx.ledger, "--dir", d / "restored", "--approvals", other_restore, alice_restore,
                  "--keys-pub", ctx.keys)
    return rc != 0 and "another fleet_id" in out, out


CASES = [
    ("version 1 is drafted, approved, signed and verifies (allow)", case_allow_sign_v1),
    ("a payload swapped after approval is refused", case_payload_swapped_after_approval),
    ("the same approver twice is refused", case_same_approver_twice),
    ("one approval only is refused", case_one_approval_only),
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
