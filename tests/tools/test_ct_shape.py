"""tools/ct-shape (M4 plan C10, C1 erasure): the normaliser catches a
one-instruction difference and nothing but address and hash noise passes;
the closure stops where C10 says; forbidden, shape and erasure each refuse
their one-change fixture.

The ELFs are assembled from tests/tools/ct_shape_elf.py with the
aarch64-none-elf toolchain (the dev image's), so objdump and c++filt run as
they do on the real PDs.

Usage: python3 tests/tools/test_ct_shape.py
Prints "CT-SHAPE-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import importlib.machinery
import importlib.util
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ct_shape_elf as elf  # noqa: E402

sys.dont_write_bytecode = True
loader = importlib.machinery.SourceFileLoader("ct_shape", str(ROOT / "tools/ct-shape"))
spec = importlib.util.spec_from_loader("ct_shape", loader)
cts = importlib.util.module_from_spec(spec)
loader.exec_module(cts)

BM = "mce460896::bm::bm"


def with_tree(**kw):
    """Runs `check(search, harness, d)` on a fresh synthetic tree."""
    def wrap(check):
        def run():
            d = pathlib.Path(tempfile.mkdtemp(prefix="test-ct-shape-"))
            try:
                search, harness = elf.tree(d, **kw)
                return check(search, harness, d)
            finally:
                shutil.rmtree(d)
        return run
    return wrap


def load(search, harness):
    return ({label: cts.Binary.load(search / label, label) for label in cts.ROOTS},
            cts.Binary.load(harness, "harness"))


def identity(**kw):
    @with_tree(**kw)
    def run(search, harness, _d):
        binaries, h = load(search, harness)
        return cts.check_identity(binaries["pd-pqkey.elf"], h, "mce460896::decaps")
    return run


def bm_with(old: str, new: str) -> list:
    assert old in elf.BM, old
    return [new if line == old else line for line in elf.BM]


def differs(at: int, here, there: str) -> list:
    here = "no instruction" if here is None else f"'{here}'"
    return [f"pd-pqkey.elf: identity: {BM} differs from the harness: +{at:#x} {here} here, '{there}' in the harness"]


@with_tree()
def normalised_bm(search, _harness, _d):
    """The normaliser's output itself: no address survives, everything else
    does (an expected-text fixture, so a format change is reviewed)."""
    binaries, _ = load(search, _harness)
    b = binaries["pd-pqkey.elf"]
    want = ["adrp x8, <page>", "add x8, x8, <mce460896::consts::TABLE>", "ldr x9, [x8, x1, lsl #3]",
            "cmp x9, #0x10", "b.cs .+0x20", "csel x0, x9, x1, eq", "bl <memcpy>", "ret",
            "bl <core::panicking::panic_bounds_check>"]
    got = cts.normalise(b, b.by_name[BM][0])
    return [] if got == want else [f"normalised {got}"]


def stops_by_property():
    """The stop set: by name (`_fail`, `_failed`, copy_from_slice's
    len_mismatch_fail included) and by never returning into
    core::panicking; not a core function that returns, nor a non-core one."""
    names = {
        0x100: "core::slice::copy_from_slice_impl::len_mismatch_fail",
        0x200: "core::option::unwrap_failed",
        0x300: "core::panicking::panic_bounds_check",
        0x400: "core::panicking::panic_fmt",
        0x500: "core::slice::index::returns",
        0x600: "mce460896::never_returns",
        0x700: "core::iter::no_ret_no_panic",
    }
    insns = {0x100: ("b", "400 <x>"), 0x200: ("b", "400 <x>"),
             0x300: ("stp", "x29, x30, [sp, #-16]!"), 0x304: ("bl", "400 <x>"), 0x308: ("nop", ""),
             0x400: ("b", "400 <x>"),
             0x500: ("bl", "400 <x>"), 0x504: ("ret", ""),
             0x600: ("bl", "400 <x>"),
             0x700: ("b", "700 <x>")}
    sizes = {0x100: 4, 0x200: 4, 0x300: 12, 0x400: 4, 0x500: 8, 0x600: 4, 0x700: 4}
    syms = [cts.Sym(n, a, sizes[a], "func") for a, n in names.items()]
    b = cts.Binary("t", syms, {n: n for n in names.values()}, insns, {})
    got = {names[a] for a in names if cts.is_panic_entry(b, a)}
    want = {names[0x100], names[0x200], names[0x300], names[0x400]}
    return [] if got == want else [f"stops {sorted(got)}"]


def hash_noise_and_instantiating_crate():
    """Crate hashes are masked; the instantiating crate of a generic is not."""
    a = "_RNvMNtNtCsx1_4core5slice4iterINtB2_4IterhE3newCsy1_9mce460896"
    b = "_RNvMNtNtCsz9_4core5slice4iterINtB2_4IterhE3newCsw4_9mce460896"
    c = "_RNvMNtNtCsz9_4core5slice4iterINtB2_4IterhE3newCsw4_4sha3"
    n = cts.demangle_all([a, b, c])
    want = "<core::slice::iter::Iter<u8>>::new @mce460896"
    errors = [] if n[a] == n[b] == want else [f"hash noise not masked: {n[a]!r} {n[b]!r}"]
    return errors + ([] if n[c] == "<core::slice::iter::Iter<u8>>::new @sha3" else [f"crate tag lost: {n[c]!r}"])


def forbidden(extra, divides=None):
    @with_tree(pd_extra=extra)
    def run(search, harness, _d):
        binaries, _ = load(search, harness)
        b = binaries["pd-pqkey.elf"]
        nodes, _, _ = cts.closure(b, "mce460896::decaps")
        return cts.check_forbidden(b, nodes, divides or {})
    return run


def shape_policy(search, harness, d, edit=lambda text: text):
    """The printed baseline with every justification filled in, then
    `edit`, as a policy file; returns check_shape's errors."""
    binaries, _ = load(search, harness)
    policy = d / "ct-shape.toml"
    policy.write_text("")
    printed = subprocess.run([sys.executable, str(ROOT / "tools/ct-shape"), "--harness", str(harness),
                              "--search-path", str(search), "--policy", str(policy), "--print-baseline"],
                             capture_output=True, text=True, check=True).stdout
    policy.write_text(edit(printed.replace('justification = ""', 'justification = "fixture"')))
    return cts.check_shape(binaries, policy)


def shape(**kw):
    edit = kw.pop("edit", lambda text: text)

    @with_tree(**kw)
    def run(search, harness, d):
        return shape_policy(search, harness, d, edit)
    return run


def erasure(label="pd-pqkey.elf", **kw):
    @with_tree(**kw)
    def run(search, _harness, _d):
        return cts.check_erasure(search / label)
    return run


@with_tree()
def erasure_control_fails(search, _harness, _d):
    """An ELF whose entry symbol is another crate's fails the control."""
    (search / "pd-pq.elf").rename(search / "pd-other.elf")
    return cts.check_erasure(search / "pd-other.elf")


def cli(**kw):
    """tools/ct-shape end to end, all four checks, against a policy made from
    the unmutated tree: (exit status, the ct-shape: lines, the count)."""
    mutated = kw.pop("mutated", False)

    def run():
        d = pathlib.Path(tempfile.mkdtemp(prefix="test-ct-shape-"))
        try:
            search, harness = elf.tree(d, **kw)
            shape_policy(search, harness, d)
            if mutated:
                (d / "m").mkdir()
                search, _ = elf.tree(d / "m", pd_bm=bm_with("csel x0, x9, x1, eq", "csel x0, x9, x2, eq"))
            r = subprocess.run([sys.executable, str(ROOT / "tools/ct-shape"), "--harness", str(harness),
                                "--search-path", str(search), "--policy", str(d / "ct-shape.toml"),
                                str(search / "pd-pq.elf"), str(search / "pd-pqkey.elf")],
                               capture_output=True, text=True)
            lines = [line for line in r.stdout.splitlines() if line.startswith(("ct-shape: ", "CT-SHAPE-SYMBOLS"))]
            return [] if (r.returncode, lines) == ((1, lines) if mutated else (0, ["CT-SHAPE-SYMBOLS 6"])) \
                and (not mutated or len(lines) == 2) else [f"exit {r.returncode}: {lines}"]
        finally:
            shutil.rmtree(d)
    return run


def make_never_writes_the_baseline():
    text = (ROOT / "Makefile").read_text()
    return ["the Makefile calls --print-baseline"] if "print-baseline" in text else []


CSEL = "csel x0, x9, x1, eq"
MUTATED_SHAPE = "pd-pq.elf: shape: mce460896::bm::bm: 'csel eq' 2 in the binary, 1 in ct-shape.toml"

# (name, expected: None for accept, or the exact list of errors; check)
CASES = [
    ("address and hash noise alone: identity holds", None, identity()),
    ("the normaliser keeps every non-address operand", None, normalised_bm),
    ("one register changed is caught",
     differs(0x14, CSEL, "csel x0, x9, x2, eq"), identity(harness_bm=bm_with(CSEL, "csel x0, x9, x2, eq"))),
    ("one opcode changed is caught",
     differs(0x14, CSEL, "csinc x0, x9, x1, eq"), identity(harness_bm=bm_with(CSEL, "csinc x0, x9, x1, eq"))),
    ("a non-address immediate changed is caught",
     differs(0xc, "cmp x9, #0x10", "cmp x9, #0x11"), identity(harness_bm=bm_with("cmp x9, #0x10", "cmp x9, #0x11"))),
    ("an adrp pair naming another symbol is caught",
     differs(0x4, "add x8, x8, <mce460896::consts::TABLE>", "add x8, x8, <mce460896::consts::TABLE2>"),
     identity(harness_bm=[line.replace("{table}", "{table2}") for line in elf.BM])),
    ("an extra instruction is caught",
     differs(0x24, None, "nop"), identity(harness_bm=elf.BM + ["nop"])),
    ("a function only in the harness's closure is caught",
     ["pd-pqkey.elf: identity: mce460896::vec::mul is in the harness's closure of mce460896::decaps but not in "
      "this ELF's", differs(0x24, None, "bl <mce460896::vec::mul>")[0]],
     identity(harness_extra=["bl {mul}"], harness_mul=True)),
    ("a stop reached only in the harness is caught",
     ["pd-pqkey.elf: identity: stop core::slice::index::slice_index_fail is reached from mce460896::decaps "
      "only in the harness", differs(0x24, None, "bl <core::slice::index::slice_index_fail>")[0]],
     identity(harness_extra=["bl {fail}"])),
    ("panic entries stop the closure by property", None, stops_by_property),
    ("crate hashes are masked, the instantiating crate is kept", None, hash_noise_and_instantiating_crate),
    ("a udiv is forbidden", [f"pd-pqkey.elf: forbidden: {BM}+0x24: udiv x0, x1, x2"], forbidden(["udiv x0, x1, x2"])),
    ("an sdiv is forbidden", [f"pd-pqkey.elf: forbidden: {BM}+0x24: sdiv x0, x1, x2"], forbidden(["sdiv x0, x1, x2"])),
    ("a udiv listed in [[divide]] passes", None,
     forbidden(["udiv x0, x1, x2"], {("pd-pqkey.elf", BM, "udiv x0, x1, x2"): "fixture"})),
    ("a [[divide]] entry that matches nothing fails",
     [f"pd-pqkey.elf: forbidden: {BM}+0x24: udiv x0, x1, x2",
      f"pd-pqkey.elf: forbidden: [[divide]] {BM}: 'udiv x0, x1, x3' matches no instruction"],
     forbidden(["udiv x0, x1, x2"], {("pd-pqkey.elf", BM, "udiv x0, x1, x3"): "fixture"})),
    ("a br is forbidden", [f"pd-pqkey.elf: forbidden: {BM}+0x24: br x3"], forbidden(["br x3"])),
    ("a blr is forbidden", [f"pd-pqkey.elf: forbidden: {BM}+0x24: blr x3"], forbidden(["blr x3"])),
    ("a call to memcmp is forbidden", [f"pd-pqkey.elf: forbidden: {BM}+0x24: a call to memcmp"],
     forbidden(["bl memcmp"])),
    ("the valgrind client-request preamble is forbidden",
     [f"pd-pqkey.elf: forbidden: {BM}+0x24: the valgrind client-request preamble (ror x12, x12, #3; "
      "ror x12, x12, #13; ror x12, x12, #51; ror x12, x12, #61)"],
     forbidden(["ror x12, x12, #3", "ror x12, x12, #13", "ror x12, x12, #51", "ror x12, x12, #61",
                "orr x10, x10, x10"])),
    ("a rotation by 3 alone is no preamble", None, forbidden(["ror x12, x12, #3", "eor x0, x0, x12"])),
    ("the unmutated shape equals its baseline", None, shape()),
    # The baseline is printed from the mutated tree, then put back to the
    # unmutated count for the first entry (pd-pq's bm).
    ("one more select is a multiset diff naming the function", [MUTATED_SHAPE],
     shape(edit=lambda t: t.replace('"csel eq" = 2', '"csel eq" = 1', 1), pd_extra=["csel x1, x1, x2, eq"])),
    ("a function missing from the baseline fails",
     ["pd-pqkey.elf: shape: mce460896::scrub_stack is not in ct-shape.toml",
      "pd-pqkey.elf: shape: mce460896::gone is listed in ct-shape.toml but not in the closure"],
     shape(edit=lambda t: t.replace('elf = "pd-pqkey.elf"\nname = "mce460896::scrub_stack"',
                                    'elf = "pd-pqkey.elf"\nname = "mce460896::gone"'))),
    ("an empty justification fails", ["pd-pq.elf: shape: mce460896::bm::bm has no justification in ct-shape.toml"],
     shape(edit=lambda t: t.replace('name = "mce460896::bm::bm"\njustification = "fixture"',
                                    'name = "mce460896::bm::bm"\njustification = ""', 1))),
    ("erasure passes a PD without Verus symbols", None, erasure()),
    ("erasure names a vstd symbol", ["pd-pqkey.elf: erasure: vstd::seq::new is a Verus symbol"], erasure(vstd=True)),
    ("erasure fails when the control cannot find the entry",
     ["pd-other.elf: erasure: positive control failed: no symbol demangles to "
      "sel4_microkit::entry::run_main<_, pd_other::init>"], erasure_control_fails),
    ("the CLI passes the unmutated tree", None, cli()),
    ("the CLI refuses a mutated ELF", None, cli(mutated=True)),
    ("no make target writes the baseline", None, make_never_writes_the_baseline),
]


def main() -> int:
    failures = 0
    for name, want, run in CASES:
        try:
            errors = run()
        except (cts.Fail, LookupError) as e:
            errors = [f"raised: {e!r}"]
        ok = not errors if want is None else errors == want
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {errors or 'accepted'}")
    print(f"CT-SHAPE-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
