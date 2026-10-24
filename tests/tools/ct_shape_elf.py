"""Synthetic PD and harness ELFs for tools/ct-shape's fixtures
(tests/tools/test_ct_shape.py, tests/tools/test_package.py).

`program(...)` returns the assembly of a small mce460896-shaped program:
the two C10 roots, a helper with a branch, a select, an adrp-paired load
and a register-offset load, a panic entry by property and one by name,
memcpy, the envelope-open root (M5 plan I10.3) with its one helper, the
TLS identity roots (M6 plan C7: the exchange calling a libcrux function
that references an anonymous constant, a panic Location pointing at its
file name, and calls memcmp or bcmp; the scrub; and the RNG-generic shim
over the exchange), the PD entry symbol the
erasure control looks for and, on request, rust-sel4's DebugPutChar
syscall wrapper (the printing check's target). `build` assembles and links
it with the aarch64-none-elf toolchain at a chosen base address, so a PD
and a "harness" differ in every address and in their crate hashes while
their code is the same.
"""

import pathlib
import subprocess

AS = "aarch64-none-elf-as"
LD = "aarch64-none-elf-ld"


def syms(h: str) -> dict:
    """v0 symbols, `h` standing in for the crate hashes (`Cs<h>_`)."""
    mce, core, tpm2 = f"Cs{h}_9mce460896", f"Cs{h}0_4core", f"Cs{h}6_4tpm2"
    tls, kem = f"Cs{h}7_8tls_core", f"Cs{h}8_14libcrux_ml_kem"
    return {
        "open": f"_RNvNt{tpm2}8envelope11open_sealed",
        "open_core": f"_RNvNt{tpm2}8envelope9open_core",
        "exchange": f"_RNvNt{tls}6hybrid24exchange_with_randomness",
        "tls_scrub": f"_RNvNt{tls}6hybrid19scrub_session_stack",
        "tls_shim": f"_RINvMNt{tls}6hybridNtNt{tls}6hybrid12HybridSecret8exchangeNtCs{h}4_6caller3RngE",
        "encapsulate": f"_RNvNt{kem}8mlkem76811encapsulate",
        "decaps": f"_RNv{mce}6decaps",
        "attempt": f"_RNv{mce}14encaps_attempt",
        "bm": f"_RNvNt{mce}2bm2bm",
        "scrub": f"_RNv{mce}11scrub_stack",
        "table": f"_RNvNt{mce}6consts5TABLE",
        "table2": f"_RNvNt{mce}6consts6TABLE2",
        "bounds": f"_RNvNt{core}9panicking18panic_bounds_check",
        "fail": f"_RNvNtNt{core}5slice5index16slice_index_fail",
        "panic_fmt": f"_RNvNt{core}9panicking9panic_fmt",
        "vstd": f"_RNvNtCs{h}1_4vstd3seq3new",
        "mul": f"_RNvNt{mce}3vec3mul",
        "shim": f"_RINv{mce}6encapsNtCs{h}4_6caller3RngE",
        "debug_put_char": f"_RNvNtNtCs{h}5_8sel4_sys8syscalls5calls17seL4_DebugPutChar",
    }


def entry(crate: str, h: str) -> str:
    """`sel4_microkit::entry::run_main::<crate::PqK, crate::init>`."""
    c = f"Cs{h}2_{len(crate)}{crate}"
    return f"_RINvNtCs{h}3_13sel4_microkit5entry8run_mainNt{c}3PqKNv{c}4initE"


# A libcrux function, outside the shape baseline: a select and a
# register-offset load the shape check would count, an anonymous constant
# and the comparison libcall.
ENCAPSULATE = ["ldr x9, [x1, x2]", "cmp x9, #0x3", "csel x0, x9, x2, ne", "adr x0, {anon_loc}", "bl {cmp_call}",
               "bl memcpy", "ret"]

BM = [
    "adrp x8, {table}",
    "add x8, x8, :lo12:{table}",
    "ldr x9, [x8, x1, lsl #3]",
    "cmp x9, #0x10",
    "b.hs 1f",
    "csel x0, x9, x1, eq",
    "bl memcpy",
    "ret",
    "1: bl {bounds}",
]


def program(h: str, crate: str, filler: int = 0, bm=None, extra=(), vstd: bool = False, mul: bool = False,
            only_root=None, entry_body=("ret",), debug_put_char: bool = False, mce: bool = True,
            open_root: bool = True, tls: bool = False, encapsulate=None, exchange_extra=(), anon_numbers=(1, 2),
            anon_file: str = "src/hybrid.rs", anon_line: int = 12, cmp_call: str = "memcmp") -> str:
    """`only_root`: keep one of the two roots ("decaps" or "attempt"), as
    each PD links only its own; `mce` False drops McEliece altogether (as
    `key` links none) and `open_root` False the envelope open (as `pq`
    links none). `entry_body`: the PD entry's instructions. `tls` adds the
    TLS roots, `encapsulate` replacing the libcrux function's body and
    `exchange_extra` appended to the exchange root's; `anon_numbers` are
    the anonymous file name's and Location's numbers (rustc's per codegen
    unit counter), `anon_file` and `anon_line` their content, `cmp_call`
    the comparison libcall."""
    s = syms(h)
    funcs = [
        ("decaps", ["stp x29, x30, [sp, #-16]!", "bl {bm}", "ldp x29, x30, [sp], #16", "b {scrub}"]),
        ("attempt", ["stp x29, x30, [sp, #-16]!", "bl {bm}", "ldp x29, x30, [sp], #16", "b {scrub}"]),
        ("bm", list(bm or BM) + list(extra)),
        ("scrub", ["mov x8, #0", "1: add x8, x8, #1", "cmp x8, #4", "b.ne 1b", "ret"]),
        ("bounds", ["stp x29, x30, [sp, #-16]!", "bl {panic_fmt}"]),
        ("fail", ["b {panic_fmt}"]),
        ("panic_fmt", ["b ."]),
        ("open", ["stp x29, x30, [sp, #-16]!", "bl {open_core}", "ldp x29, x30, [sp], #16", "ret"]),
        ("open_core", ["cbz x0, 1f", "bl memcpy", "1: ret"]),
        ("exchange", ["stp x29, x30, [sp, #-16]!", "bl {encapsulate}", *exchange_extra, "ldp x29, x30, [sp], #16",
                      "ret"]),
        ("encapsulate", list(encapsulate or ENCAPSULATE)),
        ("tls_scrub", ["mov x8, #0", "1: str xzr, [sp, x8]", "add x8, x8, #8", "cmp x8, #64", "b.ne 1b", "ret"]),
        ("tls_shim", ["stp x29, x30, [sp, #-16]!", "bl {exchange}", "ldp x29, x30, [sp], #16", "ret"]),
    ]
    out = [".text", ".globl _start", "_start:", "b ."]
    out += ["nop"] * filler
    anon = {key: f"anon.{h * 16}.{n}" for key, n in zip(("anon_file", "anon_loc"), anon_numbers)}
    names = {**s, **anon, "cmp_call": cmp_call}
    other = {"decaps": "attempt", "attempt": "decaps"}.get(only_root)
    dropped = {other} | ({"decaps", "attempt", "bm", "scrub"} if not mce else set()) \
        | ({"open", "open_core"} if not open_root else set()) \
        | ({"exchange", "encapsulate", "tls_scrub", "tls_shim"} if not tls else set())
    named = [(s[k], body) for k, body in funcs if k not in dropped]
    named += [("memcpy", ["ret"]), ("memcmp", ["ret"]), ("bcmp", ["ret"]), (entry(crate, h), list(entry_body))]
    if mce:
        named.append((s["shim"], ["cbnz w0, 1f", "1: ret"]))
    if mul:
        named.append((s["mul"], ["ret"]))
    if vstd:
        named.append((s["vstd"], ["ret"]))
    if debug_put_char:
        named.append((s["debug_put_char"], ["ret"]))
    for sym, body in named:
        out += [f".globl {sym}", f".type {sym}, %function", f"{sym}:"]
        out += [line.format(**names) for line in body]
        out += [f".size {sym}, . - {sym}"]
    out += [".section .rodata", ".balign 8"]
    out += ["nop_pad: .zero 64" if filler else ""]
    for key in ("table", "table2") if mce else ():
        sym = s[key]
        out += [f".globl {sym}", f".type {sym}, %object", f"{sym}:", ".zero 128", f".size {sym}, 128"]
    if tls:
        loc, file = anon["anon_loc"], anon["anon_file"]
        out += [".balign 8", f".type {loc}, %object", f"{loc}:", f".xword {file}", f".xword {len(anon_file)}",
                f".word {anon_line}, 5", f".size {loc}, 24",
                f".type {file}, %object", f"{file}:", f'.ascii "{anon_file}"', f".size {file}, {len(anon_file)}"]
    return "\n".join(out) + "\n"


def build(d: pathlib.Path, name: str, source: str, base: int) -> pathlib.Path:
    src, obj, elf = d / f"{name}.s", d / f"{name}.o", d / name
    src.write_text(source)
    subprocess.run([AS, "-o", str(obj), str(src)], check=True, capture_output=True)
    subprocess.run([LD, "-o", str(elf), f"-Ttext={base:#x}", str(obj)], check=True, capture_output=True)
    return elf


def tree(d: pathlib.Path, pd_bm=None, pd_extra=(), harness_bm=None, harness_extra=(), vstd: bool = False,
         harness_mul: bool = False, pd_mul: bool = False, pd_entry=("ret",), debug_put_char=None,
         harness_encapsulate=None, tls_exchange_extra=(), harness_anon_file="src/hybrid.rs", harness_anon_line=12,
         harness_cmp="bcmp"):
    """A search path with pd-pq.elf and pd-pqkey.elf, each with its own
    McEliece root only, pqkey and pd-key.elf with the envelope open (key
    without McEliece), pd-tls.elf with the TLS roots alone, and a harness
    (with every root) built at other addresses with other crate hashes,
    other anonymous-constant numbers and bcmp for memcmp.
    `debug_put_char` names the PD ELF that also gets the DebugPutChar
    wrapper. Returns (search path, harness)."""
    search = d / "search"
    search.mkdir()
    for label, crate, root in (("pd-pq.elf", "pd_pq", "attempt"), ("pd-pqkey.elf", "pd_pqkey", "decaps")):
        build(search, label, program("a1", crate, bm=pd_bm, extra=pd_extra, vstd=vstd, mul=pd_mul, only_root=root,
                                     entry_body=pd_entry, debug_put_char=label == debug_put_char,
                                     open_root=root == "decaps"), 0x200000)
    # The McEliece knobs (bm, extra, mul, entry) are pqkey's and pq's.
    build(search, "pd-key.elf", program("a1", "pd_key", vstd=vstd, debug_put_char=debug_put_char == "pd-key.elf",
                                        mce=False), 0x200000)
    build(search, "pd-tls.elf", program("a1", "pd_tls", mce=False, open_root=False, tls=True,
                                        exchange_extra=tls_exchange_extra), 0x200000)
    harness = build(d, "ct-harness", program("b7", "ct_harness", filler=37, bm=harness_bm, extra=harness_extra,
                                                     mul=harness_mul, tls=True, encapsulate=harness_encapsulate,
                                                     anon_numbers=(7, 9), anon_file=harness_anon_file,
                                                     anon_line=harness_anon_line, cmp_call=harness_cmp),
                    0x412340)
    return search, harness
