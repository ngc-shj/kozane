"""Synthetic PD and harness ELFs for tools/ct-shape's fixtures
(tests/tools/test_ct_shape.py, tests/tools/test_package.py).

`program(...)` returns the assembly of a small mce460896-shaped program:
the two C10 roots, a helper with a branch, a select, an adrp-paired load
and a register-offset load, a panic entry by property and one by name,
memcpy, the PD entry symbol the erasure control looks for and, on request,
rust-sel4's DebugPutChar syscall wrapper (the printing check's target). `build`
assembles and links it with the aarch64-none-elf toolchain at a chosen base
address, so a PD and a "harness" differ in every address and in their crate
hashes while their code is the same.
"""

import pathlib
import subprocess

AS = "aarch64-none-elf-as"
LD = "aarch64-none-elf-ld"


def syms(h: str) -> dict:
    """v0 symbols, `h` standing in for the crate hashes (`Cs<h>_`)."""
    mce, core = f"Cs{h}_9mce460896", f"Cs{h}0_4core"
    return {
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
            only_root=None, entry_body=("ret",), debug_put_char: bool = False) -> str:
    """`only_root`: keep one of the two roots ("decaps" or "attempt"), as
    each PD links only its own. `entry_body`: the PD entry's instructions."""
    s = syms(h)
    funcs = [
        ("decaps", ["stp x29, x30, [sp, #-16]!", "bl {bm}", "ldp x29, x30, [sp], #16", "b {scrub}"]),
        ("attempt", ["stp x29, x30, [sp, #-16]!", "bl {bm}", "ldp x29, x30, [sp], #16", "b {scrub}"]),
        ("bm", list(bm or BM) + list(extra)),
        ("scrub", ["mov x8, #0", "1: add x8, x8, #1", "cmp x8, #4", "b.ne 1b", "ret"]),
        ("bounds", ["stp x29, x30, [sp, #-16]!", "bl {panic_fmt}"]),
        ("fail", ["b {panic_fmt}"]),
        ("panic_fmt", ["b ."]),
    ]
    out = [".text", ".globl _start", "_start:", "b ."]
    out += ["nop"] * filler
    names = {k: v for k, v in s.items()}
    other = {"decaps": "attempt", "attempt": "decaps"}.get(only_root)
    named = [(s[k], body) for k, body in funcs if k != other]
    named += [("memcpy", ["ret"]), ("memcmp", ["ret"]), (entry(crate, h), list(entry_body)),
                                                   (s["shim"], ["cbnz w0, 1f", "1: ret"])]
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
    for key in ("table", "table2"):
        sym = s[key]
        out += [f".globl {sym}", f".type {sym}, %object", f"{sym}:", ".zero 128", f".size {sym}, 128"]
    return "\n".join(out) + "\n"


def build(d: pathlib.Path, name: str, source: str, base: int) -> pathlib.Path:
    src, obj, elf = d / f"{name}.s", d / f"{name}.o", d / name
    src.write_text(source)
    subprocess.run([AS, "-o", str(obj), str(src)], check=True, capture_output=True)
    subprocess.run([LD, "-o", str(elf), f"-Ttext={base:#x}", str(obj)], check=True, capture_output=True)
    return elf


def tree(d: pathlib.Path, pd_bm=None, pd_extra=(), harness_bm=None, harness_extra=(), vstd: bool = False,
         harness_mul: bool = False, pd_mul: bool = False, pd_entry=("ret",), debug_put_char=None):
    """A search path with pd-pq.elf and pd-pqkey.elf, each with its own root
    only, and a harness (with both) built at other addresses with other
    crate hashes. `debug_put_char` names the PD ELF that also gets the
    DebugPutChar wrapper. Returns (search path, harness)."""
    search = d / "search"
    search.mkdir()
    for label, crate, root in (("pd-pq.elf", "pd_pq", "attempt"), ("pd-pqkey.elf", "pd_pqkey", "decaps")):
        build(search, label, program("a1", crate, bm=pd_bm, extra=pd_extra, vstd=vstd, mul=pd_mul, only_root=root,
                                     entry_body=pd_entry, debug_put_char=label == debug_put_char), 0x200000)
    harness = build(d, "ct-harness", program("b7", "ct_harness", filler=37, bm=harness_bm, extra=harness_extra,
                                                     mul=harness_mul),
                    0x412340)
    return search, harness
