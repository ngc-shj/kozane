"""The guest machine (M9 plan C1): the one source of the QEMU and swtpm
argv. tests/integration/run.py builds every boot from `machine` and every
swtpm from `swtpm`; the launcher (C4) renders the same values with
`launcher=True`, where every cross-uid resource is an fd the root launcher
opened instead of a path.

Two accelerators run one machine: `kvm` (production, `-cpu host`) and `tcg`
(every worker). They differ only in `-accel`, `-cpu` and, for `tcg`,
`virtualization=on`: the Microkit loader asks PSCI for its version through
`smc` on every boot, and TCG answers PSCI over SMC only when the machine has
EL2 (deviation D-2). `violations` is I1.2: what no argv rendered here may
contain.
"""

import re

MACHINE_TYPE = "virt-9.0"
# D2: GICv3 (gx10's KVM has no GICv2 emulation, D9); no KSM page merging
# across guests (A19); guest RAM never in a QEMU core dump (H2).
MACHINE_PROPS = "gic-version=3,mem-merge=off,dump-guest-core=off"
ACCELS = ("tcg", "kvm")
# tcg: no FEAT_RNG, so a stray RNDR faults (M7 D3); kvm: the host's CPU.
CPU = {"tcg": "cortex-a72", "kvm": "host"}
MEMORY = "size=2G"

# The NICs' MACs and virtio-mmio slots: kozane.system maps slot 31 (outside,
# 0xa003e00) and slot 23 (inside, 0xa002e00) to the drivers, slot 0 to rng.
OUTSIDE_MAC = bytes.fromhex("525400123456")
INSIDE_MAC = bytes.fromhex("525400123457")
OUTSIDE_BUS = "virtio-mmio-bus.31"
INSIDE_BUS = "virtio-mmio-bus.23"
RNG_BUS = "virtio-mmio-bus.0"

# Every device the guest may have, in order (I1.2's declared list).
DEVICES = ("virtio-rng-device", "loader", "tpm-tis-device", "virtio-net-device")

# I1.2 is an allowlist: the options machine() and swtpm() emit and no
# other (the harness's own -S, -qmp, -no-reboot and HMP monitor are
# appended by spawn_qemu and refused here), each value in the forms they
# render. The patterns below then refuse keys inside an allowed value;
# `file=` is refused in the launcher form unless it names an inherited fd
# (the boot media).
# By name, without the dash: check-pins (P24, P25) finds the firmware and
# CPU options in `def machine` alone.
_QEMU_OPTIONS = ("machine", "accel", "cpu", "m", "overcommit", "chardev", "serial", "monitor", "display", "bios",
                 "object", "device", "tpmdev", "netdev")
# swtpm's options, each with whether it takes a value (`socket`, its
# subcommand, is the one positional).
_SWTPM_OPTIONS = {"tpm2": False, "tpmstate": True, "ctrl": True, "key": True}
# run.py's netdev backends (raw frames over dgram and socket, user-net,
# the tap), all harness-only: the launcher's are its own tap fds.
_HARNESS_NETDEVS = ("dgram", "socket", "user", "tap")
_FORBIDDEN = (
    (re.compile(r"(^|,)secure=on(,|$)"), "secure=on"),
    (re.compile(r"(^|,)mux=on(,|$)"), "mux=on"),
    (re.compile(r"^mon:"), "mon:"),
    (re.compile(r"^stdio(,|$)(?!.*signal=off)"), "a stdio chardev without signal=off"),
    (re.compile(r"(^|,)type=tcp(,|$)"), "type=tcp"),
    (re.compile(r"(^|,)port="), "port="),
)
_LAUNCHER_FORBIDDEN = (
    (re.compile(r"(^|,)path="), "path="),
    (re.compile(r"(^|,)helper="), "helper="),
    (re.compile(r"(^|,)br="), "br="),
    (re.compile(r"(^|,)file=(?!/dev/fd/\d+(,|$))"), "file= other than /dev/fd/<n>"),
)
_INHERITED_FD = re.compile(r"/dev/fd/\d+")


def _machine_string(accel: str) -> str:
    props = MACHINE_PROPS + (",virtualization=on" if accel == "tcg" else "")
    return f"{MACHINE_TYPE},{props}"


def machine(accel: str, firmware: str, tpm, netdevs: tuple, rng: bool = True, media=(),
            launcher: bool = False) -> list:
    """The QEMU argv for one boot, without the harness's own additions
    (-S, QMP, -no-reboot, an HMP monitor socket), which spawn_qemu appends.

    Harness form: `tpm` is the swtpm ctrl socket path, `netdevs` is
    (outside, inside) netdev specs without an id. Launcher form: `tpm` is
    the fd of the launcher's socketpair end, `netdevs` the two tap fds, and
    `firmware` and every media path are /dev/fd/<n>. `rng=False` exists only
    for the M7 deny case: it drops the RNG device and nothing else."""
    if accel not in ACCELS:
        raise ValueError(f"vm.machine: unknown accelerator {accel!r}")
    outside, inside = netdevs
    if launcher:
        chardev = f"socket,id=chrtpm,fd={int(tpm)}"
        outside, inside = f"tap,fd={int(outside)}", f"tap,fd={int(inside)}"
    else:
        chardev = f"socket,id=chrtpm,path={tpm}"
    cmd = ["-machine", _machine_string(accel), "-accel", accel, "-cpu", CPU[accel], "-m", MEMORY]
    # H2: in production guest RAM stays resident (never swapped). The harness
    # leaves it out: locking 2 GiB took 86 s per boot on a loaded host (P14,
    # deviation D-8), and nothing in a test boot needs it.
    if launcher:
        cmd += ["-overcommit", "mem-lock=on"]
    # The console is not an input to QEMU: signal=off, so a 0x03 on it is a
    # byte for the guest (S-BOOT-5 sends one), never a SIGINT that ends QEMU.
    cmd += ["-chardev", "stdio,id=serial0,signal=off", "-serial", "chardev:serial0",
            "-monitor", "none", "-display", "none", "-bios", firmware]
    if rng:
        cmd += ["-object", "rng-random,id=rng0,filename=/dev/urandom",
                "-device", f"virtio-rng-device,rng=rng0,bus={RNG_BUS}"]
    for path, addr in media:
        cmd += ["-device", f"loader,file={path},addr={addr:#x},force-raw=on"]
    cmd += ["-chardev", chardev, "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
            "-device", "tpm-tis-device,tpmdev=tpm0"]
    cmd += ["-device", f"virtio-net-device,netdev=n0,mac={OUTSIDE_MAC.hex(':')},bus={OUTSIDE_BUS}",
            "-netdev", f"{outside},id=n0",
            "-device", f"virtio-net-device,netdev=n1,mac={INSIDE_MAC.hex(':')},bus={INSIDE_BUS}",
            "-netdev", f"{inside},id=n1"]
    return cmd


def swtpm(state_dir: str, key, ctrl, launcher: bool = False) -> list:
    """The swtpm argv (without the program name): TPM 2.0, the state in
    `state_dir`, encrypted with `key` (H2), the ctrl channel the only one
    (QEMU passes the data channel over it, so no server socket exists).
    Harness form: `ctrl` is a socket path (mode 0600), `key` a file. Launcher
    form: both are inherited fds."""
    if launcher:
        ctrl_arg, key_arg = f"type=unixio,clientfd={int(ctrl)}", f"fd={int(key)},mode=aes-256-cbc"
    else:
        ctrl_arg, key_arg = f"type=unixio,path={ctrl},mode=0600", f"file={key},mode=aes-256-cbc"
    return ["socket", "--tpm2", "--tpmstate", f"dir={state_dir}", "--ctrl", ctrl_arg, "--key", key_arg]


def _keys(value: str) -> dict:
    """The `key=value` fields of one option value (a bare field maps to
    None)."""
    return dict((f.split("=", 1) + [None])[:2] for f in value.split(","))


def _value_problems(name: str, value: str, launcher: bool) -> list:
    """What is wrong with the value of one allowed QEMU option, `name`
    without its dash."""
    head, keys = value.split(",", 1)[0], _keys(value)
    if name == "machine":
        found = [] if head == MACHINE_TYPE else [f"machine {head}"]
    elif name == "accel":
        found = [] if value in ACCELS else [f"accelerator {value}"]
    elif name == "cpu":
        found = [] if value in CPU.values() else [f"cpu {value}"]
    elif name == "monitor":
        found = [] if value == "none" else ["-monitor other than none"]
    elif name == "display":
        found = [] if value == "none" else ["-display other than none"]
    elif name == "serial":
        found = [] if value == "chardev:serial0" else ["-serial other than chardev:serial0"]
    elif name == "overcommit":
        found = [] if value == "mem-lock=on" else [f"overcommit {value}"]
    elif name == "chardev":
        if head == "stdio":
            found = []
        elif head == "socket":
            want = "fd" if launcher else "path"
            found = [] if want in keys else [f"a socket chardev without {want}="]
        else:
            found = [f"chardev {head}"]
    elif name == "netdev":
        if launcher:
            ok = head == "tap" and set(keys) == {"tap", "fd", "id"}
            found = [] if ok else [f"netdev {value} (the launcher's are tap,fd= alone)"]
        else:
            found = [] if head in _HARNESS_NETDEVS else [f"netdev {head}"]
    elif name == "device":
        # The driver is the first field, or a driver= key anywhere.
        drivers = ([] if "=" in value.split(",", 1)[0] else [head]) + \
            [v for k, v in (f.split("=", 1) for f in value.split(",") if "=" in f) if k == "driver"]
        found = [f"device {d}" for d in drivers if d not in DEVICES] or ([] if drivers else ["a device without a driver"])
    elif name == "object":
        found = [] if head == "rng-random" else [f"object {head}"]
    elif name == "tpmdev":
        found = [] if head == "emulator" else [f"tpmdev {head}"]
    elif name == "bios":
        found = [] if not launcher or _INHERITED_FD.fullmatch(value) else ["-bios other than /dev/fd/<n>"]
    else:
        found = []
    return found


def violations(argv: list, launcher: bool = False) -> list:
    """I1.2 over one rendered argv (QEMU's, or swtpm's, which starts with
    its `socket` subcommand): every option outside the allowlist, every
    allowed option's value outside the rendered forms, and every forbidden
    key. A leading `--` counts as `-` (QEMU takes both). Empty means the
    argv is admissible."""
    swtpm_argv = argv[:1] == ["socket"]
    found = []
    i = 1 if swtpm_argv else 0
    while i < len(argv):
        arg = argv[i]
        if not arg.startswith("-"):
            found.append(f"positional {arg}")
            i += 1
            continue
        name = arg[2:] if arg.startswith("--") else arg[1:]
        if swtpm_argv:
            known, takes_value = name in _SWTPM_OPTIONS, _SWTPM_OPTIONS.get(name, True)
        else:
            known, takes_value = name in _QEMU_OPTIONS, True
        value = argv[i + 1] if takes_value and i + 1 < len(argv) and not argv[i + 1].startswith("-") else None
        if not known:
            # Its value, if any, goes with it, not counted as a positional.
            found.append(f"-{name}")
        elif takes_value and value is None:
            found.append(f"-{name} without a value")
        elif value is not None and swtpm_argv:
            if name == "ctrl" and not value.startswith("type=unixio,"):
                found.append("a swtpm ctrl other than unixio")
            if name == "key" and _keys(value).get("mode") != "aes-256-cbc":
                found.append("a swtpm key other than aes-256-cbc")
        elif value is not None:
            found += _value_problems(name, value, launcher)
            if name == "machine" and "virtualization=on" in value.split(",") \
                    and argv[i + 2:i + 4] != ["-accel", "tcg"]:
                found.append("virtualization=on outside tcg")
        for text in (arg, value) if value is not None else (arg,):
            for pattern, label in _FORBIDDEN + (_LAUNCHER_FORBIDDEN if launcher else ()):
                if pattern.search(text):
                    found.append(label)
        i += 2 if value is not None else 1
    if swtpm_argv and not {"--key", "-key"} & set(argv):
        found.append("swtpm without key")
    return found


# The launcher's fd layout (M9 plan C4): kozane-vm places each resource at
# exactly this number in the child, so the argv below is final as rendered.
LAUNCHER_QEMU_FDS = {"firmware": 3, "tpm": 4, "outside": 5, "inside": 6}
LAUNCHER_SWTPM_FDS = {"ctrl": 3, "key": 4}
# The boot media, from the node directory, in the harness's order
# (run.py's Package.media), each on its own fd after the fixed ones.
LAUNCHER_MEDIA = ("published.img", "boot.desc", "secrets.env", "pq_secrets.env", "tls_secrets.env",
                  "audit_secrets.env", "slot-a.bin", "slot-b.bin")
LAUNCHER_SWTPM_STATE = "/var/lib/kozane/swtpm"


def launcher_addrs() -> tuple:
    """Where QEMU loads each of LAUNCHER_MEDIA, in order."""
    import measure
    return (measure.LOAD_IMAGE, measure.LOAD_DESC) + measure.LOADS


def render_launcher_args(out=None) -> dict:
    """Write the launcher form of `machine("kvm", ...)` and `swtpm(...)`,
    with the fd layout and the media names, to build/host/vm-args.json:
    kozane-vm embeds that file at build time, so this module stays the one
    source of its argv (M9 plan C4)."""
    import json
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    out = pathlib.Path(out) if out else root / "build/host/vm-args.json"
    q, s = LAUNCHER_QEMU_FDS, LAUNCHER_SWTPM_FDS
    first = max(q.values()) + 1
    fds = range(first, first + len(LAUNCHER_MEDIA))
    media = [(f"/dev/fd/{fd}", addr) for fd, addr in zip(fds, launcher_addrs(), strict=True)]
    args = {
        "qemu": machine("kvm", f"/dev/fd/{q['firmware']}", q["tpm"], (q["outside"], q["inside"]),
                        media=media, launcher=True),
        "qemu_fds": q,
        "media": [{"name": name, "fd": fd} for name, fd in zip(LAUNCHER_MEDIA, fds, strict=True)],
        "swtpm": swtpm(LAUNCHER_SWTPM_STATE, s["key"], s["ctrl"], launcher=True),
        "swtpm_fds": s,
        "swtpm_state": LAUNCHER_SWTPM_STATE,
    }
    found = violations(args["qemu"], launcher=True) + violations(args["swtpm"], launcher=True)
    if found:
        raise ValueError(f"vm: forbidden argument {found}")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(args, indent=1, sort_keys=True) + "\n")
    return args
