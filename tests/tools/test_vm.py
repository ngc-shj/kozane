"""tools/vm.py (M9 plan C1): I1.1, the tcg and kvm argv differ only where
D2 and deviation D-2 allow; I1.2, no rendered argv carries a forbidden
option, value or device, and `violations` refuses each kind when it is
injected (paired with the clean argv it is injected into).

Usage: python3 tests/tools/test_vm.py
Prints "VM-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import vm  # noqa: E402

MEDIA = [("/m/loader.img", 0x70000000), ("/m/boot.desc", 0x6ff00000)]
HARNESS = dict(firmware="/b/u-boot.bin", tpm="/t/ctrl.sock",
               netdevs=("socket,udp=127.0.0.1:1,localaddr=127.0.0.1:2", "socket,udp=127.0.0.1:3,localaddr=127.0.0.1:4"),
               media=MEDIA)
# The launcher form at the launcher's own fd layout (I1.2 pins it).
_Q, _S = vm.LAUNCHER_QEMU_FDS, vm.LAUNCHER_SWTPM_FDS
_FIRST = max(_Q.values()) + 1
LAUNCHER = dict(firmware=f"/dev/fd/{_Q['firmware']}", tpm=_Q["tpm"], netdevs=(_Q["outside"], _Q["inside"]),
                media=[(f"/dev/fd/{_FIRST + i}", a) for i, a in enumerate(vm.launcher_addrs())], launcher=True)
LAUNCHER_SWTPM = vm.swtpm(vm.LAUNCHER_SWTPM_STATE, _S["key"], _S["ctrl"], launcher=True)


def differing(a: list, b: list) -> list:
    """The positions where two argv of the same shape differ."""
    if len(a) != len(b):
        return ["length"]
    return [a[i - 1] for i in range(len(a)) if a[i] != b[i]]


def inject(argv: list, at: int, extra: list) -> list:
    return argv[:at] + extra + argv[at:]


def main() -> int:
    failures = 0
    cases = 0

    def check(name: str, ok: bool, detail=""):
        nonlocal failures, cases
        cases += 1
        if ok:
            print(f"ok   {name}")
        else:
            failures += 1
            print(f"FAIL {name}: {detail}")

    tcg = vm.machine("tcg", **HARNESS)
    kvm = vm.machine("kvm", **HARNESS)
    # I1.1: only -machine (virtualization=on for tcg), -accel and -cpu.
    diff = differing(tcg, kvm)
    check("I1.1 tcg and kvm differ only in -machine, -accel and -cpu", diff == ["-machine", "-accel", "-cpu"],
          f"vm: tcg and kvm argv differ at {diff}")
    tcg_props = tcg[tcg.index("-machine") + 1].split(",")
    kvm_props = kvm[kvm.index("-machine") + 1].split(",")
    check("I1.1 the machine strings differ only by virtualization=on",
          sorted(set(tcg_props) ^ set(kvm_props)) == ["virtualization=on"] and "virtualization=on" in tcg_props,
          (tcg_props, kvm_props))
    check("the machine is the pinned virt-9.0 with GICv3", kvm_props[0] == "virt-9.0" and "gic-version=3" in kvm_props,
          kvm_props)
    check("the launcher form locks guest RAM, the harness form does not",
          "mem-lock=on" in vm.machine("kvm", **LAUNCHER) and "mem-lock=on" not in kvm)
    try:
        vm.machine("hvf", **HARNESS)
        check("an unknown accelerator raises", False, "no error")
    except ValueError:
        check("an unknown accelerator raises", True)

    # Clean argv are admissible (the allow side of every deny case below).
    for name, argv, launcher in [
        ("harness tcg", tcg, False), ("harness kvm", kvm, False),
        ("launcher kvm, with media", vm.machine("kvm", **LAUNCHER), True),
        ("harness swtpm", vm.swtpm("/s", "/k", "/t/ctrl.sock"), False),
        ("launcher swtpm", LAUNCHER_SWTPM, True),
    ]:
        check(f"I1.2 {name} is admissible", vm.violations(argv, launcher) == [], vm.violations(argv, launcher))
    # H2: the swtpm state is encrypted in both forms.
    for name, argv in [("harness", vm.swtpm("/s", "/k", "/t/ctrl.sock")), ("launcher", LAUNCHER_SWTPM)]:
        check(f"the {name} swtpm encrypts its state", "--key" in argv, f"vm: swtpm without key: {argv}")
    check("rng=False drops only the RNG device",
          [a for a in kvm if a not in vm.machine("kvm", rng=False, **HARNESS)] ==
          ["-object", "rng-random,id=rng0,filename=/dev/urandom", f"virtio-rng-device,rng=rng0,bus={vm.RNG_BUS}"])

    # I1.2 deny cases: each injection must be refused, with its label.
    at = kvm.index("-bios")
    for name, argv, launcher, want in [
        ("-gdb", inject(kvm, at, ["-gdb", "tcp::1234"]), False, "-gdb"),
        ("-s", inject(kvm, at, ["-s"]), False, "-s"),
        ("-qmp", inject(kvm, at, ["-qmp", "unix:/q,server=on"]), False, "-qmp"),
        ("a monitor", inject(kvm, at, ["-monitor", "unix:/m,server"]), False, "-monitor other than none"),
        ("a muxed serial", inject(kvm, at, ["-serial", "mon:stdio"]), False, "mon:"),
        ("a stdio chardev that a 0x03 can kill", inject(kvm, at, ["-chardev", "stdio,id=c"]), False,
         "a stdio chardev without signal=off"),
        ("secure=on", inject(kvm, at, ["-machine", "virt,secure=on"]), False, "secure=on"),
        ("virtualization=on under kvm",
         ["-machine", vm._machine_string("tcg"), "-accel", "kvm"] + kvm[4:], False, "virtualization=on outside tcg"),
        ("a device outside the list", inject(kvm, at, ["-device", "virtio-gpu-device"]), False,
         "device virtio-gpu-device"),
        ("a device named by driver=", inject(kvm, at, ["-device", "driver=virtio-gpu-device"]), False,
         "device virtio-gpu-device"),
        ("--qmp (QEMU's double-dash spelling)", inject(kvm, at, ["--qmp", "unix:/q,server=on"]), False, "-qmp"),
        ("an HMP -mon", inject(kvm, at, ["-mon", "chardev=x"]), False, "-mon"),
        ("a serial on tcp", inject(kvm, at, ["-serial", "tcp::4444,server=on"]), False,
         "-serial other than chardev:serial0"),
        ("a serial on telnet", inject(kvm, at, ["-serial", "telnet::1"]), False, "-serial other than chardev:serial0"),
        ("a stray positional (a drive image)", inject(kvm, at, ["/tmp/disk.img"]), False, "positional /tmp/disk.img"),
        ("a pty chardev", inject(kvm, at, ["-chardev", "pty,id=p"]), False, "chardev pty"),
        ("a netdev outside run.py's", inject(kvm, at, ["-netdev", "vhost-user,id=v,chardev=c"]), False,
         "netdev vhost-user"),
        ("a launcher netdev other than tap,fd=",
         inject(vm.machine("kvm", **LAUNCHER), at, ["-netdev", "tap,ifname=t0,id=n2"]), True,
         "netdev tap,ifname=t0,id=n2 (the launcher's are tap,fd= alone)"),
        ("a swtpm option outside the list", vm.swtpm("/s", "/k", "/c") + ["--flags", "not-need-init"], False, "-flags"),
        ("swtpm over tcp", vm.swtpm("/s", "/k", "/c")[:-2] + ["--server", "type=tcp,port=2321"], False, "type=tcp"),
        ("a path= in the launcher form",
         inject(vm.machine("kvm", **LAUNCHER), at, ["-chardev", "socket,id=x,path=/tmp/x"]), True, "path="),
        ("a file= key in the launcher form", LAUNCHER_SWTPM[:-1] + ["file=/k,mode=aes-256-cbc"],
         True, "file= other than /dev/fd/<n>"),
        # S1: a loader that sets the CPU's PC (cpu-num=, or an ELF entry when
        # not raw) would start the guest in boot media, not the pinned firmware.
        ("a loader that sets the CPU's PC",
         inject(kvm, at, ["-device", "loader,file=/m/x,addr=0x70000000,force-raw=on,cpu-num=0"]), False,
         "device loader key cpu-num"),
        ("a loader without force-raw", inject(kvm, at, ["-device", "loader,file=/m/x,addr=0x70000000"]), False,
         "device loader without force-raw="),
        ("a loader with force-raw=off",
         inject(kvm, at, ["-device", "loader,file=/m/x,addr=0x70000000,force-raw=off"]), False,
         "device loader without force-raw=on"),
        ("a device key outside its driver's set",
         inject(kvm, at, ["-device", "virtio-net-device,netdev=n0,mac=02:00:00:00:00:01,bus=b,romfile=/x"]), False,
         "device virtio-net-device key romfile"),
        ("a repeated device key",
         inject(kvm, at, ["-device", "tpm-tis-device,tpmdev=tpm0,tpmdev=tpm1"]), False,
         "device tpm-tis-device,tpmdev=tpm0,tpmdev=tpm1 (a repeated key tpmdev)"),
        # S3: the guest's entropy comes from /dev/urandom alone.
        # Code review N2/S6: a bare field is `x=on`, `nox` is `x=off` in QEMU.
        ("a bare no<key> that turns force-raw off",
         inject(kvm, at, ["-device", "loader,file=/m/x,addr=0x70000000,force-raw=on,noforce-raw"]), False,
         "device loader,file=/m/x,addr=0x70000000,force-raw=on,noforce-raw (a bare field 'noforce-raw')"),
        ("a bare flag on a net device",
         inject(kvm, at, ["-device", "virtio-net-device,netdev=n0,mac=02:00:00:00:00:01,bus=b,packed"]), False,
         "device virtio-net-device,netdev=n0,mac=02:00:00:00:00:01,bus=b,packed (a bare field 'packed')"),
        ("an empty field", inject(kvm, at, ["-device", "tpm-tis-device,,tpmdev=tpm0"]), False,
         "device tpm-tis-device,,tpmdev=tpm0 (a bare field '')"),
        ("a launcher loader at an address it does not render",
         inject(vm.machine("kvm", **LAUNCHER), at, ["-device", "loader,file=/dev/fd/11,addr=0x40000000,force-raw=on"]),
         True, "device loader,file=/dev/fd/11,addr=0x40000000,force-raw=on (not a launcher medium's fd at its address)"),
        # Code review round 3: QemuOpts' bare fields and repeated keys on
        # every option, not -device alone, and the rendered values exactly.
        ("a bare secure on the machine",
         ["-machine", vm._machine_string("kvm") + ",secure"] + kvm[2:], False,
         f"machine {vm._machine_string('kvm')},secure (a bare field 'secure')"),
        ("a bare mux on the console",
         [a if a != "stdio,id=serial0,signal=off" else "stdio,id=serial0,signal=off,mux" for a in kvm], False,
         "chardev stdio,id=serial0,signal=off,mux (a bare field 'mux')"),
        ("mem-merge turned back on by a repeated key",
         ["-machine", vm._machine_string("kvm") + ",mem-merge=on"] + kvm[2:], False,
         f"machine {vm._machine_string('kvm')},mem-merge=on (a repeated key mem-merge)"),
        ("dump-guest-core turned back on by a repeated key",
         ["-machine", vm._machine_string("kvm") + ",dump-guest-core=on"] + kvm[2:], False,
         f"machine {vm._machine_string('kvm')},dump-guest-core=on (a repeated key dump-guest-core)"),
        ("the console's signal turned back on by a repeated key",
         [a if a != "stdio,id=serial0,signal=off" else "stdio,id=serial0,signal=off,signal=on" for a in kvm], False,
         "chardev stdio,id=serial0,signal=off,signal=on (a repeated key signal)"),
        ("a machine property machine() does not render",
         ["-machine", vm._machine_string("kvm") + ",highmem=off"] + kvm[2:], False,
         f"machine {vm._machine_string('kvm')},highmem=off (not the rendered machine)"),
        ("a TPM socket with another key",
         [a if not a.startswith("socket,id=chrtpm,path=") else a + ",server=on" for a in kvm], False,
         "chardev socket,id=chrtpm,path=/t/ctrl.sock,server=on (socket,id=chrtpm,path= alone)"),
        # Code review round 4: each value bound, not only each key named.
        ("the outside and inside NICs swapped",
         [a.replace("netdev=n0", "netdev=@").replace("netdev=n1", "netdev=n0").replace("netdev=@", "netdev=n1")
          if a.startswith("virtio-net-device") else a for a in kvm], False,
         f"device virtio-net-device,netdev=n1,mac={vm.OUTSIDE_MAC.hex(':')},bus={vm.OUTSIDE_BUS} (not a rendered virtio-net-device)"),
        ("a launcher medium at another medium's address",
         [a.replace(f"addr={vm.launcher_addrs()[0]:#x}", "addr=@").replace(f"addr={vm.launcher_addrs()[1]:#x}",
                    f"addr={vm.launcher_addrs()[0]:#x}").replace("addr=@", f"addr={vm.launcher_addrs()[1]:#x}")
          for a in vm.machine("kvm", **LAUNCHER)], True,
         f"device loader,file=/dev/fd/{_FIRST},addr={vm.launcher_addrs()[1]:#x},force-raw=on "
         "(not a launcher medium's fd at its address)"),
        ("an rng on another bus", inject(kvm, at, ["-device", "virtio-rng-device,rng=rng0,bus=virtio-mmio-bus.7"]), False,
         "device virtio-rng-device,rng=rng0,bus=virtio-mmio-bus.7 (not a rendered virtio-rng-device)"),
        ("a TPM device on another backend", inject(kvm, at, ["-device", "tpm-tis-device,tpmdev=tpm1"]), False,
         "device tpm-tis-device,tpmdev=tpm1 (not a rendered tpm-tis-device)"),
        ("-m other than the rendered size", [a if a != vm.MEMORY else "64G" for a in kvm], False, "-m 64G (not size=2G)"),
        ("-m with maxmem", [a if a != vm.MEMORY else "size=2G,maxmem=4G" for a in kvm], False,
         "-m size=2G,maxmem=4G (not size=2G)"),
        ("a tpmdev on the console's chardev", [a if a != vm.TPMDEV else "emulator,id=tpm0,chardev=serial0" for a in kvm],
         False, "tpmdev emulator,id=tpm0,chardev=serial0 (not emulator,id=tpm0,chardev=chrtpm)"),
        ("a tpmdev with another key", [a if a != vm.TPMDEV else vm.TPMDEV + ",x-data=on" for a in kvm], False,
         "tpmdev emulator,id=tpm0,chardev=chrtpm,x-data=on (not emulator,id=tpm0,chardev=chrtpm)"),
        ("kvm's machine string under tcg", [a if a != vm._machine_string("tcg") else vm._machine_string("kvm") for a in tcg],
         False, f"machine {vm._machine_string('kvm')} (not tcg's)"),
        ("tcg's CPU under kvm", [a if a != vm.CPU["kvm"] else vm.CPU["tcg"] for a in kvm], False,
         f"cpu {vm.CPU['tcg']} (not kvm's)"),
        ("-m given twice", inject(kvm, at, ["-m", vm.MEMORY]), False, "-m given 2 times"),
        ("the launcher's taps swapped",
         [a.replace(f"tap,fd={_Q['outside']},id=n0", f"tap,fd={_Q['inside']},id=n0").replace(
             f"tap,fd={_Q['inside']},id=n1", f"tap,fd={_Q['outside']},id=n1") for a in vm.machine("kvm", **LAUNCHER)], True,
         f"netdev tap,fd={_Q['inside']},id=n0 (not the outside tap as n0 or the inside tap as n1)"),
        ("a launcher firmware on another fd",
         [a if a != f"/dev/fd/{_Q['firmware']}" else f"/dev/fd/{_Q['inside']}" for a in vm.machine("kvm", **LAUNCHER)], True,
         f"-bios /dev/fd/{_Q['inside']} (not the firmware's fd)"),
        ("a launcher TPM socket on another fd",
         [a if a != f"socket,id=chrtpm,fd={_Q['tpm']}" else f"socket,id=chrtpm,fd={_Q['firmware']}"
          for a in vm.machine("kvm", **LAUNCHER)], True, f"chardev socket,id=chrtpm,fd={_Q['firmware']} (not the TPM socket's fd)"),
        ("a launcher swtpm ctrl on another fd",
         [a if a != f"type=unixio,clientfd={_S['ctrl']}" else f"type=unixio,clientfd={_S['key']}" for a in LAUNCHER_SWTPM], True,
         f"a swtpm ctrl type=unixio,clientfd={_S['key']} (not the TPM socket's fd)"),
        ("a launcher swtpm key on another fd", LAUNCHER_SWTPM[:-1] + [f"fd={_S['ctrl']},mode=aes-256-cbc"], True,
         f"a swtpm key fd={_S['ctrl']},mode=aes-256-cbc (not the key's fd)"),
        ("an rng backend other than /dev/urandom",
         inject(kvm, at, ["-object", "rng-random,id=r1,filename=/dev/zero"]), False,
         "object rng-random,id=r1,filename=/dev/zero (rng-random,id=,filename=/dev/urandom alone)"),
        ("a bridge helper in the launcher form",
         inject(vm.machine("kvm", **LAUNCHER), at, ["-netdev", "bridge,br=br0,helper=/usr/lib/qemu-bridge-helper"]),
         True, "helper="),
    ]:
        got = vm.violations(argv, launcher)
        check(f"I1.2 {name} is refused", want in got, got)

    # Code review round 5: every part machine() and swtpm() always render is
    # required, exactly once; each one dropped is refused by name.
    def drop(argv: list, name: str, value=None) -> list:
        for i, a in enumerate(argv):
            if a == f"-{name}" or a == f"--{name}":
                has_value = i + 1 < len(argv) and not argv[i + 1].startswith("-")
                if value is None or (has_value and argv[i + 1] == value):
                    return argv[:i] + argv[i + 2 if has_value else i + 1:]
        raise AssertionError(f"test_vm: no -{name} {value} to drop")

    launcher_kvm = vm.machine("kvm", **LAUNCHER)
    tpm_socket = next(a for a in kvm if a.startswith("socket,id=chrtpm,"))
    nic = {nid: next(a for a in kvm if a.startswith(f"virtio-net-device,netdev={nid},")) for nid in ("n0", "n1")}
    netdev = {nid: next(a for a in kvm if a.endswith(f",id={nid}")) for nid in ("n0", "n1")}
    missing = [(f"-{n}", drop(kvm, n), False, f"-{n} given 0 times") for n in vm._ONCE]
    missing += [
        ("-overcommit (launcher)", drop(launcher_kvm, "overcommit"), True, "-overcommit given 0 times, want 1"),
        ("-tpmdev", drop(kvm, "tpmdev"), False, f"-tpmdev {vm.TPMDEV} given 0 times"),
        ("the console chardev", drop(kvm, "chardev", "stdio,id=serial0,signal=off"), False,
         "-chardev stdio,id=serial0,signal=off given 0 times"),
        ("the TPM socket chardev", drop(kvm, "chardev", tpm_socket), False, "the TPM socket chardev given 0 times"),
        ("the TPM device", drop(kvm, "device", "tpm-tis-device,tpmdev=tpm0"), False,
         "-device tpm-tis-device,tpmdev=tpm0 given 0 times"),
        ("the outside NIC", drop(kvm, "device", nic["n0"]), False, f"-device {nic['n0']} given 0 times"),
        ("the inside NIC", drop(kvm, "device", nic["n1"]), False, f"-device {nic['n1']} given 0 times"),
        ("the outside netdev", drop(kvm, "netdev", netdev["n0"]), False, "-netdev id=n0 given 0 times"),
        ("the inside netdev", drop(kvm, "netdev", netdev["n1"]), False, "-netdev id=n1 given 0 times"),
        ("a launcher medium", drop(launcher_kvm, "device", LAUNCHER["media"][0][0].join(["loader,file=", ""])
                                  + f",addr={LAUNCHER['media'][0][1]:#x},force-raw=on"), True,
         f"-device loader,file={LAUNCHER['media'][0][0]},addr={LAUNCHER['media'][0][1]:#x},force-raw=on given 0 times"),
    ]
    missing += [(f"swtpm --{n}", drop(LAUNCHER_SWTPM, n), True, f"-{n} given 0 times") for n in ("tpm2", "tpmstate", "ctrl", "key")]
    rng_object = ("object", "rng-random,id=rng0,filename=/dev/urandom")
    rng_device = ("device", f"virtio-rng-device,rng=rng0,bus={vm.RNG_BUS}")
    missing += [
        ("launcher rng backend", drop(launcher_kvm, *rng_object), True, "the rng backend given 0 times"),
        ("launcher rng device", drop(launcher_kvm, *rng_device), True,
         "an rng backend without a device, or a device without it (1, 0)"),
        ("harness rng backend (device kept)", drop(kvm, *rng_object), False,
         "an rng backend without a device, or a device without it (0, 1)"),
        ("harness rng device (backend kept)", drop(kvm, *rng_device), False,
         "an rng backend without a device, or a device without it (1, 0)"),
    ]
    for name, argv, launcher, want in missing:
        got = vm.violations(argv, launcher)
        check(f"I1.2 a missing {name} is refused", want in got, got)
    moved = [a if a != f"dir={vm.LAUNCHER_SWTPM_STATE}" else "dir=/tmp/attacker" for a in LAUNCHER_SWTPM]
    check("I1.2 a launcher swtpm state elsewhere is refused",
          f"a swtpm state dir=/tmp/attacker (not dir={vm.LAUNCHER_SWTPM_STATE})" in vm.violations(moved, True),
          vm.violations(moved, True))
    check("I1.2 the harness with neither rng half is admissible", vm.violations(vm.machine("kvm", rng=False, **HARNESS)) == [],
          vm.violations(vm.machine("kvm", rng=False, **HARNESS)))
    over = inject(kvm, at, ["-overcommit", "mem-lock=on"])
    check("I1.2 -overcommit in the harness form is refused", "-overcommit given 1 times, want 0" in vm.violations(over),
          vm.violations(over))

    # I1.2's chokepoint: render_launcher_args writes nothing for an argv
    # violations() refuses, and writes the clean one.
    with tempfile.TemporaryDirectory() as d:
        clean = pathlib.Path(d) / "clean.json"
        try:
            vm.render_launcher_args(out=clean)
            check("the clean launcher argv is rendered", clean.is_file())
        except ValueError as e:
            check("the clean launcher argv is rendered", False, str(e))
        bad = pathlib.Path(d) / "bad.json"
        real = vm.machine
        vm.machine = lambda *a, **k: real(*a, **k) + ["-gdb", "tcp::1234"]
        try:
            vm.render_launcher_args(out=bad)
            check("a forbidden launcher argv is not rendered", False, "rendered")
        except ValueError as e:
            check("a forbidden launcher argv is not rendered",
                  "vm: forbidden argument" in str(e) and not bad.exists(), str(e))
        finally:
            vm.machine = real

    # The vm-launcher-argv self-test case's drift must stay admissible, or a
    # tightening here pre-empts its needle (code review N1).
    drift = vm.machine("kvm", **LAUNCHER) + ["-device", f"virtio-rng-device,rng=rng0,bus={vm.RNG_BUS}"]
    check("the vm-launcher-argv drift is admissible", vm.violations(drift, True) == [], vm.violations(drift, True))

    print(f"VM-FIXTURES {cases}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
