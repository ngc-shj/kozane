"""tools/vm.py (M9 plan C1): I1.1, the tcg and kvm argv differ only where
D2 and deviation D-2 allow; I1.2, no rendered argv carries a forbidden
option, value or device, and `violations` refuses each kind when it is
injected (paired with the clean argv it is injected into).

Usage: python3 tests/tools/test_vm.py
Prints "VM-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import vm  # noqa: E402

MEDIA = [("/m/loader.img", 0x70000000), ("/m/boot.desc", 0x6ff00000)]
HARNESS = dict(firmware="/b/u-boot.bin", tpm="/t/ctrl.sock",
               netdevs=("socket,udp=127.0.0.1:1,localaddr=127.0.0.1:2", "socket,udp=127.0.0.1:3,localaddr=127.0.0.1:4"),
               media=MEDIA)
LAUNCHER = dict(firmware="/dev/fd/5", tpm=6, netdevs=(7, 8),
                media=[("/dev/fd/9", 0x70000000), ("/dev/fd/10", 0x6ff00000)], launcher=True)


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
        ("launcher swtpm", vm.swtpm("/s", 11, 12, launcher=True), True),
    ]:
        check(f"I1.2 {name} is admissible", vm.violations(argv, launcher) == [], vm.violations(argv, launcher))
    # H2: the swtpm state is encrypted in both forms.
    for name, argv in [("harness", vm.swtpm("/s", "/k", "/t/ctrl.sock")), ("launcher", vm.swtpm("/s", 11, 12, launcher=True))]:
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
        ("a file= key in the launcher form", vm.swtpm("/s", 11, 12, launcher=True)[:-1] + ["file=/k,mode=aes-256-cbc"],
         True, "file= other than /dev/fd/<n>"),
        ("a bridge helper in the launcher form",
         inject(vm.machine("kvm", **LAUNCHER), at, ["-netdev", "bridge,br=br0,helper=/usr/lib/qemu-bridge-helper"]),
         True, "helper="),
    ]:
        got = vm.violations(argv, launcher)
        check(f"I1.2 {name} is refused", want in got, got)

    print(f"VM-FIXTURES {cases}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
