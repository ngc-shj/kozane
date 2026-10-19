"""Each tools/package acceptance check must reject its one-change fixture and
accept the unmodified package (plan C16 acceptance [T8]).

Usage: python3 tests/tools/test_package.py
Prints "PACKAGE-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import contextlib
import importlib.machinery
import io
import importlib.util
import os
import pathlib
import shutil
import signal
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader("package", str(ROOT / "tools/package"))
spec = importlib.util.spec_from_loader("package", loader)
pkg = importlib.util.module_from_spec(spec)
loader.exec_module(pkg)

SYSTEM = """<system>
    <memory_region name="secrets" size="0x1000" prefill_path="placeholder.bin" />
    <memory_region name="ring" size="0x1000" />
    <protection_domain name="key" priority="140" passive="true">
        <program_image path="pd-key.elf" />
        <map mr="secrets" vaddr="0x8_000_000" perms="r" />
    </protection_domain>
</system>"""

BLOB = pkg.MAGIC + bytes(range(1, 101)) + bytes(pkg.REGION_SIZE - len(pkg.MAGIC) - 100)
PAD = bytes(5000)
PLACEHOLDER_IMG = b"\x7fELF" + PAD + bytes(pkg.REGION_SIZE) + PAD
PACKAGE_IMG = b"\x7fELF" + PAD + BLOB + PAD
GEN_DEBUG = "/* x */\n#define CONFIG_DEBUG_BUILD  1\n#define CONFIG_PRINTING  1\n"
GEN_RELEASE = "/* disabled: CONFIG_DEBUG_BUILD */\n/* disabled: CONFIG_PRINTING */\n"


def package_system(path="/elsewhere/secrets.bin"):
    return pkg.with_prefill(SYSTEM, path)


def flip(img: bytes, at: int) -> bytes:
    return img[:at] + bytes([img[at] ^ 1]) + img[at + 1:]


def tmp_tree():
    """A scratch directory outside the repo; each fixture removes its own."""
    return pathlib.Path(tempfile.mkdtemp(prefix="test-package-"))


def out_case(setup):
    def run():
        d = tmp_tree()
        try:
            return pkg.check_out_path(setup(d), ROOT)
        finally:
            shutil.rmtree(d)
    return run


def link_into_repo(d):
    (d / "link").symlink_to(ROOT / "build")
    return d / "link" / "pkg"


def secrets_in_cargo_home():
    d = tmp_tree()
    old = os.environ.get("CARGO_HOME")
    os.environ["CARGO_HOME"] = str(d)
    try:
        (d / "registry").mkdir()
        return pkg.check_secrets_path(d / "registry" / "s.bin", ROOT)
    finally:
        if old is None:
            del os.environ["CARGO_HOME"]
        else:
            os.environ["CARGO_HOME"] = old
        shutil.rmtree(d)


def secrets_symlink(target_in_repo: bool):
    def run():
        d = tmp_tree()
        try:
            target = ROOT / "build" / "secrets.bin" if target_in_repo else d / "real.bin"
            (d / "s.bin").symlink_to(target)
            return pkg.check_secrets_path(d / "s.bin", ROOT)
        finally:
            shutil.rmtree(d)
    return run


def run_main(build_result):
    """Runs `main()` past every check with `build` replaced: returns errors
    about OUT and leftover staging dirs (empty list when the outcome is the
    expected one for `build_result`)."""
    def run():
        d = tmp_tree()
        real_build, real_argv = pkg.build, sys.argv
        real_umask = os.umask(0o022)
        os.umask(real_umask)
        try:
            blob = d / "secrets.bin"
            blob.write_bytes(BLOB)
            gen = d / "gen_config.h"
            gen.write_text(GEN_DEBUG)
            out = d / "pkg"

            built = []

            def fake_build(a, secrets, blob_bytes, staging):
                built.append(1)
                (staging / "loader.img").write_bytes(b"image")
                if build_result == "raise":
                    raise RuntimeError("microkit failed")
                if build_result == "out-appears":
                    out.mkdir()
                    return 0
                if build_result in ("sigterm", "two-signals", "early-second-signal"):
                    os.kill(os.getpid(), signal.SIGTERM)
                if build_result == "sigint":
                    os.kill(os.getpid(), signal.SIGINT)
                if build_result == "signal-in-ignore-loop":
                    return 1
                if build_result == "exit-at-block":
                    # A handler already pending when the teardown blocks
                    # signals runs inside that call: simulate it raising
                    # there, as exit_on_signal would.
                    real_mask = signal.pthread_sigmask

                    def raising_once(how, mask):
                        signal.pthread_sigmask = real_mask
                        # As CPython does: the mask is set first, then the
                        # pending handler runs and raises.
                        real_mask(how, mask)
                        for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                            signal.signal(s, signal.SIG_IGN)
                        raise SystemExit(128 + signal.SIGTERM)
                    signal.pthread_sigmask = raising_once
                    return 1
                return build_result

            pkg.build = fake_build
            sys.argv = ["package", "--secrets", str(blob), "--out", str(out), "--system", "x", "--policy", "x",
                        "--image", "x", "--gen-config", str(gen), "--search-path", "x", "--board", "x",
                        "--config", "x", "--microkit", "x"]
            real_handlers = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
            real_sigmask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
            real_signal = signal.signal
            real_mask_fn = signal.pthread_sigmask
            if build_result == "signal-in-ignore-loop":
                # A signal landing between the teardown's per-signal SIG_IGN
                # calls: only blocking all three first keeps it out.
                sent = []

                def signal_then_other(s, h):
                    old = real_signal(s, h)
                    if h == signal.SIG_IGN and not sent:
                        # Right after the first SIG_IGN, a signal that is
                        # still handled (whatever the loop's order).
                        sent.append(signal.SIGTERM if s != signal.SIGTERM else signal.SIGHUP)
                        os.kill(os.getpid(), sent[0])
                    return old
                pkg.signal.signal = signal_then_other
            real_rmtree = pkg.shutil.rmtree
            if build_result in ("removal-fails", "signal-and-removal-fails"):
                # main()'s cleanup cannot remove the staging dir: it must say
                # so, even when a stop signal arrives during that removal.
                def cannot_remove(path, onexc=None, **_):
                    if build_result == "signal-and-removal-fails":
                        os.kill(os.getpid(), signal.SIGTERM)
                    if onexc:
                        onexc(None, str(path), PermissionError("denied"))
                pkg.shutil.rmtree = cannot_remove
            if build_result == "two-signals":
                # A second signal arrives while the staging dir is being removed.
                def second_signal(path, **kw):
                    os.kill(os.getpid(), signal.SIGTERM)
                    real_rmtree(path, **kw)
                pkg.shutil.rmtree = second_signal
            real_remove = pkg.remove_staging
            if build_result == "early-second-signal":
                # The second signal lands after the first ended the build and
                # before the removal: the teardown's own ignoring covers it
                # (exit_on_signal's ignoring is pinned by its own fixture).
                def remove_after_signal(staging):
                    os.kill(os.getpid(), signal.SIGTERM)
                    return real_remove(staging)
                pkg.remove_staging = remove_after_signal
            captured = io.StringIO()
            try:
                with contextlib.redirect_stdout(captured):
                    status = pkg.main()
            except RuntimeError:
                status = "raised"
            except SystemExit as e:
                status = f"exit {e.code}"
            finally:
                # Restored first: a patched pthread_sigmask must not run here.
                signal.pthread_sigmask = real_mask_fn
                signal.signal = real_signal
                pkg.shutil.rmtree = real_rmtree
                pkg.remove_staging = real_remove
                left_blocked = signal.pthread_sigmask(signal.SIG_SETMASK, real_sigmask)
                for s, h in real_handlers.items():
                    signal.signal(s, h)
            errors = []
            if [p for p in d.iterdir() if p.name.startswith(".pkg.")]:
                errors.append("staging directory left behind")
            if build_result == "out-appears":
                if status != 1 or list(out.iterdir()):
                    errors.append(f"OUT appearing during the build was not refused (status {status})")
            elif build_result == 0:
                if status != 0 or not (out / "loader.img").exists():
                    errors.append(f"success did not produce OUT (status {status})")
                elif oct(out.stat().st_mode & 0o777) != "0o700" or oct((out / "loader.img").stat().st_mode & 0o777) != "0o600":
                    errors.append("OUT or loader.img not owner-only")
            elif out.exists():
                errors.append(f"OUT exists after a failed build (status {status})")
            if not built:
                errors.append("main() returned before building")
            if left_blocked != real_sigmask:
                errors.append(f"main() left signals blocked: {sorted(left_blocked - real_sigmask)}")
            expected = {1: 1, "raise": "raised", "out-appears": 1, 0: 0, "signal-in-ignore-loop": 1}.get(build_result)
            if expected is not None and status != expected:
                errors.append(f"status {status}, want {expected}")
            if build_result in ("removal-fails", "signal-and-removal-fails"):
                if status != 1 or "could not remove staging directory" not in captured.getvalue():
                    errors.append(f"failed removal not reported (status {status})")
                # This variant deliberately leaves staging behind; clear the
                # expected leftover error and remove it here.
                errors = [e for e in errors if e != "staging directory left behind"]
                for p in d.iterdir():
                    if p.name.startswith(".pkg."):
                        shutil.rmtree(p)
            if build_result == "sigint" and status != f"exit {128 + signal.SIGINT}":
                errors.append(f"SIGINT did not end the run through SystemExit (status {status})")
            if build_result in ("sigterm", "two-signals", "early-second-signal", "exit-at-block") \
                    and status != f"exit {128 + signal.SIGTERM}":
                errors.append(f"SIGTERM did not end the run through SystemExit (status {status})")
            return errors
        finally:
            pkg.build, sys.argv = real_build, real_argv
            os.umask(real_umask)
            shutil.rmtree(d)
    return run


def staging_in_forbidden_root():
    """A forbidden root covering the parent (as if a path component had been
    swapped after the check): main() must refuse before building."""
    d = tmp_tree()
    real_roots, real_build, real_argv = pkg.forbidden_roots, pkg.build, sys.argv
    real_umask = os.umask(0o022)
    os.umask(real_umask)
    real_handlers = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
    built = []
    try:
        blob = d / "secrets.bin"
        blob.write_bytes(BLOB)
        gen = d / "gen_config.h"
        gen.write_text(GEN_DEBUG)
        calls = []

        def roots(repo):
            calls.append(1)
            # The first two calls are the blob and OUT checks; the third is
            # the staging re-check, which now sees `d` as forbidden.
            return real_roots(repo) + ([d.resolve()] if len(calls) > 2 else [])

        pkg.forbidden_roots = roots
        pkg.build = lambda *a: built.append(1) or 0
        sys.argv = ["package", "--secrets", str(blob), "--out", str(d / "pkg"), "--system", "x", "--policy", "x",
                    "--image", "x", "--gen-config", str(gen), "--search-path", "x", "--board", "x",
                    "--config", "x", "--microkit", "x"]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = pkg.main()
        errors = []
        if status != 1 or built or (d / "pkg").exists() or [p for p in d.iterdir() if p.name.startswith(".pkg.")]:
            errors.append(f"staging in a forbidden root was not refused cleanly (status {status}, built {built})")
        # Refused by the staging re-check itself, not by an earlier check.
        if "staging directory" not in out.getvalue() or len(calls) != 3:
            errors.append(f"refused by another check: {out.getvalue().strip()!r}, {len(calls)} root lookups")
        return errors
    finally:
        pkg.forbidden_roots, pkg.build, sys.argv = real_roots, real_build, real_argv
        os.umask(real_umask)
        for s, h in real_handlers.items():
            signal.signal(s, h)
        shutil.rmtree(d)


def failed_staging_removal_is_reported():
    d = tmp_tree()
    real_rmtree = pkg.shutil.rmtree
    try:
        staging = d / ".pkg.x"
        staging.mkdir()

        def broken(path, onexc=None):
            onexc(None, str(path), PermissionError("denied"))

        pkg.shutil.rmtree = broken
        ok = pkg.remove_staging(staging)
        return [] if ok is False else ["a failed removal was reported as success"]
    finally:
        pkg.shutil.rmtree = real_rmtree
        shutil.rmtree(d)


def signal_during_removal_does_not_cut_it_short():
    """A SIGTERM delivered while the staging dir is being removed must wait
    until the removal has finished (then end the run)."""
    d = tmp_tree()
    real_rmtree = pkg.shutil.rmtree
    real_handlers = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
    signal.signal(signal.SIGTERM, pkg.exit_on_signal)
    try:
        staging = d / ".pkg.x"
        (staging / "sub").mkdir(parents=True)
        (staging / "sub" / "loader.img").write_bytes(b"secret image")

        def interrupted(path, onexc=None):
            os.kill(os.getpid(), signal.SIGTERM)
            real_rmtree(path, onexc=onexc)

        pkg.shutil.rmtree = interrupted
        try:
            pkg.remove_staging(staging)
            ended = False
        except SystemExit:
            ended = True
        errors = []
        if staging.exists():
            errors.append("staging survived a signal during its removal")
        if not ended:
            errors.append("the signal was lost instead of ending the run after the removal")
        return errors
    finally:
        pkg.shutil.rmtree = real_rmtree
        for s, h in real_handlers.items():
            signal.signal(s, h)
        shutil.rmtree(d)


def handler_ignores_further_signals():
    """exit_on_signal must stop listening before it raises: the unwinding
    up to the teardown's `finally` is otherwise exposed to a second signal."""
    stop = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
    saved = {s: signal.getsignal(s) for s in stop}
    try:
        try:
            pkg.exit_on_signal(signal.SIGTERM, None)
            return ["exit_on_signal returned instead of raising SystemExit"]
        except SystemExit as e:
            if e.code != 128 + signal.SIGTERM:
                return [f"exit code {e.code}"]
        still = [signal.Signals(s).name for s in stop if signal.getsignal(s) != signal.SIG_IGN]
        return [f"still handled after the first signal: {still}"] if still else []
    finally:
        for s, h in saved.items():
            signal.signal(s, h)


def existing_out(d):
    (d / "pkg").mkdir()
    return d / "pkg"


# (name, expected error substring or None for accept, check)
CASES = [
    ("real package accepted", None,
     lambda: pkg.check_systems(SYSTEM, package_system()) + pkg.check_images(PLACEHOLDER_IMG, PACKAGE_IMG, BLOB)
     + pkg.check_blob(BLOB) + pkg.require_debug(GEN_DEBUG)),
    ("empty image diff", "identical to the placeholder", lambda: pkg.check_images(PLACEHOLDER_IMG, PLACEHOLDER_IMG, BLOB)),
    ("image diff outside the blob", "differs outside the blob",
     lambda: pkg.check_images(PLACEHOLDER_IMG, flip(PACKAGE_IMG, 2), BLOB)),
    ("image diff just past the blob", "differs outside the blob",
     lambda: pkg.check_images(PLACEHOLDER_IMG, flip(PACKAGE_IMG, 4 + len(PAD) + len(BLOB)), BLOB)),
    ("image length changed", "length changed", lambda: pkg.check_images(PLACEHOLDER_IMG, PACKAGE_IMG + b"\0", BLOB)),
    ("placeholder not zero under the blob", "not zero where the blob lands",
     lambda: pkg.check_images(flip(PLACEHOLDER_IMG, 4 + len(PAD) + 200), PACKAGE_IMG, BLOB)),
    # A second copy present at the same offset in both images: no extra
    # diff, so only the uniqueness clause can reject it.
    ("blob appears twice", "exactly once",
     lambda: pkg.check_images(PLACEHOLDER_IMG + BLOB, PACKAGE_IMG + BLOB, BLOB)),
    ("all-zero blob", "all zero", lambda: pkg.check_blob(bytes(pkg.REGION_SIZE))),
    ("short blob", "expected 4096", lambda: pkg.check_blob(BLOB[:-1])),
    ("blob without magic", "no secrets magic", lambda: pkg.check_blob(b"X" + BLOB[1:])),
    ("other attribute changed", "attributes of <protection_domain>",
     lambda: pkg.check_systems(SYSTEM, package_system().replace('priority="140"', 'priority="141"'))),
    ("other mr's attribute changed", "attributes of <memory_region>",
     lambda: pkg.check_systems(SYSTEM, package_system().replace('name="ring" size="0x1000"', 'name="ring" size="0x2000"'))),
    ("element added", "children",
     lambda: pkg.check_systems(SYSTEM, package_system().replace("</system>", '<memory_region name="x" size="0x1000" /></system>'))),
    ("non-debug kernel", "not debug", lambda: pkg.require_debug(GEN_RELEASE)),
    ("secrets path inside the repo", "inside", lambda: pkg.check_secrets_path(ROOT / "build/secrets.bin", ROOT)),
    ("secrets path outside the repo", None, lambda: pkg.check_secrets_path(pathlib.Path("/tmp/s.bin"), ROOT)),
    ("secrets path inside the cargo home", "inside", secrets_in_cargo_home),
    ("secrets path through a symlink into the repo", "inside", secrets_symlink(True)),
    ("secrets path through a symlink outside the repo", None, secrets_symlink(False)),
    ("successful build is renamed into place owner-only", None, run_main(0)),
    ("failed build leaves no OUT and no staging", None, run_main(1)),
    ("crashing build leaves no OUT and no staging", None, run_main("raise")),
    ("OUT appearing during the build is refused, staging removed", None, run_main("out-appears")),
    ("SIGTERM during the build leaves no OUT and no staging", None, run_main("sigterm")),
    ("a second SIGTERM during cleanup does not cut it short", None, run_main("two-signals")),
    ("a second SIGTERM before the removal is ignored", None, run_main("early-second-signal")),
    ("the signal handler ignores further signals before raising", None, handler_ignores_further_signals),
    ("SIGINT during the build leaves no OUT and no staging", None, run_main("sigint")),
    ("an exit raised as the teardown blocks signals waits for the removal", None, run_main("exit-at-block")),
    ("a signal between the teardown's ignore calls cannot skip the removal", None, run_main("signal-in-ignore-loop")),
    ("main() reports a staging dir it could not remove", None, run_main("removal-fails")),
    ("a signal during a failing removal does not hide the report", None, run_main("signal-and-removal-fails")),
    ("staging that resolves into a forbidden root is refused", None, staging_in_forbidden_root),
    ("a failed staging removal fails loudly", None, failed_staging_removal_is_reported),
    ("a signal during the staging removal waits for it", None, signal_during_removal_does_not_cut_it_short),
    ("output inside build/", "inside", lambda: pkg.check_out_path(ROOT / "build/pkg", ROOT)),
    ("output inside the repo", "inside", lambda: pkg.check_out_path(ROOT / "pkg-out", ROOT)),
    ("output through a symlink into the repo", "inside", out_case(link_into_repo)),
    ("output directory already exists", "already exists", out_case(existing_out)),
    ("fresh output outside the repo", None, out_case(lambda d: d / "pkg")),
]


def main() -> int:
    failures = 0
    for name, want, run in CASES:
        errors = run()
        if want is None:
            ok = not errors
        else:
            ok = len(errors) == 1 and want in errors[0]
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {errors or 'accepted'}")
    print(f"PACKAGE-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
