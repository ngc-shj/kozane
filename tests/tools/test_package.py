"""Each tools/package acceptance check must reject its one-change fixture and
accept the unmodified package (plan C16 acceptance [T8]).

Usage: python3 tests/tools/test_package.py
Prints "PACKAGE-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import contextlib
import hashlib
import importlib.machinery
import io
import importlib.util
import os
import pathlib
import shutil
import signal
import sys
import tempfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader("package", str(ROOT / "tools/package"))
spec = importlib.util.spec_from_loader("package", loader)
pkg = importlib.util.module_from_spec(spec)
loader.exec_module(pkg)

SYSTEM = """<system>
    <memory_region name="secrets" size="0x1000" prefill_path="placeholder.bin" />
    <memory_region name="pq_secrets" size="0x4000" prefill_path="pq-placeholder.bin" />
    <memory_region name="ring" size="0x1000" />
    <protection_domain name="key" priority="140" passive="true">
        <program_image path="pd-key.elf" />
        <map mr="secrets" vaddr="0x8_000_000" perms="r" />
    </protection_domain>
    <protection_domain name="pqkey" priority="139" passive="true">
        <program_image path="pd-pqkey.elf" />
        <map mr="pq_secrets" vaddr="0x8_000_000" perms="r" />
    </protection_domain>
</system>"""


def seal(body: bytes, size: int) -> bytes:
    """As secret_blob's Writer::seal: checksum, then zero padding."""
    sealed = body + hashlib.blake2s(body).digest()
    return sealed + bytes(size - len(sealed))


def le32(n: int) -> bytes:
    return n.to_bytes(4, "little")


# `key` blob v2 with one peer; `pqkey` blob v1 (crates/secret-blob).
KEY_BODY = b"SOSSECR1" + le32(2) + le32(1) + bytes(range(1, 97))
BLOB = seal(KEY_BODY, 4096)
PQ_BODY = b"SOSPQKY1" + le32(1) + bytes((i * 7 + 3) % 256 for i in range(13904 - 12))
PQ_BLOB = seal(PQ_BODY, 16384)
BLOBS = {"secrets": BLOB, "pq_secrets": PQ_BLOB}
PAD = bytes(5000)
KEY_AT = 4 + len(PAD)
PQ_AT = KEY_AT + len(BLOB) + len(PAD)
PQ_END = PQ_AT + len(PQ_BLOB)
PLACEHOLDER_IMG = b"\x7fELF" + PAD + bytes(4096) + PAD + bytes(16384) + PAD
PACKAGE_IMG = b"\x7fELF" + PAD + BLOB + PAD + PQ_BLOB + PAD
SPANS = f"{KEY_AT:#x}..{KEY_AT + len(BLOB):#x}, {PQ_AT:#x}..{PQ_END:#x}"
GEN_DEBUG = "/* x */\n#define CONFIG_DEBUG_BUILD  1\n#define CONFIG_PRINTING  1\n"
GEN_RELEASE = "/* disabled: CONFIG_DEBUG_BUILD */\n/* disabled: CONFIG_PRINTING */\n"
SC20 = "package: kernel config is not debug; images are dev-only until release kernels are tested (SC20)"
WAIVERS_OPEN = '[[waivers]]\nid = "SC23"\nowner = "M4"\nstatus = "open"\n' \
    '[[waivers]]\nid = "SC9"\nowner = "M3b"\nstatus = "closed"\n'
WAIVERS_CLOSED = WAIVERS_OPEN.replace('"open"', '"closed"')
MISSING_WAIVERS = "package: waiver file unusable, refusing: cannot read <d>/waivers.toml: " \
    "[Errno 2] No such file or directory: '<d>/waivers.toml'"
SC23_OPEN = "package: waiver SC23 (owner M4) is open; non-debug kernels are refused until it closes"
SC23_BOUND = "package: Cargo.lock requires waiver SC23 to be open, but policy/waivers.toml does not list it as open"
LOCK_CMR = 'version = 4\n\n[[package]]\nname = "classic-mceliece-rust"\nversion = "2.0.2"\n'
LOCK_CMR_OTHER = LOCK_CMR.replace('"2.0.2"', '"2.0.3"')
LOCK_NO_CMR = 'version = 4\n\n[[package]]\nname = "zeroize"\nversion = "1.8.1"\n'


def package_system(path="/elsewhere/secrets.bin", pq_path="/elsewhere/pq.bin"):
    return pkg.with_prefill(SYSTEM, {"secrets": path, "pq_secrets": pq_path})


def flip(img: bytes, at: int) -> bytes:
    return img[:at] + bytes([img[at] ^ 1]) + img[at + 1:]


def resealed(blob: bytes, at: int, value: bytes, body: int) -> bytes:
    """`blob` with `value` written at `at`, its checksum recomputed."""
    changed = blob[:at] + value + blob[at + len(value):]
    return seal(changed[:body], len(blob))


def waivers_file(text):
    """check_waivers against a scratch file holding `text` (None: no file)."""
    def run(gen_config):
        d = tmp_tree()
        try:
            if text is not None:
                (d / "waivers.toml").write_text(text)
            return pkg.check_waivers(gen_config, d / "waivers.toml")
        finally:
            shutil.rmtree(d)
    return run


def main_checks(gen=GEN_DEBUG, waivers_text=WAIVERS_OPEN, key=BLOB, pq=PQ_BLOB, stub_sc20=False, lock_text=LOCK_CMR):
    """Runs `main()` with `build` replaced and the waiver file and Cargo.lock
    pointed at scratch ones (None: absent). Returns what it printed (the success line
    dropped, the scratch dir shown as <d>), plus a note when the outcome disagrees with that output, so
    an accepted run returns [] and a refused one exactly its messages.
    With `stub_sc20` the SC20 predicate passes, so it cannot mask what
    comes after it."""
    def run():
        d = tmp_tree()
        real = (pkg.build, pkg.require_debug, pkg.WAIVERS, pkg.LOCK, sys.argv)
        real_umask = os.umask(0o022)
        os.umask(real_umask)
        real_handlers = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
        built = []
        try:
            (d / "secrets.bin").write_bytes(key)
            (d / "pq.bin").write_bytes(pq)
            (d / "gen_config.h").write_text(gen)
            if waivers_text is not None:
                (d / "waivers.toml").write_text(waivers_text)
            pkg.WAIVERS = d / "waivers.toml"
            if lock_text is not None:
                (d / "Cargo.lock").write_text(lock_text)
            pkg.LOCK = d / "Cargo.lock"
            if stub_sc20:
                pkg.require_debug = lambda _gen: []

            def fake_build(a, blobs, staging):
                built.append(blobs)
                (staging / "loader.img").write_bytes(b"image")
                return 0
            pkg.build = fake_build
            sys.argv = ["package", "--secrets", str(d / "secrets.bin"), "--pq-secrets", str(d / "pq.bin"),
                        "--out", str(d / "pkg"), "--system", "x", "--policy", "x", "--image", "x",
                        "--gen-config", str(d / "gen_config.h"), "--search-path", "x", "--board", "x",
                        "--config", "x", "--microkit", "x"]
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                status = pkg.main()
            printed = [line.replace(str(d), "<d>") for line in captured.getvalue().splitlines()
                       if not line.startswith("package: wrote ")]
            if status == 0 and (printed or built != [BLOBS]):
                printed.append(f"accepted, but printed {printed} and built {len(built)}")
            if status != 0 and (not printed or built):
                printed.append(f"refused (status {status}) with built {len(built)}")
            return printed
        finally:
            pkg.build, pkg.require_debug, pkg.WAIVERS, pkg.LOCK, sys.argv = real
            os.umask(real_umask)
            for s, h in real_handlers.items():
                signal.signal(s, h)
            shutil.rmtree(d)
    return run


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
            (d / "pq.bin").write_bytes(PQ_BLOB)
            gen = d / "gen_config.h"
            gen.write_text(GEN_DEBUG)
            out = d / "pkg"

            built = []

            def fake_build(a, blobs, staging):
                built.append(1)
                (staging / "loader.img").write_bytes(b"image")
                if build_result == "raise":
                    raise RuntimeError("microkit failed")
                if build_result == "out-appears":
                    out.mkdir()
                    return 0
                if build_result == "publish-fails":
                    pkg.publish = failing_publish
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
            sys.argv = ["package", "--secrets", str(blob), "--pq-secrets", str(d / "pq.bin"), "--out", str(out),
                        "--system", "x", "--policy", "x",
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
            real_publish = pkg.publish

            def failing_publish(src, dst):
                # The real publish, failing (no such parent): its own error
                # text must reach the operator once, not wrapped again.
                real_publish(src, dst.parent / "missing" / dst.name)
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
                pkg.publish = real_publish
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
            expected = {1: 1, "raise": "raised", "out-appears": 1, 0: 0, "signal-in-ignore-loop": 1,
                        "publish-fails": 1}.get(build_result)
            if build_result == "publish-fails" and (captured.getvalue().count("package: cannot publish") != 1
                                                    or "[Errno" in captured.getvalue()):
                errors.append(f"a failed publish was not reported as one package: message: {captured.getvalue()!r}")
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
        (d / "pq.bin").write_bytes(PQ_BLOB)
        gen = d / "gen_config.h"
        gen.write_text(GEN_DEBUG)
        calls = []

        def roots(repo):
            calls.append(1)
            # The first three calls are the two blob and the OUT checks; the
            # fourth is the staging re-check, which now sees `d` as forbidden.
            return real_roots(repo) + ([d.resolve()] if len(calls) > 3 else [])

        pkg.forbidden_roots = roots
        pkg.build = lambda *a: built.append(1) or 0
        sys.argv = ["package", "--secrets", str(blob), "--pq-secrets", str(d / "pq.bin"), "--out", str(d / "pkg"),
                    "--system", "x", "--policy", "x",
                    "--image", "x", "--gen-config", str(gen), "--search-path", "x", "--board", "x",
                    "--config", "x", "--microkit", "x"]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = pkg.main()
        errors = []
        if status != 1 or built or (d / "pkg").exists() or [p for p in d.iterdir() if p.name.startswith(".pkg.")]:
            errors.append(f"staging in a forbidden root was not refused cleanly (status {status}, built {built})")
        # Refused by the staging re-check itself, not by an earlier check.
        if "staging directory" not in out.getvalue() or len(calls) != 4:
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


def build_uses_the_checked_bytes(tamper: bool = False):
    """The image must be built from a private copy of the checked bytes, not
    by following the caller's path again (TOCTOU), and the copy must not be
    left beside the image. With `tamper`, the .system microkit consumed
    differs from the generated one: the build must refuse it, although the
    packaged .system is rewritten afterwards (S11-2)."""
    return lambda: _build_case(tamper)


def _build_case(tamper: bool):
    d = tmp_tree()
    real_run = pkg.subprocess.run
    seen = {}
    try:
        (d / "system.xml").write_text(SYSTEM)
        (d / "placeholder.img").write_bytes(PLACEHOLDER_IMG)
        staging = d / "staging"
        staging.mkdir()

        def fake_run(cmd, check=False, **_):
            if cmd[0] == "cargo":
                return
            system = pathlib.Path(cmd[1])
            for mr in pkg.SECRETS_MRS:
                prefill = [m.get("prefill_path") for m in pkg.ET.fromstring(system.read_text())
                           .iter("memory_region") if m.get("name") == mr][0]
                seen[mr] = (prefill, pathlib.Path(prefill).read_bytes() if pathlib.Path(prefill).is_file() else b"")
            if tamper:
                system.write_text(system.read_text().replace('priority="140"', 'priority="141"'))
            pathlib.Path(cmd[cmd.index("-o") + 1]).write_bytes(PACKAGE_IMG)

        pkg.subprocess.run = fake_run

        class A:
            system, image, policy, search_path, board, config, microkit = (
                str(d / "system.xml"), str(d / "placeholder.img"), "p", "s", "b", "c", "microkit")
            secrets = str(d / "operator" / "secrets.bin")
            pq_secrets = str(d / "operator" / "pq.bin")

        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            status = pkg.build(A, BLOBS, staging)
        if tamper:
            if status != 1 or "attributes of <protection_domain>" not in captured.getvalue():
                return [f"a changed consumed .system was accepted (status {status})"]
            return []
        errors = []
        if status != 0:
            errors.append(f"build failed ({status})")
        for mr, operator in (("secrets", A.secrets), ("pq_secrets", A.pq_secrets)):
            prefill, consumed = seen.get(mr, ("", b""))
            if not prefill.startswith(str(staging)) or consumed != BLOBS[mr]:
                errors.append(f"'{mr}' not built from its private copy: {prefill}")
            packaged = [m.get("prefill_path") for m in pkg.ET.fromstring((staging / "secureos.system").read_text())
                        .iter("memory_region") if m.get("name") == mr][0]
            if packaged != operator:
                errors.append(f"packaged .system names {packaged} for '{mr}', not the operator's blob")
        left = sorted(p.name for p in staging.iterdir() if p.suffix == ".bin")
        if left:
            errors.append(f"private blob copies left beside the image: {left}")
        return errors
    finally:
        pkg.subprocess.run = real_run
        shutil.rmtree(d)


def publish_never_replaces(existing: bool):
    def run():
        d = tmp_tree()
        try:
            src = d / "staging"
            src.mkdir()
            (src / "loader.img").write_bytes(b"image")
            dst = d / "pkg"
            if existing:
                dst.mkdir()  # an empty directory: plain rename(2) would replace it
            try:
                pkg.publish(src, dst)
                published = True
            except OSError:
                published = False
            if existing:
                return [] if not published and src.exists() and not any(dst.iterdir()) else ["replaced an existing OUT"]
            return [] if published and (dst / "loader.img").exists() else ["did not publish to a free OUT"]
        finally:
            shutil.rmtree(d)
    return run


def existing_out(d):
    (d / "pkg").mkdir()
    return d / "pkg"


def toml_error(text: str) -> str:
    try:
        tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        return str(e)
    raise AssertionError(f"{text!r} parses")


def outside(at: int) -> list:
    return [f"package: image differs outside the blobs ({at:#x}..{at:#x} vs {SPANS})"]


IMAGE_BLOBS = [BLOB, PQ_BLOB]

# (name, expected: an error substring, a list of the exact errors, or None
# for accept; check)
CASES = [
    ("real package accepted", None,
     lambda: pkg.check_systems(SYSTEM, package_system())
     + pkg.check_images(PLACEHOLDER_IMG, PACKAGE_IMG, IMAGE_BLOBS)
     + pkg.check_blob(pkg.KEY, BLOB) + pkg.check_blob(pkg.PQ, PQ_BLOB) + pkg.require_debug(GEN_DEBUG)),
    ("both blobs swapped in, in either order", None,
     lambda: pkg.check_images(PLACEHOLDER_IMG, PACKAGE_IMG, [PQ_BLOB, BLOB])),
    ("empty image diff", "identical to the placeholder",
     lambda: pkg.check_images(PLACEHOLDER_IMG, PLACEHOLDER_IMG, IMAGE_BLOBS)),
    ("image diff outside the blob", "differs outside the blob",
     lambda: pkg.check_images(PLACEHOLDER_IMG, flip(PACKAGE_IMG, 2), IMAGE_BLOBS)),
    ("image diff just past the blob", "differs outside the blob",
     lambda: pkg.check_images(PLACEHOLDER_IMG, flip(PACKAGE_IMG, KEY_AT + len(BLOB)), IMAGE_BLOBS)),
    ("image diff just before the key blob", outside(KEY_AT - 1),
     lambda: pkg.check_images(PLACEHOLDER_IMG, flip(PACKAGE_IMG, KEY_AT - 1), IMAGE_BLOBS)),
    ("image diff between the two blobs", outside(PQ_AT - 100),
     lambda: pkg.check_images(PLACEHOLDER_IMG, flip(PACKAGE_IMG, PQ_AT - 100), IMAGE_BLOBS)),
    ("image diff just before the pq blob", outside(PQ_AT - 1),
     lambda: pkg.check_images(PLACEHOLDER_IMG, flip(PACKAGE_IMG, PQ_AT - 1), IMAGE_BLOBS)),
    ("image diff just past the pq blob", outside(PQ_END),
     lambda: pkg.check_images(PLACEHOLDER_IMG, flip(PACKAGE_IMG, PQ_END), IMAGE_BLOBS)),
    ("image diff in the last byte", outside(len(PACKAGE_IMG) - 1),
     lambda: pkg.check_images(PLACEHOLDER_IMG, flip(PACKAGE_IMG, len(PACKAGE_IMG) - 1), IMAGE_BLOBS)),
    ("pq blob missing from the image", ["package: 'SOSPQKY1' blob does not appear exactly once in the image"],
     lambda: pkg.check_images(PLACEHOLDER_IMG, PACKAGE_IMG[:PQ_AT] + bytes(len(PQ_BLOB)) + PACKAGE_IMG[PQ_END:],
                              IMAGE_BLOBS)),
    ("image length changed", "length changed",
     lambda: pkg.check_images(PLACEHOLDER_IMG, PACKAGE_IMG + b"\0", IMAGE_BLOBS)),
    ("placeholder not zero under the blob", "not zero where a blob lands",
     lambda: pkg.check_images(flip(PLACEHOLDER_IMG, KEY_AT + 200), PACKAGE_IMG, IMAGE_BLOBS)),
    ("placeholder not zero under the pq blob",
     [f"package: placeholder image is not zero where a blob lands ({PQ_AT:#x}..{PQ_END:#x})"],
     lambda: pkg.check_images(flip(PLACEHOLDER_IMG, PQ_AT + 200), PACKAGE_IMG, IMAGE_BLOBS)),
    # A second copy present at the same offset in both images: no extra
    # diff, so only the uniqueness clause can reject it.
    ("blob appears twice", "exactly once",
     lambda: pkg.check_images(PLACEHOLDER_IMG + BLOB, PACKAGE_IMG + BLOB, IMAGE_BLOBS)),
    ("pq blob appears twice", ["package: 'SOSPQKY1' blob does not appear exactly once in the image"],
     lambda: pkg.check_images(PLACEHOLDER_IMG + PQ_BLOB, PACKAGE_IMG + PQ_BLOB, IMAGE_BLOBS)),
    ("all-zero blob", "all zero", lambda: pkg.check_blob(pkg.KEY, bytes(4096))),
    ("short blob", "expected 4096", lambda: pkg.check_blob(pkg.KEY, BLOB[:-1])),
    ("blob without magic", "no SOSSECR1 magic", lambda: pkg.check_blob(pkg.KEY, b"X" + BLOB[1:])),
    ("key blob version 1", ["package: 'secrets' blob is version 1, expected 2"],
     lambda: pkg.check_blob(pkg.KEY, resealed(BLOB, 8, le32(1), len(KEY_BODY)))),
    ("key blob peer count zero", ["package: 'secrets' blob peer count is out of range"],
     lambda: pkg.check_blob(pkg.KEY, resealed(BLOB, 12, le32(0), len(KEY_BODY)))),
    ("key blob checksum mismatch", ["package: 'secrets' blob checksum mismatch"],
     lambda: pkg.check_blob(pkg.KEY, flip(BLOB, 20))),
    ("key blob non-zero padding", ["package: 'secrets' blob has non-zero padding"],
     lambda: pkg.check_blob(pkg.KEY, flip(BLOB, 4095))),
    ("pq blob in the key's mr", ["package: 'secrets' blob holds a 'pq_secrets' blob (SOSPQKY1)"],
     lambda: pkg.check_blob(pkg.KEY, PQ_BLOB)),
    ("key blob in the pq mr", ["package: 'pq_secrets' blob holds a 'secrets' blob (SOSSECR1)"],
     lambda: pkg.check_blob(pkg.PQ, BLOB)),
    ("pq blob bad magic", ["package: 'pq_secrets' blob has no SOSPQKY1 magic"],
     lambda: pkg.check_blob(pkg.PQ, b"X" + PQ_BLOB[1:])),
    ("pq blob version 2", ["package: 'pq_secrets' blob is version 2, expected 1"],
     lambda: pkg.check_blob(pkg.PQ, resealed(PQ_BLOB, 8, le32(2), len(PQ_BODY)))),
    ("pq blob checksum mismatch", ["package: 'pq_secrets' blob checksum mismatch"],
     lambda: pkg.check_blob(pkg.PQ, flip(PQ_BLOB, 13903))),
    ("pq blob checksum field changed", ["package: 'pq_secrets' blob checksum mismatch"],
     lambda: pkg.check_blob(pkg.PQ, flip(PQ_BLOB, 13904))),
    ("pq blob non-zero padding", ["package: 'pq_secrets' blob has non-zero padding"],
     lambda: pkg.check_blob(pkg.PQ, flip(PQ_BLOB, 13936))),
    ("short pq blob", ["package: 'pq_secrets' blob is 16383 bytes, expected 16384"],
     lambda: pkg.check_blob(pkg.PQ, PQ_BLOB[:-1])),
    ("main() packages both blobs", None, main_checks()),
    ("main() refuses the pq blob given as --secrets",
     ["package: 'secrets' blob holds a 'pq_secrets' blob (SOSPQKY1)",
      "package: 'pq_secrets' blob holds a 'secrets' blob (SOSSECR1)"],
     main_checks(key=PQ_BLOB, pq=BLOB)),
    ("main() refuses a bad pq blob", ["package: 'pq_secrets' blob checksum mismatch"],
     main_checks(pq=flip(PQ_BLOB, 100))),
    ("other attribute changed", "attributes of <protection_domain>",
     lambda: pkg.check_systems(SYSTEM, package_system().replace('priority="140"', 'priority="141"'))),
    ("other mr's attribute changed", "attributes of <memory_region>",
     lambda: pkg.check_systems(SYSTEM, package_system().replace('name="ring" size="0x1000"', 'name="ring" size="0x2000"'))),
    ("prefill_path added to a non-secrets mr", ["package: system/memory_region[2]: attributes of <memory_region> changed"],
     lambda: pkg.check_systems(SYSTEM, package_system().replace('name="ring"', 'name="ring" prefill_path="/x"'))),
    ("package system without the pq mr's prefill_path",
     ["package: package system needs one 'pq_secrets' mr with a prefill_path"],
     lambda: pkg.check_systems(SYSTEM, package_system().replace('prefill_path="/elsewhere/pq.bin"', 'prefill_path=""'))),
    ("element added", "children",
     lambda: pkg.check_systems(SYSTEM, package_system().replace("</system>", '<memory_region name="x" size="0x1000" /></system>'))),
    ("non-debug kernel", "not debug", lambda: pkg.require_debug(GEN_RELEASE)),
    ("open waiver refuses a non-debug kernel, named", [SC23_OPEN], lambda: waivers_file(WAIVERS_OPEN)(GEN_RELEASE)),
    ("each open waiver is named",
     [SC23_OPEN, "package: waiver SC9 (owner M3b) is open; non-debug kernels are refused until it closes"],
     lambda: waivers_file(WAIVERS_OPEN.replace('"closed"', '"open"'))(GEN_RELEASE)),
    ("open waiver allows a debug kernel", None, lambda: waivers_file(WAIVERS_OPEN)(GEN_DEBUG)),
    ("no open waiver allows a non-debug kernel", None, lambda: waivers_file(WAIVERS_CLOSED)(GEN_RELEASE)),
    ("the repository's waiver file parses", None, lambda: pkg.check_waivers(GEN_DEBUG, pkg.WAIVERS)),
    # With the SC20 predicate stubbed to pass, so it cannot mask the waiver
    # gate (M3 plan, Packaging).
    ("SC20 stubbed: an open waiver refuses and names itself", [SC23_OPEN],
     main_checks(gen=GEN_RELEASE, stub_sc20=True)),
    ("SC20 stubbed: a missing waiver file refuses", [MISSING_WAIVERS],
     main_checks(gen=GEN_RELEASE, waivers_text=None, stub_sc20=True)),
    ("SC20 stubbed: an unparsable waiver file refuses",
     [f"package: waiver file unusable, refusing: not valid TOML: {toml_error('[[waivers]')}"],
     main_checks(gen=GEN_RELEASE, waivers_text="[[waivers]", stub_sc20=True)),
    ("SC20 stubbed: a waiver outside the schema refuses",
     ["package: waiver file unusable, refusing: waiver SC23: status 'maybe' is not one of open, closed"],
     main_checks(gen=GEN_RELEASE, waivers_text=WAIVERS_OPEN.replace('"open"', '"maybe"'), stub_sc20=True)),
    ("SC20 stubbed: no open waiver allows", None,
     main_checks(gen=GEN_RELEASE, waivers_text=WAIVERS_CLOSED, stub_sc20=True, lock_text=LOCK_NO_CMR)),
    # SC23 bound to cmr in Cargo.lock, whatever its version and kernel
    # (M3 plan, Packaging; P6's rule, which `make package` does not run).
    ("SC23 closed while cmr is locked refuses a debug kernel", [SC23_BOUND],
     main_checks(waivers_text=WAIVERS_CLOSED)),
    ("SC23 closed while cmr is locked at another version refuses", [SC23_BOUND],
     main_checks(waivers_text=WAIVERS_CLOSED, lock_text=LOCK_CMR_OTHER)),
    ("an empty waiver file refuses while cmr is locked", [SC23_BOUND], main_checks(waivers_text="")),
    ("SC20 stubbed: SC23 closed while cmr is locked refuses a non-debug kernel too", [SC23_BOUND],
     main_checks(gen=GEN_RELEASE, waivers_text=WAIVERS_CLOSED, stub_sc20=True)),
    ("an empty Cargo.lock refuses",
     ["package: Cargo.lock unusable, refusing: Cargo.lock has no [[package]] tables"], main_checks(lock_text="")),
    ("a Cargo.lock whose package is not an array of tables refuses",
     ["package: Cargo.lock unusable, refusing: Cargo.lock has no [[package]] tables"],
     main_checks(lock_text='version = 4\n[package]\nname = "classic-mceliece-rust"\n')),
    ("a Cargo.lock package without a string name refuses",
     ["package: Cargo.lock unusable, refusing: Cargo.lock has a [[package]] entry without a string name"],
     main_checks(lock_text='version = 4\n[[package]]\nversion = "1"\n')),
    ("SC23 closed without cmr locked allows a debug kernel", None,
     main_checks(waivers_text=WAIVERS_CLOSED, lock_text=LOCK_NO_CMR)),
    ("a missing Cargo.lock refuses",
     ["package: Cargo.lock unusable, refusing: [Errno 2] No such file or directory: '<d>/Cargo.lock'"],
     main_checks(lock_text=None)),
    ("a missing waiver file refuses a debug kernel too", [MISSING_WAIVERS], main_checks(waivers_text=None)),
    ("non-debug kernel with no open waiver: SC20 alone", [SC20],
     main_checks(gen=GEN_RELEASE, waivers_text=WAIVERS_CLOSED, lock_text=LOCK_NO_CMR)),
    ("non-debug kernel with an open waiver: both refusals", [SC20, SC23_OPEN], main_checks(gen=GEN_RELEASE)),
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
    ("the image is built from a private copy of the checked blob", None, build_uses_the_checked_bytes()),
    ("a consumed .system that differs from the generated one is refused", None, build_uses_the_checked_bytes(tamper=True)),
    ("publishing refuses to replace an OUT that appeared", None, publish_never_replaces(True)),
    ("publishing to a free OUT succeeds", None, publish_never_replaces(False)),
    ("a failed publish is reported and leaves no OUT or staging", None, run_main("publish-fails")),
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
        elif isinstance(want, list):
            ok = errors == want
        else:
            ok = len(errors) == 1 and want in errors[0]
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {errors or 'accepted'}")
    print(f"PACKAGE-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
