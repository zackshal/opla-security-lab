import importlib.util
import json
import os
import signal
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from contextlib import nullcontext
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module():
    path = ROOT / "bin/opla-lab-configure-launcher.py"
    spec = importlib.util.spec_from_file_location(
        "opla_configure_launcher_test", path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ConfigureLauncherTests(unittest.TestCase):

    def test_registry_is_checked_before_dropped_user_dispatch(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'lab-Ab12').mkdir()
            user = SimpleNamespace(pw_name='test', pw_dir=temp, pw_uid=os.getuid(), pw_gid=os.getgid())
            records = [{'lab': 'lab-Ab12', 'status': 'recorded'}]
            def dispatch(command, **kwargs):
                import fcntl
                fd = int(command[-1])
                self.assertEqual(kwargs['pass_fds'], (fd,))
                self.assertEqual(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
                self.assertEqual(os.fstat(fd).st_mode & 0o777, 0o600)
                self.assertEqual(json.loads(os.read(fd, 65536)), records)
                return subprocess.CompletedProcess(command, 0)
            with patch.object(module, 'ROOT', root), \
                 patch.object(module, 'invoking_user', return_value=user), \
                 patch.object(module, 'verify_trusted_code'), \
                 patch.object(module, 'load_locks', return_value=SimpleNamespace(lifecycle_lock=lambda path: nullcontext())), \
                 patch.object(module, 'registry_ready_snapshot', return_value=records), \
                 patch.object(module, 'run_configure', side_effect=dispatch) as runner:
                self.assertEqual(module.main(['lab-Ab12', 'lab-Ab12']), 0)
                runner.assert_called_once()
            with patch.object(module, 'ROOT', root):
                with self.assertRaisesRegex(RuntimeError, 'registry check failed'):
                    module.registry_ready_snapshot('lab-Ab12')

    def test_inherited_registry_descriptor_reaches_child(self):
        import sys
        module = load_module()
        with tempfile.TemporaryFile() as snapshot:
            snapshot.write(b'validated registry snapshot')
            snapshot.seek(0)
            command = [sys.executable, '-c',
                       'import os,sys; sys.exit(0 if os.read(int(sys.argv[1]), 64) == b"validated registry snapshot" else 2)',
                       str(snapshot.fileno())]
            result = module.run_configure(command, cwd='/tmp', env={}, preexec_fn=lambda: None,
                                          pass_fds=(snapshot.fileno(),), timeout=5)
            self.assertEqual(result.returncode, 0)

    def test_configure_timeout_env_is_validated_and_bounded(self):
        module = load_module()
        self.assertEqual(
            module.configure_timeout_from_env({"OPLA_CONFIGURE_TIMEOUT": "120"}),
            120,
        )
        for raw in ("0", "-1", "3601", "nan", "1.5", "bad"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                module.configure_timeout_from_env({"OPLA_CONFIGURE_TIMEOUT": raw})

    def test_reconciliation_receipt_is_atomic_and_identity_bound(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            path = module.persist_configure_reconciliation(
                lab, "lab-ABCD1234", 900,
                {"status": "reaped-after-kill", "term_sent": True, "kill_sent": True},
                require_root_owner=False,
            )
            self.assertEqual(path.name, module.RECONCILIATION_FILENAME)
            self.assertFalse(path.is_symlink())
            self.assertTrue(stat.S_ISREG(path.stat().st_mode))
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["lab_id"], "lab-ABCD1234")
            self.assertEqual(payload["status"], "RECONCILIATION_REQUIRED")
            self.assertEqual(payload["resource_reconciliation"], "unverified")
            self.assertEqual(list(lab.glob(".configure-reconciliation-*")), [])

    def test_unresolved_receipt_blocks_before_dispatch(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            module.persist_configure_reconciliation(
                lab, "lab-ABCD1234", 900, {}, require_root_owner=False,
            )
            with self.assertRaisesRegex(RuntimeError, "reconciliation required"):
                module.ensure_no_unresolved_reconciliation(
                    lab, "lab-ABCD1234", require_root_owner=False,
                )

    def test_unsafe_or_invalid_receipts_fail_closed(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            target = lab / module.RECONCILIATION_FILENAME
            other = lab / "other"
            other.write_text("{}", encoding="utf-8")
            target.symlink_to(other)
            with self.assertRaises(RuntimeError):
                module.ensure_no_unresolved_reconciliation(
                    lab, "lab-ABCD1234", require_root_owner=False,
                )
            target.unlink()
            target.write_text("{", encoding="utf-8")
            target.chmod(0o600)
            with self.assertRaises(RuntimeError):
                module.ensure_no_unresolved_reconciliation(
                    lab, "lab-ABCD1234", require_root_owner=False,
                )
            target.unlink()
            os.link(other, target)
            with self.assertRaises(RuntimeError):
                module.ensure_no_unresolved_reconciliation(
                    lab, "lab-ABCD1234", require_root_owner=False,
                )

    def test_run_configure_preserves_process_contract(self):
        module = load_module()
        calls = []

        class Process:
            pid = 1234

            def wait(self, timeout=None):
                calls.append(("wait", timeout))
                return 0

        def popen(*args, **kwargs):
            calls.append((args, kwargs))
            return Process()

        result = module.run_configure(
            ["/bin/bash", "configure.sh"], cwd="/tmp", env={"LAB_DIR": "/tmp/lab"},
            preexec_fn=lambda: None, timeout=12, popen_factory=popen,
        )
        self.assertEqual(result.returncode, 0)
        args, kwargs = calls[0]
        self.assertEqual(args, (["/bin/bash", "configure.sh"],))
        self.assertEqual(kwargs["cwd"], "/tmp")
        self.assertEqual(kwargs["env"], {"LAB_DIR": "/tmp/lab"})
        self.assertTrue(kwargs["start_new_session"])
        self.assertEqual(calls[1], ("wait", 12))

    def test_timeout_sends_term_then_reaps_and_preserves_exception(self):
        module = load_module()
        signals = []

        class Process:
            pid = 1234

            def __init__(self):
                self.first = True

            def wait(self, timeout=None):
                if self.first:
                    self.first = False
                    raise subprocess.TimeoutExpired("configure", timeout)
                return 143

        def killpg(pid, signum):
            signals.append((pid, signum))

        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            module.run_configure(
                ["configure"], cwd="/tmp", env={}, preexec_fn=None, timeout=1,
                popen_factory=lambda *a, **k: Process(), killpg=killpg, grace=2,
            )
        self.assertEqual(signals, [(1234, signal.SIGTERM)])
        self.assertEqual(caught.exception.cleanup_evidence["status"], "reaped-after-term")

    def test_initial_wait_oserror_still_records_cleanup_and_rethrows(self):
        module = load_module()
        signals = []

        class Process:
            pid = 1235

            def wait(self, timeout=None):
                raise OSError("wait failed")

        with self.assertRaises(OSError) as caught:
            module.run_configure(
                ["configure"], cwd="/tmp", env={}, preexec_fn=None, timeout=1,
                popen_factory=lambda *a, **k: Process(),
                killpg=lambda pid, signum: signals.append((pid, signum)), grace=2,
            )
        self.assertEqual(signals, [(1235, signal.SIGTERM), (1235, signal.SIGKILL)])
        self.assertIn("cleanup_evidence", dir(caught.exception))

    def test_timeout_escalates_to_kill_and_reaps(self):
        module = load_module()
        signals = []

        class Process:
            pid = 1234

            def __init__(self):
                self.waits = 0

            def wait(self, timeout=None):
                self.waits += 1
                if self.waits < 3:
                    raise subprocess.TimeoutExpired("configure", timeout)
                return 137

        def killpg(pid, signum):
            signals.append((pid, signum))

        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            module.run_configure(
                ["configure"], cwd="/tmp", env={}, preexec_fn=None, timeout=1,
                popen_factory=lambda *a, **k: Process(), killpg=killpg, grace=2,
            )
        self.assertEqual(signals, [(1234, signal.SIGTERM), (1234, signal.SIGKILL)])
        self.assertEqual(caught.exception.cleanup_evidence["status"], "reaped-after-kill")

    def test_timeout_cleanup_evidence_can_be_persisted_as_reconciliation(self):
        module = load_module()

        class Process:
            pid = 1234

            def __init__(self):
                self.waits = 0

            def wait(self, timeout=None):
                self.waits += 1
                if self.waits == 1:
                    raise subprocess.TimeoutExpired("configure", timeout)
                return 137

        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                module.run_configure(
                    ["configure"], cwd=directory, env={}, preexec_fn=None, timeout=1,
                    popen_factory=lambda *a, **k: Process(),
                    killpg=lambda *a: None, grace=2,
                )
            path = module.persist_configure_reconciliation(
                lab, "lab-ABCD1234", 1,
                caught.exception.cleanup_evidence, require_root_owner=False,
            )
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["cleanup"]["term_sent"], True)

    def test_unexpected_grace_wait_error_still_attempts_kill_and_reap(self):
        module = load_module()
        signals = []

        class Process:
            pid = 1234

            def __init__(self):
                self.waits = 0

            def wait(self, timeout=None):
                self.waits += 1
                if self.waits == 1:
                    raise subprocess.TimeoutExpired("configure", timeout)
                if self.waits == 2:
                    raise OSError("wait failed")
                return 137

        def killpg(pid, signum):
            signals.append((pid, signum))

        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            module.run_configure(
                ["configure"], cwd="/tmp", env={}, preexec_fn=None, timeout=1,
                popen_factory=lambda *a, **k: Process(), killpg=killpg, grace=2,
            )
        self.assertEqual(signals, [(1234, signal.SIGTERM), (1234, signal.SIGKILL)])
        self.assertEqual(caught.exception.cleanup_evidence["status"], "reaped-after-error")

    def test_valid_identity(self):
        module = load_module()
        self.assertEqual(
            module.validate_arguments(
                ["lab-ABCD1234", "lab-ABCD1234"]
            ),
            "lab-ABCD1234",
        )

    def test_rejects_mismatched_confirmation(self):
        module = load_module()
        with self.assertRaises(ValueError):
            module.validate_arguments(
                ["lab-ABCD1234", "lab-OTHER1234"]
            )

    def test_rejects_unsafe_identifier(self):
        module = load_module()
        for value in (
            "../lab-ABCD1234",
            "lab-ABCD1234/../../tmp",
            "lab-A_B_C",
            "lab-abc",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    module.validate_arguments([value, value])

    def test_privileged_source_requires_root_ownership(self):
        module = load_module()
        self.assertTrue(
            callable(module.verify_trusted_code)
        )

        source = (
            ROOT / "bin/opla-lab-configure-launcher.py"
        ).read_text()

        self.assertIn("verify_trusted_code()", source)
        self.assertIn("st.st_uid != 0", source)
        self.assertIn("st.st_mode & 0o022", source)
        self.assertIn("stat.S_ISREG", source)
        self.assertIn("subprocess.SubprocessError", source)

    def test_existing_lifecycle_lock_usage(self):
        source = (
            ROOT / "bin/opla-lab-configure-launcher.py"
        ).read_text()

        self.assertIn('ROOT / ".opla-prune.lock"', source)
        self.assertIn('lab / "maintenance.lock"', source)
        self.assertIn("os.setuid(user.pw_uid)", source)
        self.assertIn("preexec_fn=drop_privileges", source)


if __name__ == "__main__":
    unittest.main()
