import importlib.util
import math
import subprocess
import sys
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
SPEC = importlib.util.spec_from_file_location(
    "opla_lifecycle_timeout_test", ROOT / "bin/lab-lifecycle.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LifecycleCommandTimeoutTests(unittest.TestCase):
    def test_owned_process_group_terminates_and_reaps_after_timeout(self):
        class FakeProcess:
            pid = 4321
            returncode = -9

            def __init__(self):
                self.waits = 0

            def communicate(self, input=None, timeout=None):
                self.waits += 1
                if self.waits == 1:
                    raise subprocess.TimeoutExpired(("sleep", "x"), timeout)
                if self.waits == 2:
                    raise subprocess.TimeoutExpired(("sleep", "x"), timeout)
                return "", ""

        process = FakeProcess()
        signals = []
        with mock.patch.object(MODULE.subprocess, "Popen", return_value=process) as popen:
            with mock.patch.object(MODULE.os, "killpg", side_effect=lambda pid, sig: signals.append((pid, sig))):
                with self.assertRaises(subprocess.TimeoutExpired):
                    MODULE.call("sleep", "x", timeout=0.1)
        kwargs = popen.call_args.kwargs
        self.assertTrue(kwargs["start_new_session"])
        self.assertEqual(signals, [(4321, MODULE.signal.SIGTERM), (4321, MODULE.signal.SIGKILL)])
        self.assertEqual(process.waits, 3)

    def test_owned_process_group_reaps_after_term_without_kill(self):
        class FakeProcess:
            pid = 4322
            returncode = 0

            def __init__(self):
                self.calls = 0

            def communicate(self, input=None, timeout=None):
                self.calls += 1
                if self.calls == 1:
                    raise subprocess.TimeoutExpired(("cmd",), timeout)
                return "ok", ""

        process = FakeProcess()
        with mock.patch.object(MODULE.subprocess, "Popen", return_value=process):
            with mock.patch.object(MODULE.os, "killpg") as killpg:
                with self.assertRaises(subprocess.TimeoutExpired):
                    MODULE.call("cmd", timeout=0.1)
        killpg.assert_called_once_with(4322, MODULE.signal.SIGTERM)
        self.assertEqual(process.calls, 2)

    def test_cleanup_oserror_still_attempts_kill_and_preserves_timeout(self):
        class FakeProcess:
            pid = 4323

            def communicate(self, input=None, timeout=None):
                if timeout is not None:
                    if timeout == 0.1:
                        raise subprocess.TimeoutExpired(("cmd",), timeout)
                    raise OSError("wait failed")
                raise OSError("reap failed")

        process = FakeProcess()
        with mock.patch.object(MODULE.subprocess, "Popen", return_value=process):
            with mock.patch.object(MODULE.os, "killpg", side_effect=OSError("signal failed")) as killpg:
                with self.assertRaises(subprocess.TimeoutExpired):
                    MODULE.call("cmd", timeout=0.1)
        self.assertEqual(killpg.call_count, 2)

    def test_initial_communicate_oserror_still_cleans_process_group(self):
        class FakeProcess:
            pid = 4324

            def communicate(self, input=None, timeout=None):
                raise OSError("communicate failed")

        with mock.patch.object(MODULE.subprocess, "Popen", return_value=FakeProcess()):
            with mock.patch.object(MODULE.os, "killpg") as killpg:
                with self.assertRaises(OSError):
                    MODULE.call("cmd", timeout=0.1)
        self.assertEqual(killpg.call_count, 2)

    def test_call_passes_timeout_and_input_to_injected_runner(self):
        calls = []

        def runner(*args, **kwargs):
            calls.append((args, kwargs))
            return subprocess.CompletedProcess(args, 0, "ok", "")

        result = MODULE.call(
            "nft", "-f", "-", check=True, timeout=4.5,
            input="rules", runner=runner
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)
        args, kwargs = calls[0]
        self.assertEqual(args, (("nft", "-f", "-"),))
        self.assertEqual(kwargs, {
            "check": True,
            "text": True,
            "capture_output": True,
            "input": "rules",
            "timeout": 4.5,
        })

    def test_invalid_timeout_is_rejected_before_dispatch(self):
        called = []

        def runner(*args, **kwargs):
            called.append(True)
            return subprocess.CompletedProcess(args, 0, "", "")

        for timeout in (True, False, 0, -1, math.nan, math.inf, "30"):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                MODULE.call("systemctl", "is-active", timeout=timeout, runner=runner)
        self.assertEqual(called, [])

    def test_timeout_error_is_preserved_for_fail_closed_caller(self):
        def runner(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

        with self.assertRaises(subprocess.TimeoutExpired):
            MODULE.call("ip", "link", "show", timeout=0.1, runner=runner)

    def test_direct_subprocess_dispatch_is_consolidated_in_wrapper(self):
        source = (ROOT / "bin/lab-lifecycle.py").read_text(encoding="utf-8")
        self.assertIn("dispatch = subprocess.run if runner is None else runner", source)
        self.assertNotIn("subprocess.run([", source)
        self.assertIn("call('nft', '-f', '-', input=rules)", source)


if __name__ == "__main__":
    unittest.main()
