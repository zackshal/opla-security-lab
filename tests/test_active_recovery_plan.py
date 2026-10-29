import importlib.util
import math
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stderr
import io

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('active_recovery_plan_test',ROOT/'bin/opla-active-recovery-plan.py')
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

class ActiveRecoveryPlanTests(unittest.TestCase):
    def test_missing_receipt_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(mod.prune,'safe_root',side_effect=lambda p:Path(p)):
                with self.assertRaises(mod.Blocked):mod.verify_receipt(td,'lab-Test123')

    def test_no_mutating_commands(self):
        source=(ROOT/'bin/opla-active-recovery-plan.py').read_text()
        for fragment in ('systemctl stop','ip link delete','nft delete','shutil.rmtree','os.unlink('):
            self.assertNotIn(fragment,source)
        self.assertIn("'execution_allowed':False",source)

    def test_make_exposes_plan_only(self):
        mk=(ROOT/'Makefile').read_text()
        self.assertIn('creation-active-recovery-plan:',mk)
        self.assertNotIn('creation-active-recovery-execute:',mk)

    def test_default_probe_runner_is_bounded(self):
        with patch.object(mod.process_runtime, "run_bounded",
                          return_value=subprocess.CompletedProcess([], 0, "", "")) as dispatch:
            result = mod.run(["systemctl", "show"], timeout=4)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(dispatch.call_args.args[0], ["systemctl", "show"])
        self.assertEqual(dispatch.call_args.kwargs["timeout"], 4)
        self.assertEqual(dispatch.call_args.kwargs["max_output_bytes"], mod.MAX_PROBE_OUTPUT_BYTES)

    def test_injected_probe_runner_keeps_test_contract(self):
        calls = []
        def runner(*args, **kwargs):
            calls.append((args, kwargs))
            return subprocess.CompletedProcess(args, 0, "", "")
        mod.run(["systemctl", "show"], runner=runner, timeout=4)
        self.assertEqual(calls[0][1], {
            "capture_output": True, "text": True, "check": False, "timeout": 4,
        })

    def test_require_blocks_on_probe_output_overflow(self):
        result = subprocess.CompletedProcess([], 1, "", "")
        result.output_limited = True
        with self.assertRaisesRegex(mod.Blocked, "output exceeded"):
            mod.require(["ip", "link"], lambda *_: result)

    def test_require_blocks_on_uncertain_probe_cleanup(self):
        result = subprocess.CompletedProcess([], 1, "", "")
        result.cleanup_error = "process group remains"
        with self.assertRaisesRegex(mod.Blocked, "cleanup is uncertain"):
            mod.require(["systemctl", "show"], lambda *_: result)

    def test_actual_bounded_probe_stops_after_output_limit(self):
        result = mod.run([
            sys.executable, "-c",
            f"import sys; sys.stdout.write('x' * {mod.MAX_PROBE_OUTPUT_BYTES + 1})",
        ], timeout=5)
        self.assertTrue(result.output_limited)
        self.assertLessEqual(len(result.stdout.encode()), mod.MAX_PROBE_OUTPUT_BYTES)
        with self.assertRaisesRegex(mod.Blocked, "output exceeded"):
            mod.require(["fixture-output"], lambda *_: result)

    def test_actual_bounded_probe_timeout_is_rejected(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            mod.run([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.05)

    def test_invalid_probe_timeout_rejected_before_dispatch(self):
        for timeout in (True, 0, -1, math.nan, math.inf, "10"):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                mod.run(["systemctl", "show"], timeout=timeout,
                        runner=lambda *a, **k: self.fail("dispatched"))

    def test_cli_normalizes_probe_timeout_to_blocked_exit(self):
        error = subprocess.TimeoutExpired(["systemctl"], 10)
        stderr = io.StringIO()
        with patch.object(mod.os, "geteuid", return_value=0), \
             patch.object(mod, "audit", side_effect=error), \
             redirect_stderr(stderr):
            result = mod.main(["--lab", "lab-Test123", "--root", "/tmp"])
        self.assertEqual(result, 2)
        self.assertIn("BLOCKED:", stderr.getvalue())

if __name__=='__main__':unittest.main()
