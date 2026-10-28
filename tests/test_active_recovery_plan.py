import importlib.util
import math
import subprocess
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
        calls = []

        def runner(*args, **kwargs):
            calls.append((args, kwargs))
            return subprocess.CompletedProcess(args, 0, "", "")

        result = mod.run(["systemctl", "show"], runner=runner, timeout=4)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(calls[0][1]["timeout"], 4)

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
