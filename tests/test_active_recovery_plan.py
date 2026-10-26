import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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

if __name__=='__main__':unittest.main()
