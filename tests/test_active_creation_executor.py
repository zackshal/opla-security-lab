import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('v595recover', ROOT / 'bin' / 'opla-active-creation-recover.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class ActiveExecutorTests(unittest.TestCase):
    def test_wrong_confirmation_does_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(mod.prune,'safe_root',side_effect=lambda x:Path(x)):
                with self.assertRaisesRegex(mod.Blocked,'confirmation'):
                    mod.locked_recover(Path(td),'lab-Test123','wrong')

    def test_missing_receipt_blocks_before_stop(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)
            with patch.object(mod.prune,'safe_root',side_effect=lambda x:Path(x)), patch.object(mod.rollback,'lock_is_safe',return_value=True):
                touched=[]
                with self.assertRaises(Exception):
                    mod.locked_recover(path,'lab-Test123','RECOVER-CREATION:lab-Test123',stop=lambda *a:touched.append('stop'))
                self.assertFalse(touched)

    def test_stop_failure_retains_resources(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)
            with patch.object(mod.prune,'safe_root',side_effect=lambda x:Path(x)),patch.object(mod.rollback,'lock_is_safe',return_value=True),patch.object(mod.prune,'write_journal'):
                steps=[]
                def audit(*_): steps.append('audit')
                def evidence(*_): steps.append('pid')
                def stop(*_): steps.append('stop');raise RuntimeError('QMP refused')
                def offline(*_): steps.append('delete')
                with self.assertRaisesRegex(RuntimeError,'QMP refused'):
                    mod.locked_recover(path,'lab-Test123','RECOVER-CREATION:lab-Test123',audit=audit,evidence=evidence,stop=stop,offline=offline)
                self.assertEqual(steps,['audit','pid','audit','pid','stop'])

    def test_success_requires_recheck(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)
            with patch.object(mod.prune,'safe_root',side_effect=lambda x:Path(x)),patch.object(mod.rollback,'lock_is_safe',return_value=True),patch.object(mod.prune,'write_journal'):
                steps=[]
                result=mod.locked_recover(path,'lab-Test123','RECOVER-CREATION:lab-Test123',
                    audit=lambda *_:steps.append('audit'),evidence=lambda *_:steps.append('pid'),
                    stop=lambda *_:steps.append('stop'),offline=lambda *_:steps.append('offline') or {'safe':True})
                self.assertEqual(steps,['audit','pid','audit','pid','stop','pid','offline'])
                self.assertEqual(result['status'],'completed')

    def test_make_target_requires_confirmation(self):
        make=(ROOT/'Makefile').read_text()
        self.assertIn('bin/opla-active-creation-recover.py',make)
        self.assertIn('CONFIRM_RECOVER',make)
