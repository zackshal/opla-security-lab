import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('opla_lab_cleanup_plan', ROOT / 'bin' / 'opla-lab-cleanup-plan.py')
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class LabCleanupPlanTests(unittest.TestCase):
    def test_empty_registry_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            result = MOD.plan(td, 'lab-Ab1234')
            self.assertFalse(result['execution_allowed'])
            self.assertTrue(any('missing' in x for x in result['reasons']))

    def test_invalid_id_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                MOD.plan(td, '../../etc')

    def test_root_symlink_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'actual').mkdir()
            (root / 'alias').symlink_to(root / 'actual')
            result = MOD.plan(root / 'alias', 'lab-Ab1234')
            self.assertFalse(result['execution_allowed'])
            self.assertTrue(any('unsafe' in x for x in result['reasons']))

    def test_make_targets_fail_closed(self):
        mk = (ROOT / 'Makefile').read_text()
        shell = (ROOT / 'bin' / 'opla-lab-delete.sh').read_text()
        self.assertIn('legacy down bypasses ownership checks', mk)
        self.assertIn('destructive lab-delete awaits verified ownership executor', mk)
        self.assertIn('exit 2', shell)


if __name__ == '__main__':
    unittest.main()
