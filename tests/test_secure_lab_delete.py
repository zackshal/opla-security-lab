"""Unit tests: full live QMP/network deletion requires dedicated disposable VM host."""
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('v59_lab_delete',ROOT/'bin/opla-secure-lab-delete.py')
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class SecureDeleteTests(unittest.TestCase):
    def test_wrong_confirmation_fails_before_lock_or_host_calls(self):
        with patch.object(mod.prune,'safe_root',return_value=Path('/var/lib/opla')):
            with patch.object(mod.os,'open',side_effect=AssertionError('must not touch lock')):
                with self.assertRaisesRegex(mod.Blocked,'confirmation'):
                    mod.run('/var/lib/opla','lab-Test123','wrong')

    def test_missing_receipt_blocks_before_host_mutation(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'registry').mkdir()
            with patch.object(mod.prune,'safe_root',return_value=root):
                with patch.object(mod.lifecycle,'clean_stop',side_effect=AssertionError('no stop')):
                    with self.assertRaisesRegex(mod.Blocked,'receipt'):
                        mod.verify_pre_stop(root,'lab-Test123')

    def test_coordinator_uses_same_global_lock(self):
        source=(ROOT/'bin/opla-secure-lab-delete.py').read_text()
        self.assertIn("'.opla-prune.lock'",source)
        self.assertIn('lock_held=True',source)
        self.assertIn('lifecycle.clean_stop',source)
        creation=(ROOT/'bin/create-lab.sh').read_text()
        lifecycle=(ROOT/'bin/lab-lifecycle.py').read_text()
        launcher = (
            ROOT / 'bin' / 'opla-create-launcher.py'
        ).read_text()

        self.assertIn('ROOT = Path("/var/lib/opla")', launcher)
        self.assertIn('root / ".opla-prune.lock"', launcher)
        self.assertIn('root / "create.lock"', launcher)
        self.assertIn('locks.lifecycle_lock(', launcher)
        self.assertIn("'.opla-prune.lock'",lifecycle)

    def test_no_shell_cleanup_bypass(self):
        make=(ROOT/'Makefile').read_text()
        self.assertIn('opla-secure-lab-delete.py',make)
        self.assertIn('legacy down bypasses ownership checks',make)

if __name__=='__main__': unittest.main()
