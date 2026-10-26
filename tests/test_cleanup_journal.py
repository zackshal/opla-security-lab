import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cleanup_journal_v57', ROOT / 'bin' / 'opla-cleanup-journal.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class JournalTests(unittest.TestCase):
    def test_empty_and_blocked_record(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(mod.read_records(td), [])
            rec = mod.append_record(td, 'lab-Test123')
            self.assertEqual(rec['outcome'], 'blocked')
            self.assertFalse(rec['execution_allowed'])
            self.assertEqual(len(mod.read_records(td)), 1)
    def test_repeated_assessments_are_appended(self):
        with tempfile.TemporaryDirectory() as td:
            mod.append_record(td, 'lab-Test123')
            mod.append_record(td, 'lab-Test123')
            self.assertEqual(len(mod.read_records(td)), 2)
    def test_unsafe_journal_path_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / 'operations').symlink_to(p)
            with self.assertRaises(ValueError):
                mod.append_record(td, 'lab-Test123')
    def test_invalid_lab_never_creates_log(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                mod.append_record(td, '../../etc')
            self.assertFalse((Path(td) / 'operations').exists())
    def test_no_host_destructive_calls(self):
        import inspect
        code = inspect.getsource(mod)
        self.assertNotIn('subprocess.run', code)
        self.assertNotIn('shutil.rmtree', code)

if __name__ == '__main__':
    unittest.main()
