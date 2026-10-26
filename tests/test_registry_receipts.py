import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'bin' / 'opla-registry.py'
spec = importlib.util.spec_from_file_location('opla_registry', SOURCE)
reg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reg)


class RegistryReceiptTests(unittest.TestCase):
    def make_lab(self, root, name='lab-Ab12'):
        lab = Path(root) / name
        lab.mkdir()
        (lab / 'state.env').write_text(f'LAB_ID={name}\nBRIDGE=br-op7\n')
        return lab

    def test_atomic_begin_and_ready(self):
        with tempfile.TemporaryDirectory() as d:
            self.make_lab(d)
            path = reg.persist(d, 'lab-Ab12', 'creating')
            self.assertEqual(json.loads(path.read_text())['phase'], 'creating')
            reg.persist(d, 'lab-Ab12', 'ready')
            self.assertEqual(reg.inspect(d)[0]['status'], 'recorded')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_missing_lab_is_stale_and_no_deletion(self):
        with tempfile.TemporaryDirectory() as d:
            lab = self.make_lab(d)
            reg.persist(d, 'lab-Ab12', 'ready')
            (lab / 'state.env').unlink()
            self.assertEqual(reg.inspect(d)[0]['status'], 'stale_or_invalid')
            self.assertTrue(lab.exists())

    def test_identity_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            self.make_lab(d)
            with self.assertRaises(ValueError):
                reg.persist(d, '../../etc', 'ready')
            (Path(d) / 'registry').symlink_to(Path(d) / 'other')
            with self.assertRaises(ValueError):
                reg.persist(d, 'lab-Ab12', 'ready')

    def test_no_host_calls(self):
        with tempfile.TemporaryDirectory() as d:
            self.make_lab(d)
            reg.persist(d, 'lab-Ab12', 'ready')
            records = reg.inspect(d)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]['resources'], 16)


if __name__ == '__main__':
    unittest.main()
