import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1] / 'bin'
spec = importlib.util.spec_from_file_location('opla_verify', ROOT / 'opla-registry-verify.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class VerifyTests(unittest.TestCase):
    def lab(self, root):
        path = Path(root) / 'lab-Ab12'
        path.mkdir()
        state = path / 'state.env'
        state.write_text(
            'LAB_ID=lab-Ab12\nBRIDGE=br-op7\nSUBNET=100.64.0.0/29\n'
            'MGMT_BRIDGE=br-op8\nMGMT_SUBNET=100.64.0.8/29\n'
            'MGMT_GW=100.64.0.9\nATTACKER_MGMT_IP=100.64.0.10\n'
            'VICTIM_MGMT_IP=100.64.0.11\nCLIENT_MGMT_IP=100.64.0.12\n'
        )
        state.chmod(0o600)
        mod.reg.persist(root, 'lab-Ab12', 'ready')
        return path

    def test_verified_resource_names_still_block_deletion(self):
        with tempfile.TemporaryDirectory() as root:
            self.lab(root)
            seen = []
            def fake(kind, name):
                seen.append((kind, name))
                return 'present', 'fake'
            result = mod.verify(root, inspector=fake)[0]
            self.assertEqual(len(seen), 20)
            self.assertFalse(result['verified_for_deletion'])
            self.assertEqual(result['status'], 'observed_unverified')

    def test_poisoned_resource_path_fails_closed_without_probe(self):
        with tempfile.TemporaryDirectory() as root:
            self.lab(root)
            path = Path(root) / 'registry/lab-Ab12.json'
            receipt = json.loads(path.read_text())
            receipt['resources'][0]['name'] = '/etc/passwd'
            path.write_text(json.dumps(receipt))
            result = mod.verify(root, inspector=lambda *_: self.fail('must not probe'))[0]
            self.assertEqual(result['status'], 'blocked')
            self.assertIn('differ from state.env', result['errors'][0])

    def test_deleted_lab_stays_blocked(self):
        with tempfile.TemporaryDirectory() as root:
            lab = self.lab(root)
            (lab / 'state.env').unlink()
            result = mod.verify(root, inspector=lambda *_: self.fail('must not probe'))[0]
            self.assertEqual(result['status'], 'blocked')

    def test_symlink_receipt_stays_blocked(self):
        with tempfile.TemporaryDirectory() as root:
            self.lab(root)
            path = Path(root) / 'registry/lab-Ab12.json'
            path.unlink()
            path.symlink_to('/etc/passwd')
            self.assertEqual(mod.verify(root)[0]['status'], 'blocked')

    def test_hardlink_or_writable_receipt_stays_blocked(self):
        with tempfile.TemporaryDirectory() as root:
            self.lab(root)
            path = Path(root) / 'registry/lab-Ab12.json'
            other = Path(root) / 'receipt-copy.json'
            path.unlink()
            other.write_text('{}')
            path.hardlink_to(other)
            self.assertEqual(mod.verify(root)[0]['status'], 'blocked')
            path.unlink()
            path.write_text('{}')
            path.chmod(0o666)
            self.assertEqual(mod.verify(root)[0]['status'], 'blocked')

    def test_inspector_failure_and_malformed_result_stay_blocked(self):
        for inspector in (
                lambda *_: (_ for _ in ()).throw(RuntimeError('backend down')),
                lambda *_: (object(), 'detail')):
            with tempfile.TemporaryDirectory() as root:
                self.lab(root)
                result = mod.verify(root, inspector=inspector)[0]
                self.assertEqual(result['status'], 'blocked')
                self.assertFalse(result['verified_for_deletion'])
                self.assertTrue(result['errors'])

    def test_no_registry_does_not_create_files(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(mod.verify(root), [])
            self.assertFalse((Path(root) / 'registry').exists())


if __name__ == '__main__':
    unittest.main()
