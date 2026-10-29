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
        state = lab / 'state.env'
        state.write_text(
            f'LAB_ID={name}\nBRIDGE=br-op7\nSUBNET=100.64.0.0/29\n'
            'MGMT_BRIDGE=br-op8\nMGMT_SUBNET=100.64.0.8/29\n'
            'MGMT_GW=100.64.0.9\nATTACKER_MGMT_IP=100.64.0.10\n'
            'VICTIM_MGMT_IP=100.64.0.11\nCLIENT_MGMT_IP=100.64.0.12\n'
        )
        state.chmod(0o600)
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

    def test_state_hardlink_and_group_writable_file_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            lab = self.make_lab(d)
            state = lab / 'state.env'
            copy = Path(d) / 'state-copy.env'
            copy.write_text(state.read_text())
            state.unlink()
            state.hardlink_to(copy)
            with self.assertRaisesRegex(ValueError, 'state.env'):
                reg.state_of(d, 'lab-Ab12')
            state.unlink()
            state.write_text(copy.read_text())
            state.chmod(0o666)
            with self.assertRaisesRegex(ValueError, 'ownership or mode'):
                reg.state_of(d, 'lab-Ab12')

    def test_no_host_calls(self):
        with tempfile.TemporaryDirectory() as d:
            self.make_lab(d)
            reg.persist(d, 'lab-Ab12', 'ready')
            records = reg.inspect(d)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]['resources'], 20)
            self.assertEqual(records[0]['state']['LAB_ID'], 'lab-Ab12')
            self.assertEqual(records[0]['state']['MGMT_BRIDGE'], 'br-op8')

    def test_inspection_rejects_receipt_resource_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            self.make_lab(d)
            path = reg.persist(d, 'lab-Ab12', 'ready')
            receipt = json.loads(path.read_text())
            receipt['resources'].pop()
            path.write_text(json.dumps(receipt))
            path.chmod(0o600)
            self.assertEqual(reg.inspect(d)[0]['status'], 'stale_or_invalid')

    def test_ready_rejects_single_nic_state(self):
        with tempfile.TemporaryDirectory() as d:
            lab = Path(d) / 'lab-Ab12'
            lab.mkdir()
            state = lab / 'state.env'
            state.write_text('LAB_ID=lab-Ab12\nBRIDGE=br-op7\n')
            state.chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'dual-NIC'):
                reg.persist(d, 'lab-Ab12', 'ready')

    def test_ready_rejects_overlapping_management_subnet(self):
        with tempfile.TemporaryDirectory() as d:
            lab = self.make_lab(d)
            state = (lab / 'state.env').read_text().replace(
                'MGMT_SUBNET=100.64.0.8/29', 'MGMT_SUBNET=100.64.0.0/29')
            (lab / 'state.env').write_text(state)
            (lab / 'state.env').chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'overlapping'):
                reg.persist(d, 'lab-Ab12', 'ready')


if __name__ == '__main__':
    unittest.main()
