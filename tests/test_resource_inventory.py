"""Read-only inventory never invokes destructive commands."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'bin' / 'opla-resources.py'
spec = importlib.util.spec_from_file_location('opla_resources', SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ResourceInventoryTests(unittest.TestCase):
    def dual_state(self):
        return (
            'LAB_ID=lab-Ab12\nBRIDGE=br-op7\nSUBNET=100.64.0.0/29\n'
            'MGMT_BRIDGE=br-op8\nMGMT_SUBNET=100.64.0.8/29\n'
            'MGMT_GW=100.64.0.9\nATTACKER_MGMT_IP=100.64.0.10\n'
            'VICTIM_MGMT_IP=100.64.0.11\nCLIENT_MGMT_IP=100.64.0.12\n'
        )

    def test_valid_dual_nic_state_is_accepted(self):
        self.assertEqual(
            module.validate_state(dict(line.split('=', 1) for line in self.dual_state().splitlines()), 'lab-Ab12')['MGMT_BRIDGE'],
            'br-op8')

    def test_partial_or_overlapping_management_state_is_rejected(self):
        state = dict(line.split('=', 1) for line in self.dual_state().splitlines())
        state.pop('CLIENT_MGMT_IP')
        with self.assertRaises(ValueError):
            module.validate_state(state, 'lab-Ab12')
        state = dict(line.split('=', 1) for line in self.dual_state().splitlines())
        state['MGMT_SUBNET'] = '100.64.0.0/29'
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            module.validate_state(state, 'lab-Ab12')

    def test_inventory_skips_invalid_management_state_without_host_probe(self):
        for mutation in ('partial', 'overlap', 'outside'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as root:
                lab = Path(root) / 'lab-Ab12'
                lab.mkdir()
                state = self.dual_state()
                if mutation == 'partial':
                    state = state.replace('CLIENT_MGMT_IP=100.64.0.12\n', '')
                elif mutation == 'overlap':
                    state = state.replace('MGMT_SUBNET=100.64.0.8/29', 'MGMT_SUBNET=100.64.0.0/29')
                else:
                    state = state.replace('MGMT_GW=100.64.0.9', 'MGMT_GW=10.0.0.1')
                (lab / 'state.env').write_text(state)
                with mock.patch.object(module, 'call', side_effect=AssertionError('host probe')):
                    records, warnings = module.inventory(Path(root), inspect_runtime=False)
                self.assertFalse(any(r['lab'] == 'lab-Ab12' for r in records))
                self.assertTrue(any('lab-Ab12' in warning for warning in warnings))

    def test_inventory_scopes_and_shared_resource(self):
        with tempfile.TemporaryDirectory() as root:
            lab = Path(root) / 'lab-Ab12'
            (lab / 'victim').mkdir(parents=True)
            (lab / 'state.env').write_text('LAB_ID=lab-Ab12\nBRIDGE=br-op7\n')
            (lab / 'victim' / 'disk.qcow2').write_bytes(b'fake')
            with mock.patch.object(module, 'call', side_effect=AssertionError('no host commands expected')):
                records, warnings = module.inventory(Path(root), inspect_runtime=False)
            self.assertEqual(warnings, [])
            self.assertTrue(any(r['type'] == 'lab_directory' and r['lab'] == 'lab-Ab12' for r in records))
            self.assertTrue(any(r['scope'] == 'shared' and r['type'] == 'compose_project' for r in records))
            self.assertFalse(any(r['confidence'] == 'verified_owner' for r in records))

    def test_rejects_symlink_lab_and_invalid_id(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / 'outside'
            target.mkdir()
            (Path(root) / 'lab-Fake').symlink_to(target, target_is_directory=True)
            records, warnings = module.inventory(Path(root), inspect_runtime=False)
            self.assertEqual(len(warnings), 1)
            self.assertFalse(any(r['lab'] == 'lab-Fake' for r in records))
            with self.assertRaises(SystemExit):
                module.main(['prune', '--lab', '../../etc'])

    def test_preview_explicitly_non_destructive(self):
        with mock.patch.object(module, 'inventory', return_value=([], [])):
            with mock.patch.object(module, 'render') as render:
                self.assertEqual(module.main(['prune']), 0)
                self.assertEqual(render.call_args.args[2], 'prune')


if __name__ == '__main__':
    unittest.main()
