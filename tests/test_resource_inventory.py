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
