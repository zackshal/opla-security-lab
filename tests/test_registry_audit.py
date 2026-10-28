import importlib.util
from pathlib import Path
import json
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1] / 'bin'
spec = importlib.util.spec_from_file_location('opla_registry_audit', ROOT / 'opla-registry-audit.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class AuditTests(unittest.TestCase):
    def lab(self, root, lab, bridge):
        d = Path(root)/lab
        d.mkdir()
        state = d/'state.env'
        state.write_text(
            f'LAB_ID={lab}\nBRIDGE={bridge}\nSUBNET=100.64.0.0/29\n'
            f'MGMT_BRIDGE={"br-op9" if bridge == "br-op8" else "br-op8"}\nMGMT_SUBNET=100.64.0.8/29\n'
            'MGMT_GW=100.64.0.9\nATTACKER_MGMT_IP=100.64.0.10\n'
            'VICTIM_MGMT_IP=100.64.0.11\nCLIENT_MGMT_IP=100.64.0.12\n'
        )
        state.chmod(0o600)
        mod.verify_mod.reg.persist(root, lab, 'ready')
        return d

    def test_empty_is_read_only(self):
        with tempfile.TemporaryDirectory() as root:
            report = mod.audit(root)
            self.assertEqual(report['summary']['receipts'],0)
            self.assertFalse(report['safe_for_deletion'])
            self.assertFalse((Path(root)/'registry').exists())

    def test_conflicting_bridges_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            self.lab(root,'lab-Aaaa','br-op7')
            self.lab(root,'lab-Bbbb','br-op7')
            report=mod.audit(root,lambda *_: ('present','mock'))
            self.assertTrue(report['conflicts'])
            self.assertGreater(report['summary']['errors'],0)
            self.assertFalse(report['safe_for_deletion'])

    def test_nonconflicting_receipts_still_not_authorization(self):
        with tempfile.TemporaryDirectory() as root:
            self.lab(root,'lab-Aaaa','br-op7')
            self.lab(root,'lab-Bbbb','br-op8')
            result=mod.audit(root,lambda *_: ('present','mock'))
            self.assertEqual(result['conflicts'],[])
            self.assertFalse(result['safe_for_deletion'])

    def test_corrupt_receipt_blocks_without_probe(self):
        with tempfile.TemporaryDirectory() as root:
            self.lab(root,'lab-Aaaa','br-op7')
            path=Path(root)/'registry/lab-Aaaa.json'
            data=json.loads(path.read_text());data['resources'][0]['name']='/etc/passwd'
            path.write_text(json.dumps(data))
            report=mod.audit(root,lambda *_: self.fail('no probing after invalid receipt'))
            self.assertGreater(report['summary']['errors'],0)

    def test_symlink_root_blocks(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'shortcut';path.symlink_to(Path(root),target_is_directory=True)
            result=mod.audit(path)
            self.assertGreater(result['summary']['errors'],0)

if __name__=='__main__': unittest.main()
