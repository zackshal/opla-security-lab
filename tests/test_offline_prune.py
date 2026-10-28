import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

SCRIPT = Path(__file__).resolve().parents[1]/'bin'/'opla-offline-prune.py'
spec=importlib.util.spec_from_file_location('offline_prune',SCRIPT)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class OfflinePruneTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.lab='lab-Test123'
        (self.root/self.lab).mkdir()
        (self.root/'registry').mkdir()
        state = self.root/self.lab/'state.env'
        state.write_text(
            'LAB_ID=lab-Test123\nBRIDGE=br-op7\nSUBNET=100.64.0.0/29\n'
            'MGMT_BRIDGE=br-op8\nMGMT_SUBNET=100.64.0.8/29\n'
            'MGMT_GW=100.64.0.9\nATTACKER_MGMT_IP=100.64.0.10\n'
            'VICTIM_MGMT_IP=100.64.0.11\nCLIENT_MGMT_IP=100.64.0.12\n'
        )
        state.chmod(0o600)
        receipt=module.registry.receipt(self.root,self.lab,'ready')
        receipt_path = self.root/'registry'/(self.lab+'.json')
        receipt_path.write_text(json.dumps(receipt))
        receipt_path.chmod(0o600)
        self.own=patch.object(module,'safe_root',side_effect=lambda p: Path(p))
        self.own.start();self.addCleanup(self.own.stop)
    def runner(self,cmd):
        if cmd[0]=='ip':return SimpleNamespace(returncode=1,stderr='Device does not exist',stdout='')
        if cmd[0]=='nft':return SimpleNamespace(returncode=0,stderr='',stdout='table inet unrelated\n')
        if cmd[0]=='systemctl':return SimpleNamespace(returncode=0,stderr='',stdout='ActiveState=inactive\nLoadState=not-found\nMainPID=0\n')
        raise AssertionError(cmd)
    def test_plan_does_not_delete(self):
        assert module.check(self.root,self.lab,self.runner)['mode']=='offline_only'
        assert (self.root/self.lab).exists()
    def test_confirmation_required(self):
        with self.assertRaises(module.Blocked):module.execute(self.root,self.lab,'wrong',self.runner)
        assert (self.root/self.lab).exists()
    def test_network_device_present_blocks(self):
        def runner(cmd):
            if cmd[0]=='ip':return SimpleNamespace(returncode=0,stdout='something',stderr='')
            return self.runner(cmd)
        with self.assertRaises(module.Blocked):module.check(self.root,self.lab,runner)
    def test_missing_registry_explained(self):
        import shutil
        shutil.rmtree(self.root/'registry')
        with self.assertRaisesRegex(module.Blocked,'registry not initialized'):
            module.check(self.root,self.lab,self.runner)

    def test_missing_receipt_explained(self):
        (self.root/'registry'/(self.lab+'.json')).unlink()
        with self.assertRaisesRegex(module.Blocked,'no registry receipt'):
            module.check(self.root,self.lab,self.runner)

    def test_symlink_registry_explained(self):
        import shutil
        shutil.rmtree(self.root/'registry')
        (self.root/'registry').symlink_to(self.root/self.lab, target_is_directory=True)
        with self.assertRaisesRegex(module.Blocked,'unsafe registry'):
            module.check(self.root,self.lab,self.runner)

    def test_symlink_blocks(self):
        (self.root/self.lab/'bad').symlink_to('/etc/passwd')
        with self.assertRaises(module.Blocked):module.check(self.root,self.lab,self.runner)
    def test_success_removes_only_lab_and_receipt(self):
        (self.root/'untouched').write_text('important')
        module.execute(self.root,self.lab,'DELETE-OFFLINE:lab-Test123',self.runner)
        assert not (self.root/self.lab).exists()
        assert not (self.root/'registry'/(self.lab+'.json')).exists()
        assert (self.root/'untouched').read_text()=='important'
        assert 'completed' in (self.root/'operations'/'lab-cleanup.jsonl').read_text()

if __name__=='__main__':unittest.main()
