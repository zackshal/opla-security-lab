import importlib.util
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
spec=importlib.util.spec_from_file_location('disk_integration',ROOT/'bin/vm-disk.py')
disk=importlib.util.module_from_spec(spec)
spec.loader.exec_module(disk)

@unittest.skipUnless(shutil.which('qemu-img') and shutil.which('qemu-io'), 'qemu-utils not installed')
class DiskIntegration(unittest.TestCase):
    def test_standalone_backup_and_restore_retains_old_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);lab=root/'lab-test';lab.mkdir()
            base=root/'base.qcow2'
            subprocess.run(['qemu-img','create','-q','-f','qcow2',str(base),'16M'],check=True)
            (lab/'state.env').write_text('LAB_ID=lab-test\n')
            for vm in disk.VMS:
                folder=lab/vm;folder.mkdir();(folder/'seed.iso').write_bytes(b'test seed')
                subprocess.run(['qemu-img','create','-q','-f','qcow2','-F','qcow2','-b',str(base),str(folder/'disk.qcow2')],check=True)
            victim=lab/'victim/disk.qcow2'
            subprocess.run(['qemu-io','-f','qcow2','-c','write -P 0x5a 0 4096',str(victim)],check=True,stdout=subprocess.DEVNULL)
            archive=root/'backup';disk.backup(lab,archive)
            subprocess.run(['qemu-io','-f','qcow2','-c','write -P 0x0 0 4096',str(victim)],check=True,stdout=subprocess.DEVNULL)
            disk.restore(lab,archive,'victim')
            self.assertEqual(subprocess.run(['qemu-img','compare',str(victim),str(archive/'victim.qcow2')],stdout=subprocess.DEVNULL).returncode,0)
            self.assertEqual(len(list(victim.parent.glob('disk.before-restore-*.qcow2'))),1)
