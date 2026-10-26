import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('opla_creation_rollback_test', ROOT / 'bin/opla-creation-rollback.py')
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class Probe:
    def __init__(self, live=False):
        self.live = live

    def __call__(self, args):
        if args[0] == 'ip':
            return subprocess.CompletedProcess(args, 0 if self.live else 1, '', 'Device does not exist')
        if args[0] == 'nft':
            result = 'table inet opla_other\n' if not self.live else 'table inet opla_lab_Ab1234\n'
            return subprocess.CompletedProcess(args, 0, result, '')
        if args[0] == 'systemctl':
            return subprocess.CompletedProcess(args, 0, 'ActiveState=active\nMainPID=10\nLoadState=loaded\n' if self.live else 'ActiveState=inactive\nMainPID=0\nLoadState=not-found\n', '')
        raise AssertionError(args)


def setup_lab(root, phase='creating'):
    lab = 'lab-Ab1234'
    folder = root / lab
    folder.mkdir()
    (folder / 'state.env').write_text('LAB_ID=lab-Ab1234\nBRIDGE=br-op7\nGW=10.10.10.1\n')
    (folder / 'attacker').mkdir()
    (folder / 'attacker' / 'disk.qcow2').write_bytes(b'fake')
    reg = root / 'registry'
    reg.mkdir()
    reg.joinpath(lab + '.json').write_text(json.dumps(MOD.registry.receipt(root, lab, phase)))
    return lab


class CreationRollbackTests(unittest.TestCase):
    def test_plan_is_non_destructive(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            lab = setup_lab(root)
            with patch.object(MOD.prune, 'safe_root', side_effect=lambda p: Path(p)):
                self.assertEqual(MOD.verify(root, lab, Probe())['phase'], 'creating')
            self.assertTrue((root / lab).exists())

    def test_active_host_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            lab = setup_lab(root)
            with self.assertRaises(MOD.Blocked):
                MOD.verify(root, lab, Probe(live=True))
            self.assertTrue((root / lab).exists())

    def test_ready_receipt_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            lab = setup_lab(root, 'ready')
            with self.assertRaises(MOD.Blocked):
                MOD.verify(root, lab, Probe())

    def test_wrong_confirmation_keeps_data(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            lab = setup_lab(root)
            with self.assertRaises(MOD.Blocked):
                MOD.execute(root, lab, 'WRONG', Probe())
            self.assertTrue((root / lab).exists())

    def test_verified_offline_cleanup_records_journal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            lab = setup_lab(root)
            with patch.object(MOD.prune, 'safe_root', side_effect=lambda p: Path(p)), \
                 patch.object(MOD, 'lock_is_safe', return_value=True):
                MOD.execute(root, lab, 'ROLLBACK-CREATION:' + lab, Probe())
            self.assertFalse((root / lab).exists())
            self.assertFalse((root / 'registry' / (lab + '.json')).exists())
            lines = (root / 'operations' / 'lab-cleanup.jsonl').read_text().splitlines()
            self.assertIn('"outcome": "completed"', lines[-1])

    def test_production_root_and_lock_guards_are_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            lab = setup_lab(root)
            if root.stat().st_uid != 0:
                with self.assertRaisesRegex(MOD.Blocked, 'root-owned'):
                    MOD.verify(root, lab, Probe())
            with patch.object(MOD.prune, 'safe_root', side_effect=lambda p: Path(p)):
                with patch.object(MOD, 'lock_is_safe', return_value=False):
                    with self.assertRaisesRegex(MOD.Blocked, 'unsafe global lifecycle lock'):
                        MOD.execute(root, lab, 'ROLLBACK-CREATION:' + lab, Probe())
                self.assertTrue((root / lab).exists())

    def test_symlink_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            lab = setup_lab(root)
            (root / lab / 'evil').symlink_to('/tmp')
            with self.assertRaises(MOD.Blocked):
                MOD.verify(root, lab, Probe())


if __name__ == '__main__':
    unittest.main()
