import importlib.util
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / 'bin' / 'opla-monitoring-prune.py'
spec = importlib.util.spec_from_file_location('opla_mp', PATH)
mp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mp)

class MonitoringPurgeTests(unittest.TestCase):
    def test_wrong_confirmation_never_runs(self):
        with self.assertRaises(mp.Blocked):
            mp.purge('/nonexistent', 'yes', check=lambda _: self.fail('must not check'), execute=lambda *_: self.fail('must not execute'))

    def test_empty_noop(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            (repo / 'monitoring').mkdir()
            (repo / 'monitoring/compose.yaml').write_text('name: opla-monitoring\n')
            def fake(*cmd):
                if cmd[0:2] == ('ps', '-a') or cmd[0:2] == ('volume', 'ls') or cmd[0:2] == ('network', 'ls'):
                    return ''
                raise AssertionError(cmd)
            self.assertTrue(mp.audit(repo, docker_api=fake)['empty'])

    def test_unknown_service_blocks(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            (repo / 'monitoring').mkdir()
            (repo / 'monitoring/compose.yaml').write_text('name: opla-monitoring\n')
            def fake(*cmd):
                if cmd[0:2] == ('ps', '-a') and '-q' in cmd:
                    return 'container-1'
                if cmd[0:2] == ('inspect', '--type'):
                    import json
                    return json.dumps([{'Id': 'container-1', 'Config': {'Labels': {'com.docker.compose.project':'opla-monitoring','com.docker.compose.service':'unknown'}}}])
                raise AssertionError(cmd)
            with self.assertRaises(mp.Blocked):
                mp.audit(repo, docker_api=fake)

if __name__ == '__main__':
    unittest.main()

class OrphanVolumeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        (self.repo / 'monitoring').mkdir()
        (self.repo / 'monitoring/compose.yaml').write_text('name: opla-monitoring\n')
        self.executed = []

    def fake(self, *cmd):
        import json
        if cmd[:2] in (('ps', '-a'), ('network', 'ls')) and '-q' in cmd:
            return ''
        if cmd[:2] == ('volume', 'ls'):
            return mp.VOLUME
        if cmd[:3] == ('inspect', '--type', 'volume'):
            return json.dumps([{
                'Name': mp.VOLUME, 'Driver': 'local', 'Scope': 'local',
                'Labels': {'com.docker.compose.project': mp.PROJECT,
                           'com.docker.compose.volume': 'db-data'}}])
        raise AssertionError(f'unexpected docker call {cmd}')

    def plan(self):
        return mp.audit(self.repo, docker_api=self.fake)

    def test_orphan_plan_read_only(self):
        plan = self.plan()
        self.assertTrue(plan['orphan_volume'])
        self.assertEqual(plan['containers'], {})
        self.assertEqual(plan['networks'], [])
        self.assertEqual(plan['volume'], mp.VOLUME)

    def test_full_stack_confirmation_cannot_delete_orphan(self):
        with self.assertRaises(mp.Blocked):
            mp.purge(self.repo, f'PURGE:{mp.PROJECT}:{mp.VOLUME}',
                     check=lambda _: self.plan(), execute=lambda *x: self.executed.append(x), root=self.repo)
        self.assertEqual(self.executed, [])

    def test_orphan_confirmation_deletes_only_volume(self):
        mp.purge(self.repo, f'PURGE-ORPHAN:{mp.PROJECT}:{mp.VOLUME}',
                 check=lambda _: self.plan(), execute=lambda *x: self.executed.append(x), root=self.repo)
        self.assertEqual(self.executed, [('volume', 'rm', mp.VOLUME)])

    def test_lab_directory_blocks_deletion(self):
        (self.repo / 'lab-ABCDEFGH').mkdir()
        with self.assertRaises(mp.Blocked):
            mp.purge(self.repo, f'PURGE-ORPHAN:{mp.PROJECT}:{mp.VOLUME}',
                     check=lambda _: self.plan(), execute=lambda *x: self.executed.append(x), root=self.repo)
        self.assertEqual(self.executed, [])

    def test_foreign_container_using_volume_blocks(self):
        import json
        def fake(*cmd):
            if cmd[:2] == ('ps', '-a') and '-q' in cmd:
                if 'label=com.docker.compose.project' in ' '.join(cmd):
                    return ''
                return 'foreign-container'
            if cmd[:3] == ('inspect', '--type', 'container'):
                return json.dumps([{'Id':'foreign-container', 'Mounts':[{'Name': mp.VOLUME}]}])
            return self.fake(*cmd)
        with self.assertRaises(mp.Blocked):
            mp.audit(self.repo, docker_api=fake)
