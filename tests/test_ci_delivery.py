import hashlib
import os
from pathlib import Path
import runpy
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

class DeliveryTests(unittest.TestCase):
    def test_package_contains_only_bpf_and_build_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'dist').mkdir()
            blob = b'test BPF fixture; not a loadable program'
            (root/'dist/xdp_ddos_protect.o').write_bytes(blob)
            (root/'dist/compiler.txt').write_text('test compiler\n')
            (root/'dist/packages.txt').write_text('test packages\n')
            (root/'dist/SHA256SUMS').write_text(hashlib.sha256(blob).hexdigest()+'  dist/xdp_ddos_protect.o\n')
            (root/'private.env').write_text('DO_NOT_PACKAGE=test\n')
            env = dict(os.environ, CI_COMMIT_SHA='a'*40)
            subprocess.run(['bash', str(ROOT/'ci/package.sh')], cwd=root, env=env, check=True, stdout=subprocess.DEVNULL)
            with tarfile.open(root/'dist/opla-bpf-aaaaaaaaaaaa.tar.gz') as archive:
                names = {member.name.removeprefix('./') for member in archive if member.isfile()}
                self.assertEqual(names, {'xdp_ddos_protect.o','compiler.txt','packages.txt','COMMIT','BUILD','VALIDATION','SHA256SUMS'})

    def test_package_rejects_corrupt_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'dist').mkdir()
            (root/'dist/xdp_ddos_protect.o').write_bytes(b'corrupt')
            (root/'dist/SHA256SUMS').write_text('0'*64+'  dist/xdp_ddos_protect.o\n')
            result = subprocess.run(['bash', str(ROOT/'ci/package.sh')], cwd=root,
                                    env=dict(os.environ, CI_COMMIT_SHA='a'*40), capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list((root/'dist').glob('*.tar.gz')), [])

    def test_unprotected_deployment_is_rejected_before_network(self):
        result = subprocess.run(['bash', str(ROOT/'ci/deploy.sh')],
                                env=dict(os.environ, CI_COMMIT_REF_PROTECTED='false', OPLA_DEPLOY_ENABLED='1'),
                                capture_output=True)
        self.assertEqual(result.returncode, 2)

    def test_deployment_requires_file_variables(self):
        env = {key: value for key, value in os.environ.items() if not key.startswith('OPLA_')}
        env.update(CI_COMMIT_REF_PROTECTED='true', OPLA_DEPLOY_ENABLED='1')
        result = subprocess.run(['bash', str(ROOT/'ci/deploy.sh')], env=env, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'OPLA_DEPLOY_INVENTORY', result.stderr)

    def test_suricata_validator_writes_required_yaml_header(self):
        try:
            import yaml
        except ImportError:
            self.skipTest('PyYAML unavailable')
        modes = []
        def validate(command, **kwargs):
            config = Path(command[-1]).read_text()
            self.assertTrue(config.startswith('%YAML 1.1\n---\n'))
            self.assertIsInstance(yaml.safe_load(config), dict)
            modes.append(command)
        original_read = Path.read_text
        def read(path, *args, **kwargs):
            if str(path) == '/etc/suricata/suricata.yaml':
                return '{}'
            return original_read(path, *args, **kwargs)
        with patch('subprocess.run', side_effect=validate), patch.object(Path, 'read_text', new=read):
            runpy.run_path(str(ROOT/'tools/check-suricata.py'), run_name='ci_validator_test')
        self.assertEqual(len(modes), 2)
