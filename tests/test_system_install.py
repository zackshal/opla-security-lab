import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('system_install', Path(__file__).resolve().parents[1] / 'bin/opla-system-install.py')
INSTALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALL)


class SystemInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / 'source'
        (self.source / 'bin').mkdir(parents=True)
        for name in ('Makefile', 'bin/opla-cli.py', 'bin/opla-create-launcher.py'):
            (self.source / name).write_text('# fixture\n')

    def test_snapshot_preserves_bytes_without_host_execution(self):
        digest, _ = INSTALL.inventory(self.source)
        target = self.base / 'installed'
        INSTALL.install(self.source, target, digest)
        self.assertEqual(INSTALL.inventory(target)[0], digest)
        self.assertEqual((target / 'bin/opla-cli.py').stat().st_mode & 0o777, 0o644)

    def test_changed_source_blocks_before_destination(self):
        digest, _ = INSTALL.inventory(self.source)
        (self.source / 'Makefile').write_text('changed')
        with self.assertRaises(ValueError):
            INSTALL.install(self.source, self.base / 'installed', digest)
        self.assertFalse((self.base / 'installed').exists())

    def test_existing_target_and_symlinks_rejected(self):
        target = self.base / 'installed'
        target.mkdir()
        with self.assertRaises(ValueError):
            INSTALL.install(self.source, target, 'unused')
        (self.source / 'link').symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):
            INSTALL.inventory(self.source)
