import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('system_install', Path(__file__).resolve().parents[1] / 'bin/opla-system-install.py')
INSTALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALL)


class SystemInstallTests(unittest.TestCase):
    def test_sparse_copy_preserves_data_holes_and_trailing_size(self):
        import io
        content = b'a' * (1024 * 1024) + b'\0' * (2 * 1024 * 1024)
        with tempfile.TemporaryFile() as output:
            INSTALL.copy_sparse(io.BytesIO(content), output)
            self.assertEqual(output.tell(), len(content))
            output.seek(0)
            self.assertEqual(output.read(), content)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / 'source'
        (self.source / 'bin').mkdir(parents=True)
        for name in ('Makefile', 'bin/opla-cli.py', 'bin/opla-create-launcher.py'):
            (self.source / name).write_text('# fixture\n')

    def test_snapshot_preserves_bytes_without_host_execution(self):
        (self.source / 'monitoring').mkdir()
        (self.source / 'monitoring/.env').write_text('DB_PASSWORD=must-not-enter-snapshot\n')
        digest, _ = INSTALL.inventory(self.source)
        target = self.base / 'installed'
        INSTALL.install(self.source, target, digest)
        self.assertEqual(INSTALL.inventory(target)[0], digest)
        self.assertEqual((target / 'bin/opla-cli.py').stat().st_mode & 0o777, 0o644)
        self.assertFalse((target / 'monitoring/.env').exists())

    def test_env_changes_do_not_change_snapshot_inventory(self):
        monitoring = self.source / 'monitoring'
        monitoring.mkdir()
        secret = monitoring / '.env'
        secret.write_text('DB_PASSWORD=first\n')
        first, _ = INSTALL.inventory(self.source)
        secret.write_text('DB_PASSWORD=second\n')
        second, _ = INSTALL.inventory(self.source)
        self.assertEqual(first, second)

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
