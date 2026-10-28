"""Offline unprivileged version promotion contract."""
import hashlib
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'bin' / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
bundle = load('opla-release-bundle.py')
promote = load('opla-release-promote.py')

class ReviewPromoteTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / 'src'
        for name in ('Makefile', 'bin/opla-create-launcher.py',
                     'bin/opla-lab-configure-launcher.py', 'bin/create-lab.sh',
                     'bin/opla-lifecycle-lock.py'):
            p = self.source / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('sample\n')
        self.archive = self.root / 'bundle.tar.gz'
        bundle.build(self.source, self.archive)
        self.digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.install = self.root / 'review'

    def call(self, digest=None):
        with patch.object(promote.os, 'geteuid', return_value=1000):
            return promote.promote(self.archive, self.install, digest or self.digest)

    def test_promote_and_activate(self):
        ident, count = self.call()
        self.assertEqual(count, 5)
        self.assertEqual(os.readlink(self.install / 'current'), 'releases/' + ident)
        self.assertTrue((self.install / 'current' / 'REVIEW.json').exists())

    def test_refuse_unapproved_bundle(self):
        with self.assertRaises(ValueError):
            self.call('0' * 64)
        self.assertFalse((self.install / 'current').exists())

    def test_no_overwrite_existing_release(self):
        self.call()
        with self.assertRaisesRegex(ValueError, 'already staged'):
            self.call()

    def test_root_forbidden(self):
        with patch.object(promote.os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(ValueError, 'root execution forbidden'):
                promote.promote(self.archive, self.install, self.digest)

    def test_external_current_link_rejected(self):
        self.install.mkdir(mode=0o700)
        (self.install / 'current').symlink_to('/etc')
        with self.assertRaisesRegex(ValueError, 'outside managed releases'):
            self.call()
        self.assertEqual(os.readlink(self.install / 'current'), '/etc')

    def test_parent_symlink_rejected(self):
        link = self.root / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with patch.object(promote.os, 'geteuid', return_value=1000):
            with self.assertRaises(ValueError):
                promote.promote(self.archive, link / 'review', self.digest)

    def test_current_replace_failure_does_not_change_existing_current(self):
        self.call()
        old = os.readlink(self.install / 'current')
        second_source = self.root / 'src-second'
        second_source.mkdir()
        for name in ('Makefile', 'bin/opla-create-launcher.py',
                     'bin/opla-lab-configure-launcher.py', 'bin/create-lab.sh',
                     'bin/opla-lifecycle-lock.py'):
            p = second_source / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('second\n')
        second_archive = self.root / 'bundle-second.tar.gz'
        bundle.build(second_source, second_archive)
        second_digest = hashlib.sha256(second_archive.read_bytes()).hexdigest()
        with patch.object(promote.os, 'replace', side_effect=OSError('activation interrupted')):
            with patch.object(promote.os, 'geteuid', return_value=1000):
                with self.assertRaisesRegex(OSError, 'activation interrupted'):
                    promote.promote(second_archive, self.install, second_digest)
        self.assertEqual(os.readlink(self.install / 'current'), old)
        self.assertFalse((self.install / ('.current-' + second_digest)).exists())

if __name__ == '__main__':
    unittest.main()
