"""No root, no package installation, no VM startup."""

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1] / 'bin'
spec = importlib.util.spec_from_file_location(
    'opla_release_deb_test',
    HERE / 'opla-release-deb.py',
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DebReleaseTests(unittest.TestCase):

    def test_root_denied(self):
        with patch.object(module.os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(
                ValueError, 'root execution forbidden'
            ):
                module.build(
                    'anything', '0' * 64,
                    '/tmp/does-not-matter.deb'
                )

    def test_digest_validation(self):
        if os.geteuid() == 0:
            self.skipTest('run unprivileged')

        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            module.build(
                'anything', 'UNAPPROVED',
                '/tmp/does-not-matter.deb'
            )

    def test_no_overwrite(self):
        if os.geteuid() == 0:
            self.skipTest('run unprivileged')

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            dest = root / 'package.deb'
            dest.touch()

            with self.assertRaisesRegex(ValueError, 'output exists'):
                module.build('anything', '0' * 64, dest)

    def test_output_guard_before_extract(self):
        if os.geteuid() == 0:
            self.skipTest('run unprivileged')

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            dest = root / 'package.deb'
            dest.touch()

            with patch.object(module.stage, 'stage') as stage_call:
                with self.assertRaisesRegex(
                    ValueError, 'output exists'
                ):
                    module.build('anything', '0' * 64, dest)

                stage_call.assert_not_called()


if __name__ == '__main__':
    unittest.main()
