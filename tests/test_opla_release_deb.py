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

    def test_package_layout_rejects_maintainer_scripts_and_current(self):
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / 'pkg'
            destination = pkg / 'opt' / 'opla' / 'releases' / 'sha256-x'
            (pkg / 'DEBIAN').mkdir(parents=True)
            destination.mkdir(parents=True)
            (pkg / 'DEBIAN' / 'control').write_text('Package: test\n')
            (pkg / 'DEBIAN' / 'postinst').write_text('#!/bin/sh\n')
            with self.assertRaisesRegex(ValueError, 'maintainer scripts'):
                module._validate_package_layout(pkg, destination)

    def test_injected_dpkg_runner_contract(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return module.subprocess.CompletedProcess(argv, 0, '', '')

        result = module._run_dpkg_deb(['dpkg-deb', '--build'], runner=runner, timeout=7)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(calls[0][0], ['dpkg-deb', '--build'])
        self.assertEqual(calls[0][1]['timeout'], 7)
        self.assertFalse(calls[0][1]['check'])

    def test_failing_dpkg_runner_with_missing_stderr_blocks_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            output = root / 'package.deb'

            def fake_stage(_bundle, staged, _expected):
                staged.mkdir(parents=True)
                (staged / 'Makefile').write_text('sample\n')
                return 1

            def failed_runner(argv, **_kwargs):
                return module.subprocess.CompletedProcess(argv, 1, '', None)

            with patch.object(module.os, 'geteuid', return_value=1000), \
                 patch.object(module.stage, 'stage', side_effect=fake_stage):
                with self.assertRaisesRegex(ValueError, 'dpkg-deb failed'):
                    module.build('bundle', 'a' * 64, output, runner=failed_runner)
            self.assertFalse(output.exists())

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
