"""Exercise the Make recipe with fake commands; never invoke real sudo/VMs."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CreateCallerTests(unittest.TestCase):
    def run_recipe(self, uid):
        make = (ROOT / 'Makefile').read_text()
        recipe = make.split('\nup:\n', 1)[1].split('\nready ssh console:', 1)[0]
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            scripts = {
                'id': f'#!/bin/sh\necho {uid}\n',
                'python3': '#!/bin/sh\nprintf "direct:%s:%s\\n" "$SUDO_USER" "$1"\n',
                'sudo': '#!/bin/sh\nprintf "sudo:%s\\n" "$*"\n',
            }
            for name, contents in scripts.items():
                script = folder / name
                script.write_text(contents)
                script.chmod(0o755)
            # Absolute fake commands prevent shell startup files from restoring PATH.
            recipe = recipe.replace('id -u', f'/bin/sh {folder}/id -u')
            recipe = recipe.replace('python3', f'/bin/sh {folder}/python3')
            recipe = recipe.replace('sudo ', f'/bin/sh {folder}/sudo ')
            (folder / 'Makefile').write_text('up:\n' + recipe + '\n')
            result = subprocess.run(
                ['make', '--no-print-directory', '-C', temp, 'up'],
                env={**os.environ, 'PATH': f'{temp}:/usr/bin:/bin', 'SUDO_USER': 'fixture-user'},
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()

    def test_root_preserves_original_sudo_user_without_nested_sudo(self):
        self.assertEqual(self.run_recipe(0), 'direct:fixture-user:bin/opla-create-launcher.py')

    def test_unprivileged_user_still_requires_sudo(self):
        self.assertTrue(self.run_recipe(1000).startswith('sudo:/bin/sh '))
