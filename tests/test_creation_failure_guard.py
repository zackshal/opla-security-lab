from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]

class CreationFailureGuardTests(unittest.TestCase):
    def test_creation_error_does_not_call_legacy_cleanup(self):
        source = (ROOT / 'bin' / 'create-lab.sh').read_text()
        self.assertIn('opla_creation_failed', source)
        self.assertIn('trap \'opla_creation_failed "$?"\' ERR', source)
        self.assertNotIn('"$SCRIPT_DIR/cleanup-lab.sh" "$LAB_DIR"', source)

    def test_locks_and_registry_are_preserved(self):
        source = (ROOT / 'bin' / 'create-lab.sh').read_text()
        self.assertIn('exec 8>/var/lib/opla/.opla-prune.lock', source)
        self.assertIn('flock -n 8', source)
        self.assertIn('opla-registry.py" begin', source)
        self.assertIn('opla-registry.py" ready', source)

    def test_shell_syntax(self):
        subprocess.run(['bash', '-n', str(ROOT / 'bin' / 'create-lab.sh')], check=True)

if __name__ == '__main__':
    unittest.main()
