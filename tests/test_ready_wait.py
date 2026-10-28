"""Readiness retries use fake shell SSH; no guests or host mutation."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReadyWaitTests(unittest.TestCase):
    def run_wait(self, fake):
        script = '''
set -eu
export LAB_DIR=/tmp/fixture
source "$1/xdp/lib.sh"
python3() { echo 100.64.0.10; }
timeout() { shift; "$@"; }
sleep() { :; }
''' + fake + '\nwait_vm_ready 100.64.0.2 attacker\n'
        return subprocess.run(['bash', '-c', script, 'fixture', str(ROOT)],
                              capture_output=True, text=True, timeout=3)

    def test_transient_refusal_retried(self):
        result = self.run_wait('''
SECONDS=0
ssh() {
    # SECONDS is advanced by fake sleep in the parent shell.
    if (( SECONDS == 0 )); then echo 'Connection refused' >&2; return 255; fi
    echo 'status: done'
}
sleep() { SECONDS=1; }
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PASS: attacker', result.stdout)

    def test_host_key_failure_not_retried(self):
        result = self.run_wait("ssh() { echo 'Host key verification failed' >&2; return 255; }")
        self.assertEqual(result.returncode, 255)
        self.assertIn('Host key verification failed', result.stderr)

    def test_cloud_init_failure_is_not_ready(self):
        result = self.run_wait("ssh() { echo 'status: error'; return 1; }")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('PASS:', result.stdout)
