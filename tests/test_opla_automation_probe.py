import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class AutomationProbeTests(unittest.TestCase):

    def test_probe_dispatch_is_read_only(self):
        source = (
            ROOT / "bin/opla-automation.sh"
        ).read_text()

        match = re.search(
            r'(?m)^    probe\)\s*\n(.*?)^        ;;',
            source,
            re.DOTALL | re.MULTILINE,
        )

        self.assertIsNotNone(match)
        commands = match.group(1)

        self.assertIn("check_guest_target", commands)
        self.assertIn(
            "playbook ansible/playbooks/preflight.yml",
            commands,
        )

        self.assertNotIn("provision", commands.replace(
            "# No provisioning, package installation or VM lifecycle.", ""
        ))
        self.assertNotIn("remote_acceptance", commands)
        self.assertNotIn("validate\n", commands)

    def test_probe_make_target_does_not_use_guest_mode(self):
        source = (ROOT / "Makefile").read_text()

        match = re.search(
            r'(?m)^automation-probe:\s*\n([^\n]+)',
            source,
        )

        self.assertIsNotNone(match)
        self.assertIn(
            "./bin/opla-automation.sh probe",
            match.group(1),
        )


if __name__ == "__main__":
    unittest.main()
