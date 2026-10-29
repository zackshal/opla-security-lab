import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SuricataLauncherTests(unittest.TestCase):
    def test_guest_dependency_failures_are_actionable_and_precede_mutations(self):
        source = (ROOT / "bin/suricata.sh").read_text(encoding="utf-8")
        suricata_check = source.index("command -v suricata")
        yaml_check = source.index("import yaml")
        staging = source.index('mkdir -p /tmp/opla-suricata')
        logrotate_install = source.index("/etc/logrotate.d/opla-suricata")
        manager_call = source.index("manage.py '$mode'")

        self.assertIn("Suricata is missing from the victim VM", source)
        self.assertIn("PyYAML is missing from the victim VM", source)
        self.assertLess(suricata_check, yaml_check)
        self.assertLess(yaml_check, staging)
        self.assertLess(staging, logrotate_install)
        self.assertLess(logrotate_install, manager_call)


if __name__ == "__main__":
    unittest.main()
