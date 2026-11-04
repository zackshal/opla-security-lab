import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "alerts_service_test", ROOT / "monitoring/alerts_service.py"
)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class AlertServiceUnitTests(unittest.TestCase):
    def test_unit_install_replaces_symlink_without_writing_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside.service"
            outside.write_text("keep\n", encoding="utf-8")
            unit = root / "user" / "opla-alerts.service"
            unit.parent.mkdir()
            unit.symlink_to(outside)

            module.write_unit(
                unit, "/usr/bin/python3", "/tmp/alert_delivery.py",
                root / "selected-lab",
            )

            self.assertFalse(unit.is_symlink())
            self.assertEqual(outside.read_text(encoding="utf-8"), "keep\n")
            self.assertIn("OPLA Zabbix email notifications", unit.read_text(encoding="utf-8"))
            self.assertEqual(unit.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
