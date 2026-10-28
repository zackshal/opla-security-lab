import importlib.util
from pathlib import Path
import sys
import tempfile
from unittest import TestCase
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
SPEC = importlib.util.spec_from_file_location("lab_cli", ROOT / "bin/lab-cli.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LabSelectionTests(TestCase):
    def test_missing_selected_lab_is_cleared(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selection = root / "selected-lab"
            selection.write_text("lab-gone\n", encoding="utf-8")
            with patch.object(MODULE, "SELECTION", selection), \
                 patch.object(MODULE, "validate", side_effect=FileNotFoundError("lab removed")):
                self.assertIsNone(MODULE.selected())
            self.assertFalse(selection.exists())

    def test_malformed_selection_is_not_silently_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            selection = Path(directory) / "selected-lab"
            selection.write_text("not-a-lab\n", encoding="utf-8")
            with patch.object(MODULE, "SELECTION", selection):
                with self.assertRaises(ValueError):
                    MODULE.selected()
            self.assertTrue(selection.exists())

    def test_symlink_selection_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("lab-gone\n", encoding="utf-8")
            selection = root / "selected-lab"
            selection.symlink_to(target)
            with patch.object(MODULE, "SELECTION", selection):
                with self.assertRaises(ValueError):
                    MODULE.selected()
            self.assertTrue(selection.is_symlink())

    def test_current_requires_explicit_selection_instead_of_latest_fallback(self):
        with patch.object(MODULE, "selected", return_value=None), \
             patch.object(MODULE, "latest", return_value="/var/lib/opla/lab-LATEST1"):
            with self.assertRaisesRegex(ValueError, "не выбрана"):
                MODULE.current()

    def test_control_requires_explicit_lab_dir(self):
        source = (ROOT / "bin" / "control.sh").read_text(encoding="utf-8")
        self.assertIn("LAB_DIR=\"${LAB_DIR:-}\"", source)
        self.assertNotIn("state.py\" --latest", source)

    def test_support_scripts_do_not_select_latest_implicitly(self):
        for name in ("bin/versions.sh", "bin/observability-up.sh", "monitoring/manage.sh"):
            source = (ROOT / name).read_text(encoding="utf-8")
            self.assertNotIn("state.py --latest", source)
        self.assertIn("LAB_DIR обязателен", source)

    def test_activation_exposes_explicit_optional_monitoring_switch(self):
        activate = (ROOT / "bin/opla-lab-activate.sh").read_text()
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn('OPLA_ENABLE_MONITORING:=1', activate)
        self.assertIn('OPLA_ENABLE_MONITORING=0', activate)
        self.assertIn('OPLA_ENABLE_MONITORING="$(or $(OPLA_ENABLE_MONITORING),1)"', makefile)

    def test_live_cleanup_passes_exact_lab_to_monitoring_stop(self):
        source = (ROOT / "ci/live/lib/common.sh").read_text(encoding="utf-8")
        self.assertIn('LAB_DIR="/var/lib/opla/$lab_id" opla monitoring stop', source)

    def test_global_monitoring_down_requires_explicit_confirmation(self):
        source = (ROOT / "monitoring/manage.sh").read_text(encoding="utf-8")
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("I_UNDERSTAND_GLOBAL_MONITORING_DOWN", source)
        self.assertIn('CONFIRM_GLOBAL="$(CONFIRM_GLOBAL)"', makefile)
        self.assertIn("lab-stack-down:\n\t@test", makefile)
        self.assertNotIn("lab-stack-down: lab-stop", makefile)

