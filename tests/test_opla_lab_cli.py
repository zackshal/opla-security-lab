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

