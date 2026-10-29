import importlib.util
import io
from contextlib import redirect_stdout
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("opla_help", ROOT / "bin/opla-help.py")
help_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(help_module)


class HelpTests(unittest.TestCase):
    def test_brief_help_exposes_read_only_host_admission_without_claiming_create(self):
        output = io.StringIO()
        with redirect_stdout(output):
            help_module.brief()
        text = output.getvalue()
        self.assertIn("host-admission-export OUTPUT=file", text)
        self.assertIn("host-admission-import REPORT=file", text)
        self.assertIn("не создаёт VM", text)


if __name__ == "__main__":
    unittest.main()
