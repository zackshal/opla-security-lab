import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class MakeCheckContractTests(unittest.TestCase):
    def test_main_check_runs_documentation_gate(self):
        source = (ROOT / "Makefile").read_text(encoding="utf-8")
        check_body = source.split("check:\n", 1)[1].split(
            "\n.PHONY:", 1
        )[0]
        self.assertIn("python3 tests/check.py", check_body)
        self.assertIn("python3 tools/check-documentation.py", check_body)


if __name__ == "__main__":
    unittest.main()
