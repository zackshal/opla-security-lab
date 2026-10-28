"""Regression checks for create-lab.sh execution order."""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "bin" / "create-lab.sh"


class CreateExecutionOrderTests(unittest.TestCase):

    def test_fd_check_before_dependencies_and_creation(self):
        source = SOURCE.read_text()

        verifier = source.index(
            'python3 "$SCRIPT_DIR/opla-create-lock-check.py"'
        )
        dependencies = source.index(
            "for cmd in qemu-system-x86_64"
        )
        creation = source.index(
            'LAB_DIR="$(mktemp -d'
        )

        self.assertLess(verifier, dependencies)
        self.assertLess(verifier, creation)

    def test_error_handler_before_lab_creation(self):
        source = SOURCE.read_text()

        handler = source.index(
            """trap 'opla_creation_failed "$?"' ERR"""
        )
        creation = source.index(
            'LAB_DIR="$(mktemp -d'
        )

        self.assertLess(handler, creation)


if __name__ == "__main__":
    unittest.main()
