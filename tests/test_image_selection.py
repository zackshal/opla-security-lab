"""Image role selection safety contracts."""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CREATE = ROOT / "bin/create-lab.sh"


class ImageSelectionTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.source = CREATE.read_text()

    def test_all_role_images_required(self):
        early = self.source.split(
            'LAB_DIR="$(mktemp -d /var/lib/opla/lab-XXXXXXXX)"'
        )[0]

        self.assertIn('python3 "$SCRIPT_DIR/opla-image-verify.py" || exit 2', early)
        self.assertNotIn("qemu-img create", early)

    def test_no_victim_fallback(self):
        self.assertNotIn(
            '[[ -f "$image" ]] || image=',
            self.source,
        )

    def test_explicit_role_mapping(self):
        self.assertIn("victim|attacker|client)", self.source)
        self.assertIn('opla-image-verify.py" --select "$name"', self.source)
        self.assertIn("unsupported VM role", self.source)


if __name__ == "__main__":
    unittest.main()
