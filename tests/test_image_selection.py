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

        for name in (
            "debian-12-xdp.qcow2",
            "debian-12-attacker.qcow2",
            "debian-12-client.qcow2",
        ):
            self.assertIn(name, early)

        self.assertIn("missing required image", early)

    def test_no_victim_fallback(self):
        self.assertNotIn(
            '[[ -f "$image" ]] || image=',
            self.source,
        )

    def test_explicit_role_mapping(self):
        for role, image in (
            ("victim", "debian-12-xdp.qcow2"),
            ("attacker", "debian-12-attacker.qcow2"),
            ("client", "debian-12-client.qcow2"),
        ):
            self.assertIn(
                f'{role})',
                self.source,
            )
            self.assertIn(image, self.source)

        self.assertIn("unsupported VM role", self.source)


if __name__ == "__main__":
    unittest.main()
