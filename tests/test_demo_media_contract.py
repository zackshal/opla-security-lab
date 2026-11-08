"""Keep the public demonstration media visually and semantically consistent."""
import hashlib
import json
import unittest
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
SVG_FILES = (
    ROOT / "assets/demo/banner.svg",
    ROOT / "assets/demo/overview.svg",
    ROOT / "assets/demo/results.svg",
    ROOT / "assets/demo/services/terminal.svg",
    ROOT / "docs/figures/topology.svg",
    ROOT / "docs/figures/packet-path.svg",
)
PALETTE = ("#090a10", "#11131d", "#4ad9d0", "#f3f2ff", "#a7a5bc")


class DemoMediaContractTests(unittest.TestCase):
    def test_svg_media_has_accessible_metadata_and_shared_palette(self):
        for path in SVG_FILES:
            text = path.read_text(encoding="utf-8")
            root = ElementTree.fromstring(text)
            self.assertEqual(root.tag.rsplit("}", 1)[-1], "svg", path)
            self.assertIn("role=\"img\"", text, path)
            self.assertIn("aria-labelledby=\"title desc\"", text, path)
            self.assertIn("<title", text, path)
            self.assertIn("<desc", text, path)
            for color in PALETTE:
                self.assertIn(color, text.lower(), f"{color} missing from {path}")

    def test_public_readme_uses_dependency_free_svg_cards(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("assets/demo/overview.svg", readme)
        self.assertIn("assets/demo/results.svg", readme)
        self.assertNotIn("assets/demo/overview.gif)", readme)
        self.assertNotIn("assets/demo/results.png)", readme)

    def test_manifest_binds_current_svg_hashes(self):
        manifest = json.loads((ROOT / "assets/demo/media-manifest.json").read_text())
        for name in ("banner.svg", "overview.svg", "results.svg"):
            digest = hashlib.sha256((ROOT / "assets/demo" / name).read_bytes()).hexdigest()
            self.assertEqual(manifest["artifacts"][name], digest, name)


if __name__ == "__main__":
    unittest.main()
