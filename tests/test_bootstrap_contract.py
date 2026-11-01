import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class BootstrapContractTests(unittest.TestCase):
    def test_base_image_has_reviewed_digest_gate_before_publish(self):
        source = (ROOT / "bootstrap.sh").read_text()
        digest = re.search(r'BASE_SHA512:-([a-f0-9]{128})', source)
        self.assertIsNotNone(digest)
        self.assertIn('ACTUAL_SHA512', source)
        self.assertLess(source.index('ACTUAL_SHA512'), source.index('mv "$NAME.part"'))
        self.assertIn('source-sha512.txt', source)


if __name__ == "__main__":
    unittest.main()
