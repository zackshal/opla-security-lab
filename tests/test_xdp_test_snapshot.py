import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "xdp_test_snapshot", ROOT / "xdp/validate-test-snapshot.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class XDPTestSnapshotTests(unittest.TestCase):
    def test_requires_loaded_program_before_traffic(self):
        with self.assertRaisesRegex(ValueError, "refusing to generate"):
            module.validate('{"loaded":0,"mode":"off"}')

    def test_rejects_missing_or_unusable_mode(self):
        for data in (
                '{"loaded":1}',
                '{"loaded":1,"mode":"off"}',
                '{"loaded":true,"mode":"native"}',
                '[]',
                'invalid'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                module.validate(data)

    def test_accepts_attached_native_or_generic_program(self):
        for mode in ("native", "generic"):
            with self.subTest(mode=mode):
                result = module.validate(
                    '{"loaded":1,"mode":"' + mode + '"}')
                self.assertEqual(result["mode"], mode)


if __name__ == "__main__":
    unittest.main()
