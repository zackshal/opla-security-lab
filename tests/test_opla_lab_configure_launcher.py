import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module():
    path = ROOT / "bin/opla-lab-configure-launcher.py"
    spec = importlib.util.spec_from_file_location(
        "opla_configure_launcher_test", path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ConfigureLauncherTests(unittest.TestCase):

    def test_valid_identity(self):
        module = load_module()
        self.assertEqual(
            module.validate_arguments(
                ["lab-ABCD1234", "lab-ABCD1234"]
            ),
            "lab-ABCD1234",
        )

    def test_rejects_mismatched_confirmation(self):
        module = load_module()
        with self.assertRaises(ValueError):
            module.validate_arguments(
                ["lab-ABCD1234", "lab-OTHER1234"]
            )

    def test_rejects_unsafe_identifier(self):
        module = load_module()
        for value in (
            "../lab-ABCD1234",
            "lab-ABCD1234/../../tmp",
            "lab-A_B_C",
            "lab-abc",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    module.validate_arguments([value, value])

    def test_privileged_source_requires_root_ownership(self):
        module = load_module()
        self.assertTrue(
            callable(module.verify_trusted_code)
        )

        source = (
            ROOT / "bin/opla-lab-configure-launcher.py"
        ).read_text()

        self.assertIn("verify_trusted_code()", source)
        self.assertIn("st.st_uid != 0", source)
        self.assertIn("st.st_mode & 0o022", source)
        self.assertIn("stat.S_ISREG", source)

    def test_existing_lifecycle_lock_usage(self):
        source = (
            ROOT / "bin/opla-lab-configure-launcher.py"
        ).read_text()

        self.assertIn('ROOT / ".opla-prune.lock"', source)
        self.assertIn('lab / "maintenance.lock"', source)
        self.assertIn("os.setuid(user.pw_uid)", source)
        self.assertIn("preexec_fn=drop_privileges", source)


if __name__ == "__main__":
    unittest.main()
