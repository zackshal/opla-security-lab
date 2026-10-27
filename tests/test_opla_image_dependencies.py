"""Offline validation of guest package-verification logic."""

import importlib.util
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class ImageDependencyTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manifest = self.root / "verified.txt"

        source = (ROOT / "bin/prepare-image.sh").read_text()

        match = re.search(
            r"verify_command=\$\(cat <<'GUEST_VERIFY'\n"
            r"(.*?)\nGUEST_VERIFY",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(match)

        self.script = match.group(1)
        self.assertIn("__PACKAGES__", self.script)

        # Redirect the manifest into an isolated temporary directory.
        self.script = self.script.replace(
            "/etc/opla-dependencies-verified",
            str(self.manifest),
        )
        self.script = self.script.replace(
            "__PACKAGES__", "clang llvm suricata"
        )


    def execute(self, missing=""):
        env = os.environ.copy()
        env["MISSING_PACKAGE"] = missing

        # POSIX-compatible function name. Substitute only the test copy
        # of the guest script; production sources stay unchanged.
        fake_function = """
fake_dpkg_query() {
    format=""
    pkg=""

    for arg in "$@"; do
        case "$arg" in
            -f=*) format="${arg#-f=}" ;;
            -W) ;;
            *) pkg="$arg" ;;
        esac
    done

    if [ "$pkg" = "${MISSING_PACKAGE:-}" ]; then
        return 1
    fi

    case "$format" in
        *Status*)
            printf 'install ok installed'
            ;;
        *Version*)
            printf '%s\\t1.0-test\\n' "$pkg"
            ;;
        *)
            return 2
            ;;
    esac
}
"""

        guest_script = self.script.replace(
            "dpkg-query", "fake_dpkg_query"
        )

        return subprocess.run(
            ["/bin/sh"],
            input=fake_function + "\n" + guest_script,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    def test_all_required_packages_generate_manifest(self):
        result = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)

        contents = self.manifest.read_text()
        for pkg in ("clang", "llvm", "suricata"):
            self.assertIn(pkg, contents)

    def test_missing_package_blocks_publication(self):
        result = self.execute(missing="suricata")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("suricata", result.stderr)
        self.assertFalse(self.manifest.exists())

    def test_image_size_contract(self):
        path = ROOT / "bin/opla-image-verify.py"
        spec = importlib.util.spec_from_file_location(
            "opla_image_contract", path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        allowed = module.ROLE_IMAGES["victim"][1]
        self.assertEqual(
            allowed, (3 * 1024**3, 10 * 1024**3)
        )

        self.assertEqual(
            module.ROLE_IMAGES["attacker"][1],
            4 * 1024**3,
        )
        self.assertEqual(
            module.ROLE_IMAGES["client"][1],
            4 * 1024**3,
        )


if __name__ == "__main__":
    unittest.main()
