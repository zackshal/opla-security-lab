"""P14 offline trusted-package staging tests. Never use sudo, SSH or QEMU."""
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("opla_bundle", ROOT / "bin/opla-release-bundle.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReleaseBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "source"
        for name in ("Makefile", "bin/opla-create-launcher.py",
                     "bin/opla-lab-configure-launcher.py", "bin/create-lab.sh",
                     "bin/opla-lifecycle-lock.py"):
            path = self.root / name
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_text("safe source\n")
        self.output = Path(self.tmp.name) / "bundle.tar.gz"

    def test_build_verify(self):
        self.assertEqual(module.build(self.root, self.output), 5)
        self.assertEqual(module.verify(self.output), 5)

    def test_reject_missing_critical_file(self):
        (self.root / "bin/create-lab.sh").unlink()
        with self.assertRaisesRegex(ValueError, "missing critical"):
            module.build(self.root, self.output)

    def test_reject_symlink(self):
        (self.root / "bin/create-lab.sh").unlink()
        (self.root / "bin/create-lab.sh").symlink_to("opla-create-launcher.py")
        with self.assertRaisesRegex(ValueError, "symlink"):
            module.build(self.root, self.output)

    def test_reject_output_overwrite(self):
        module.build(self.root, self.output)
        with self.assertRaisesRegex(ValueError, "already exists"):
            module.build(self.root, self.output)

    def test_reject_tampered_manifest(self):
        module.build(self.root, self.output)
        changed = self.output.with_name("changed.tar.gz")
        with tarfile.open(self.output, "r:gz") as src, tarfile.open(changed, "w:gz") as dst:
            for member in src:
                data = src.extractfile(member).read()
                if member.name == "source/Makefile":
                    data = b"modified\n"
                info = tarfile.TarInfo(member.name)
                info.size = len(data)
                dst.addfile(info, io.BytesIO(data))
        with self.assertRaisesRegex(ValueError, "mismatch"):
            module.verify(changed)

    def test_reject_path_traversal(self):
        with tarfile.open(self.output, "w:gz") as tar:
            data = b"wrong"
            info = tarfile.TarInfo("source/../../unsafe")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        with self.assertRaisesRegex(ValueError, "unsafe member path"):
            module.verify(self.output)

    def test_rejects_noncanonical_member_paths(self):
        for name in ("source/bin/./tool", "source/bin//tool"):
            with self.subTest(name=name):
                with tarfile.open(self.output, "w:gz") as tar:
                    info = tarfile.TarInfo(name)
                    info.size = 1
                    tar.addfile(info, io.BytesIO(b"x"))
                with self.assertRaisesRegex(ValueError, "unsafe member path"):
                    module.verify(self.output)

    def test_rejects_file_count_overflow_before_manifest_validation(self):
        with tarfile.open(self.output, "w:gz") as tar:
            manifest = tarfile.TarInfo("MANIFEST.json")
            manifest_data = b"{}"
            manifest.size = len(manifest_data)
            tar.addfile(manifest, io.BytesIO(manifest_data))
            for index in range(module.MAX_FILES + 1):
                info = tarfile.TarInfo(f"source/extra-{index}")
                info.size = 1
                tar.addfile(info, io.BytesIO(b"x"))
        with self.assertRaisesRegex(ValueError, "bundle exceeds limits"):
            module.verify(self.output)


if __name__ == "__main__":
    unittest.main()
