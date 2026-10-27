import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "opla_fingerprint_test",
    ROOT / "xdp/fingerprint.py",
)
fp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fp)


class FingerprintTests(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)

        self.root = Path(tmp.name)
        self.source = self.root / "xdp_ddos_protect.c"
        self.obj = self.root / "xdp_ddos_protect.o"
        self.manifest = self.root / "build-manifest.json"

        self.source.write_bytes(b"source")
        self.obj.write_bytes(b"compiled-object")

        for name, value in (
            ("SOURCE", self.source),
            ("OBJECT", self.obj),
            ("MANIFEST", self.manifest),
        ):
            p = patch.object(fp, name, value)
            p.start()
            self.addCleanup(p.stop)

    def test_sha256(self):
        expected = hashlib.sha256(b"compiled-object").hexdigest()
        self.assertEqual(fp.sha256(self.obj), expected)

    def test_manifest_written(self):
        data = {
            "schema_version": 1,
            "threshold": 100,
            "window_ns": 1000000000,
            "max_sources": 4096,
        }

        fp.write_manifest(data)
        self.assertEqual(json.loads(self.manifest.read_text()), data)
        self.assertEqual(self.manifest.stat().st_mode & 0o777, 0o600)

    def test_build_captures_compilation_parameters(self):
        args = SimpleNamespace(
            threshold=300,
            window_ns=1000000000,
            max_sources=4096,
        )

        with patch.object(
            fp.subprocess,
            "check_output",
            return_value="clang version test\n",
        ):
            fp.build(args)

        data = json.loads(self.manifest.read_text())
        self.assertEqual(data["threshold"], 300)
        self.assertEqual(data["window_ns"], 1000000000)
        self.assertEqual(data["max_sources"], 4096)
        self.assertEqual(data["object_sha256"], fp.sha256(self.obj))
        self.assertEqual(data["source_sha256"], fp.sha256(self.source))

    def test_missing_object_blocks_build_manifest(self):
        self.obj.unlink()

        with self.assertRaises(ValueError):
            fp.build(SimpleNamespace(
                threshold=100,
                window_ns=1000000000,
                max_sources=4096,
            ))

        self.assertFalse(self.manifest.exists())


    def test_verified_build_accepts_matching_object(self):
        data = {
            "schema_version": 1,
            "object_sha256": fp.sha256(self.obj),
        }
        fp.write_manifest(data)

        self.assertEqual(fp.verified_build(), data)

    def test_verified_build_rejects_modified_object(self):
        fp.write_manifest({
            "schema_version": 1,
            "object_sha256": fp.sha256(self.obj),
        })
        self.obj.write_bytes(b"modified-object")

        with self.assertRaisesRegex(ValueError, "differs"):
            fp.verified_build()

    def test_receipt_uses_separate_destination(self):
        receipt = self.root / "load-receipt.json"
        build_data = {"schema_version": 1, "threshold": 100}
        load_data = {"schema_version": 1, "program_id": 42}

        fp.write_manifest(build_data)
        fp.write_manifest(load_data, receipt)

        self.assertEqual(json.loads(self.manifest.read_text()), build_data)
        self.assertEqual(json.loads(receipt.read_text()), load_data)
        self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
