import importlib.util
from pathlib import Path
import tempfile
import unittest
import stat
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("xdp_runtime_guard", ROOT / "xdp/runtime-guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class XDPRuntimeGuardTests(unittest.TestCase):
    def receipt(self):
        return {"schema_version": 2, "program_id": 20, "program_tag": "abc123",
                "program_map_ids": [1, 2, 3], "attachment_mode": "generic",
                "maps": {name: {"id": index, "type": "hash"}
                         for index, name in enumerate(sorted(guard.EXPECTED_MAP_PINS), 1)}}

    def test_only_explicit_off_is_loadable(self):
        observed = [{"ifname": "ens3", "xdp": {"attached": "off"}}]
        self.assertEqual(guard.parse_link(observed), {"mode": "off", "program_id": None})
        for xdp in ({}, {"prog_id": 10}, {"attached": "new-mode"}, None, "off"):
            with self.subTest(xdp=xdp), self.assertRaises(ValueError):
                guard.parse_link([{"ifname": "ens3", "xdp": xdp}])

    def test_iproute2_omitted_xdp_object_means_no_attachment(self):
        # iproute2 omits the xdp key when `bpftool net show dev ens3` has an
        # empty xdp section. Keep exact interface identity mandatory.
        observed = [{"ifname": "ens3", "flags": ["UP"], "mtu": 1500}]
        self.assertEqual(guard.parse_link(observed), {"mode": "off", "program_id": None})
        with self.assertRaisesRegex(ValueError, "unexpected interface identity"):
            guard.parse_link([{"ifname": "ens4", "flags": ["UP"]}])

    def test_load_blocks_existing_program_even_when_id_field_missing(self):
        with self.assertRaisesRegex(ValueError, "identity is missing"):
            guard.parse_link([{"ifname": "ens3", "xdp": {"attached": "drv"}}])

    def test_link_identity_and_attached_state_must_be_unambiguous(self):
        cases = [
            [{"ifname": "ens4", "xdp": {"attached": "off"}}],
            [{"ifname": "ens3", "xdp": {"attached": "off", "prog_id": 17}}],
            [{"ifname": "ens3", "xdp": {"attached": "drv", "prog_id": 17,
                                              "prog": {"id": 18}}}],
        ]
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                guard.parse_link(payload)

    def test_unload_refuses_attachment_without_pin_identity(self):
        link = {"mode": "generic", "program_id": 20}
        with self.assertRaisesRegex(ValueError, "no OPLA pin identity"):
            guard.classify_unload(link)

    def test_unload_requires_receipt_bound_to_pinned_program(self):
        link = {"mode": "generic", "program_id": 20}
        pinned = {"id": 20, "tag": "abc123", "map_ids": [1, 2, 3]}
        with self.assertRaisesRegex(ValueError, "receipt is missing"):
            guard.classify_unload(link, pinned, None)
        receipt = {"schema_version": 2, "program_id": 21,
                   "program_tag": "abc123", "attachment_mode": "generic"}
        with self.assertRaisesRegex(ValueError, "does not identify"):
            guard.classify_unload(link, pinned, receipt)

    def test_owned_attachment_is_classified_only_on_exact_identity(self):
        link = {"mode": "generic", "program_id": 20}
        pinned = {"id": 20, "tag": "abc123", "map_ids": [1, 2, 3]}
        receipt = self.receipt()
        self.assertEqual(guard.classify_unload(link, pinned, receipt), "attached-owned")
        with self.assertRaisesRegex(ValueError, "foreign or has changed"):
            guard.classify_unload({"mode": "generic", "program_id": 22}, pinned, receipt)

    def test_receipt_maps_must_be_referenced_by_pinned_program(self):
        receipt = self.receipt()
        receipt["program_map_ids"] = [1, 2, 99]
        with self.assertRaisesRegex(ValueError, "map IDs"):
            guard.classify_unload({"mode": "generic", "program_id": 20},
                                  {"id": 20, "tag": "abc123", "map_ids": [1, 2, 3]}, receipt)

    def test_legacy_receipt_requires_live_map_identity_for_unload(self):
        legacy = self.receipt()
        legacy["schema_version"] = 1
        legacy.pop("program_map_ids")
        legacy.pop("maps")
        pinned = {"id": 20, "tag": "abc123", "map_ids": [1, 2, 3]}
        link = {"mode": "generic", "program_id": 20}
        self.assertEqual(guard.classify_unload(link, pinned, legacy), "attached-owned")
        malformed_ids = dict(legacy, program_map_ids=[True, 2, 3])
        with self.assertRaisesRegex(ValueError, "legacy load receipt map IDs"):
            guard.classify_unload(link, pinned, malformed_ids)
        malformed_maps = dict(legacy, maps={**self.receipt()["maps"],
                                             "syn_windows": {"id": True, "type": "hash"}})
        with self.assertRaisesRegex(ValueError, "legacy receipt map identity"):
            guard.classify_unload(link, pinned, malformed_maps)
        observed = {name: {"id": index, "type": "hash"}
                    for index, name in enumerate(sorted(guard.EXPECTED_MAP_PINS), 1)}
        guard.validate_map_pin_identity(None, observed, pinned["map_ids"])
        observed["xdp_policy"]["id"] = 99
        with self.assertRaisesRegex(ValueError, "program map IDs"):
            guard.validate_map_pin_identity(None, observed, pinned["map_ids"])

    def test_unknown_pin_inventory_is_preserved(self):
        guard.validate_map_pin_names(guard.EXPECTED_MAP_PINS)
        with self.assertRaisesRegex(ValueError, "preserve resources"):
            guard.validate_map_pin_names({*guard.EXPECTED_MAP_PINS, "foreign_map"})

    def test_same_map_pin_names_with_foreign_object_ids_are_rejected(self):
        receipt = {name: {"id": index, "type": "hash"}
                   for index, name in enumerate(sorted(guard.EXPECTED_MAP_PINS), 1)}
        observed = {name: dict(value) for name, value in receipt.items()}
        observed["xdp_policy"]["id"] += 100
        with self.assertRaisesRegex(ValueError, "identity differs"):
            guard.validate_map_pin_identity(receipt, observed, [1, 2, 3])

    def test_program_map_identity_must_match_every_receipt_map(self):
        receipt = self.receipt()["maps"]
        observed = {name: dict(value) for name, value in receipt.items()}
        with self.assertRaisesRegex(ValueError, "program map IDs"):
            guard.validate_map_pin_identity(receipt, observed, [1, 2, 8])

    def test_partial_pin_tree_is_not_reported_as_already_unloaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "opla"
            root.mkdir()
            with patch.object(guard, "PIN_ROOT", root), \
                 patch.object(guard, "PROGRAM_PIN", root / "program"), \
                 patch.object(guard, "inspect_link", return_value={"mode": "off", "program_id": None}):
                with self.assertRaisesRegex(ValueError, "partial OPLA pin tree"):
                    guard.inspect_unload()

    def test_receipt_reader_rejects_duplicate_keys_without_following_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt_path = Path(tmp) / "receipt.json"
            receipt_path.write_text('{"schema_version":2,"schema_version":1}')
            fake_info = type("Stat", (), {"st_mode": stat.S_IFREG | 0o600,
                                           "st_nlink": 1, "st_uid": 0,
                                           "st_size": receipt_path.stat().st_size})()
            with patch.object(guard, "RECEIPT", receipt_path), \
                 patch.object(guard.os, "fstat", return_value=fake_info), \
                 self.assertRaisesRegex(ValueError, "duplicate"):
                guard.read_receipt()

            link = Path(tmp) / "receipt-link.json"
            link.symlink_to(receipt_path)
            with patch.object(guard, "RECEIPT", link), \
                 self.assertRaises(OSError):
                guard.read_receipt()

    def test_load_and_unload_share_cooperative_lock_before_mutations(self):
        load = (ROOT / "xdp/load.sh").read_text()
        unload = (ROOT / "xdp/unload.sh").read_text()
        for source, mutation in ((load, "bpftool prog load"), (unload, "ip link set dev ens3 xdp off")):
            with self.subTest(mutation=mutation):
                self.assertIn("/run/lock/opla-xdp.lock", source)
                self.assertIn("flock -n 9", source)
                self.assertIn("-f \"$lock_path\" && ! -L \"$lock_path\"", source)
                self.assertIn("stat -c '%u %h %a' \"$lock_path\"", source)
                self.assertNotIn("%F", source)
                self.assertLess(source.index("flock -n 9"), source.index(mutation))


if __name__ == "__main__":
    unittest.main()
