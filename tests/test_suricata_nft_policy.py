"""Offline ownership tests for the guest-local Suricata nft table."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SURICATA = ROOT / "security/suricata"
sys.path.insert(0, str(SURICATA))
import nft_policy


def table_output(comment=nft_policy.OWNER_COMMENT):
    table = {"family": "inet", "name": nft_policy.TABLE}
    if comment is not None:
        table["comment"] = comment
    return json.dumps({"nftables": [{"metainfo": {"json_schema_version": 1}},
                                    {"table": table}]})


def result(code=0, stdout="", stderr=""):
    from types import SimpleNamespace
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


def load_manager():
    spec = importlib.util.spec_from_file_location("suricata_manager_test", SURICATA / "manage.py")
    manager = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manager)
    return manager


class SuricataNftOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.lock_path = Path(self.temporary.name) / "opla.lock"

    def test_only_explicitly_marked_table_is_owned(self):
        self.assertEqual(nft_policy.table_status(
            lambda *args, **kwargs: result(stdout=table_output())), "OWNED")
        for comment in (None, "another-manager"):
            with self.subTest(comment=comment):
                self.assertEqual(nft_policy.table_status(
                    lambda *args, **kwargs: result(stdout=table_output(comment))), "FOREIGN")

    def test_absence_requires_specific_nft_diagnostic(self):
        self.assertEqual(nft_policy.table_status(
            lambda *args, **kwargs: result(1, stderr="No such file or directory")), "ABSENT")
        with self.assertRaisesRegex(RuntimeError, "cannot establish"):
            nft_policy.table_status(lambda *args, **kwargs: result(1, stderr="Operation not permitted"))

    def test_lock_rejects_symlinked_or_hardlinked_files(self):
        target = Path(self.temporary.name) / "target"
        target.write_text("lock")
        self.lock_path.symlink_to(target)
        with self.assertRaises(OSError):
            with nft_policy.exclusive_lock(self.lock_path):
                pass
        self.lock_path.unlink()
        self.lock_path.hardlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "unsafe"):
            with nft_policy.exclusive_lock(self.lock_path):
                pass

    def test_lock_rejects_group_or_world_access(self):
        self.lock_path.touch(mode=0o600)
        self.lock_path.chmod(0o640)
        with self.assertRaisesRegex(RuntimeError, "unsafe"):
            with nft_policy.exclusive_lock(self.lock_path):
                pass

    def test_malformed_or_ambiguous_inspection_blocks(self):
        for payload in ("not json", '{"nftables":[],"nftables":[]}'):
            with self.subTest(payload=payload), self.assertRaises(RuntimeError):
                nft_policy.table_status(lambda *args, **kwargs: result(stdout=payload))

    def test_foreign_table_is_never_deleted(self):
        calls = []
        def runner(*args, **kwargs):
            calls.append((args, kwargs))
            return result(stdout=table_output("foreign"))
        with self.assertRaisesRegex(RuntimeError, "unmarked"):
            nft_policy.delete_owned_table(runner, lock_path=self.lock_path)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0][0], ["nft", "-j", "list", "table", "inet", "opla_ips"])

    def test_marked_table_can_be_deleted(self):
        calls = []
        def runner(*args, **kwargs):
            calls.append((args, kwargs))
            return result(stdout=table_output())
        self.assertTrue(nft_policy.delete_owned_table(runner, lock_path=self.lock_path))
        self.assertEqual(calls[1][0][0], ["nft", "delete", "table", "inet", "opla_ips"])

    def test_absent_table_is_created_without_delete(self):
        calls = []
        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[:3] == ["nft", "-j", "list"]:
                return result(1, stderr="No such file or directory")
            return result()
        nft_policy.replace_table("table inet opla_ips {}", runner, lock_path=self.lock_path)
        self.assertEqual(calls[-1][0], ["nft", "-f", "-"])
        self.assertNotIn("delete table", calls[-1][1]["input"])

    def test_owned_table_replacement_is_single_delete_and_create_batch(self):
        calls = []
        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return result(stdout=table_output())
        nft_policy.replace_table("table inet opla_ips {}", runner, lock_path=self.lock_path)
        self.assertEqual(calls[-1][0], ["nft", "-f", "-"])
        self.assertEqual(calls[-1][1]["input"].count("delete table inet opla_ips"), 1)

    def test_replace_rechecks_ownership_before_applying(self):
        states = [table_output(), table_output("foreign")]
        calls = []
        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[:3] == ["nft", "-j", "list"]:
                return result(stdout=states.pop(0))
            return result()
        with self.assertRaisesRegex(RuntimeError, "changed to unmarked"):
            nft_policy.replace_table("table inet opla_ips {}", runner, lock_path=self.lock_path)
        self.assertTrue(any(argv[:3] == ["nft", "--check", "-f"] for argv, _ in calls))
        self.assertFalse(any(argv == ["nft", "-f", "-"] for argv, _ in calls))

    def test_runtime_ids_mode_uses_ownership_guard(self):
        spec = importlib.util.spec_from_file_location("suricata_runtime_test", SURICATA / "runtime.py")
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        with patch.object(runtime.sys, "argv", ["runtime.py", "ids", "ens3"]), \
                patch.object(runtime, "delete_owned_table", side_effect=RuntimeError("foreign")) as delete:
            with self.assertRaisesRegex(RuntimeError, "foreign"):
                runtime.main()
        delete.assert_called_once_with()

    def test_off_preserves_mode_receipt_when_service_stop_fails(self):
        manager = load_manager()
        root = Path(self.temporary.name) / "manager-root"
        root.mkdir()
        receipt = root / "mode.json"
        receipt.write_text('{"mode":"ips"}\n')
        with patch.object(manager, "ROOT", root), \
                patch.object(manager, "MANAGER_LOCK_PATH", self.lock_path), \
                patch.object(manager, "owned_unit_bytes", return_value=b"marked unit"), \
                patch.object(manager, "remove_queue") as remove, \
                patch.object(manager, "run", side_effect=RuntimeError("systemctl failed")), \
                patch.object(manager.subprocess, "run") as probe:
            with self.assertRaisesRegex(RuntimeError, "systemctl failed"):
                manager.turn_off()
        remove.assert_not_called()
        probe.assert_not_called()
        self.assertTrue(receipt.exists())

    def test_off_removes_receipt_only_after_confirmed_inactive_disabled(self):
        manager = load_manager()
        root = Path(self.temporary.name) / "manager-root"
        root.mkdir()
        receipt = root / "mode.json"
        receipt.write_text('{"mode":"ips"}\n')
        probes = [result(3, "inactive\n"), result(1, "disabled\n")]
        order = []
        with patch.object(manager, "ROOT", root), \
                patch.object(manager, "MANAGER_LOCK_PATH", self.lock_path), \
                patch.object(manager, "owned_unit_bytes", return_value=b"marked unit"), \
                patch.object(manager, "remove_queue", side_effect=lambda: order.append("remove")) as remove, \
                patch.object(manager, "run", side_effect=lambda *args: order.append("disable")) as run, \
                patch.object(manager.subprocess, "run",
                             side_effect=lambda *args, **kwargs: (order.append("verify"), probes.pop(0))[1]):
            manager.turn_off()
        remove.assert_called_once_with()
        run.assert_called_once_with("systemctl", "disable", "--now", "opla-suricata.service")
        self.assertEqual(order, ["disable", "verify", "verify", "remove"])
        self.assertFalse(receipt.exists())

    def test_off_does_not_remove_queue_while_service_may_still_be_active(self):
        manager = load_manager()
        root = Path(self.temporary.name) / "manager-root"
        root.mkdir()
        receipt = root / "mode.json"
        receipt.write_text('{"mode":"ips"}\n')
        with patch.object(manager, "ROOT", root), \
                patch.object(manager, "MANAGER_LOCK_PATH", self.lock_path), \
                patch.object(manager, "owned_unit_bytes", return_value=b"marked unit"), \
                patch.object(manager, "run"), \
                patch.object(manager.subprocess, "run", return_value=result(0, "active\n")), \
                patch.object(manager, "remove_queue") as remove:
            with self.assertRaisesRegex(RuntimeError, "inactive state"):
                manager.turn_off()
        remove.assert_not_called()
        self.assertTrue(receipt.exists())

    def test_apply_receipt_failure_restores_disabled_previous_unit(self):
        manager = load_manager()
        root = Path(self.temporary.name) / "manager-root"
        root.mkdir()
        (root / "log").mkdir()
        old_rules = {}
        for name in ("opla.rules", "ips.rules"):
            old_rules[name] = b"previous rules\n"
            (root / name).write_bytes(old_rules[name])
        old_mode = b'{"mode":"ids","previous":true}\n'
        (root / "mode.json").write_bytes(old_mode)
        old_config = b"previous config\n"
        old_unit = (manager.UNIT_MARKER + "\n[Unit]\nprevious unit\n").encode()
        (root / "suricata.yaml").write_bytes(old_config)
        (root / "unit").write_bytes(old_unit)

        calls = []
        def runner(*args, **kwargs):
            calls.append(args)

        original_write = manager.write_mode_receipt
        write_count = 0
        def fail_new_receipt(path, raw):
            nonlocal write_count
            write_count += 1
            if write_count == 1:
                raise OSError("receipt fsync failed")
            return original_write(path, raw)

        def prior_unit_state(argv, **kwargs):
            calls.append(tuple(argv))
            if argv[:2] == ["systemctl", "is-enabled"]:
                return result(1, "disabled\n")
            if argv[:3] == ["systemctl", "is-active", "--quiet"]:
                return result(3)
            return result(0)

        with patch.object(manager, "ROOT", root), \
                patch.object(manager, "LOG", root / "log"), \
                patch.object(manager, "UNIT", root / "unit"), \
                patch.object(manager, "validate_unit_parent_chain"), \
                patch.object(manager, "validate_unit_metadata"), \
                patch.object(manager, "config", return_value={}), \
                patch.object(manager, "run", side_effect=runner), \
                patch.object(manager.subprocess, "run", side_effect=prior_unit_state), \
                patch.object(manager.subprocess, "check_output", return_value=""), \
                patch.object(manager, "write_mode_receipt", side_effect=fail_new_receipt):
            with self.assertRaisesRegex(OSError, "receipt fsync failed"):
                manager._apply("ids", "100.64.0.0/29")
        self.assertEqual((root / "mode.json").read_bytes(), old_mode)
        self.assertEqual((root / "suricata.yaml").read_bytes(), old_config)
        self.assertEqual((root / "unit").read_bytes(), old_unit)
        self.assertIn(("systemctl", "enable", "opla-suricata.service"), calls)
        self.assertIn(("systemctl", "disable", "opla-suricata.service"), calls)
        self.assertIn(("systemctl", "stop", "opla-suricata.service"), calls)
        for name, content in old_rules.items():
            self.assertEqual((root / name).read_bytes(), content)

    def test_first_apply_receipt_failure_disables_and_removes_new_unit(self):
        manager = load_manager()
        root = Path(self.temporary.name) / "manager-root"
        root.mkdir()
        (root / "log").mkdir()
        unit = root / "unit"
        config = root / "suricata.yaml"

        def systemctl(argv, **kwargs):
            if argv[:2] == ["systemctl", "is-enabled"]:
                return result(4, "not-found\n")
            if argv[:3] == ["systemctl", "is-active", "--quiet"]:
                return result(3)
            return result(0)

        with patch.object(manager, "ROOT", root), \
                patch.object(manager, "LOG", root / "log"), \
                patch.object(manager, "UNIT", unit), \
                patch.object(manager, "validate_unit_parent_chain"), \
                patch.object(manager, "config", return_value={}), \
                patch.object(manager, "run"), \
                patch.object(manager, "remove_queue") as remove, \
                patch.object(manager.subprocess, "run", side_effect=systemctl), \
                patch.object(manager, "write_mode_receipt", side_effect=OSError("receipt fsync failed")):
            with self.assertRaisesRegex(OSError, "receipt fsync failed"):
                manager._apply("ids", "100.64.0.0/29")
        self.assertFalse((root / "mode.json").exists())
        self.assertFalse(config.exists())
        self.assertFalse(unit.exists())
        self.assertFalse((root / "runtime.py").exists())
        self.assertFalse((root / "nft_policy.py").exists())
        remove.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
