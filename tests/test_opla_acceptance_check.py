import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location(
    "opla_acceptance_check",
    ROOT / "bin/opla-acceptance-check.py",
)
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class AcceptanceCheckTests(unittest.TestCase):

    def test_builtin_dual_nic_contract_is_verified_offline(self):
        valid, detail = acceptance.verify_builtin_topology()
        self.assertTrue(valid, detail)

    def test_builtin_contract_tampering_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for relative in (
                "bin/create-lab.sh", "bin/vm-disk.py", "bin/state.py",
                "bin/opla-registry.py", "bin/lab-lifecycle.py",
            ):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("single-nic\n", encoding="utf-8")
            valid, detail = acceptance.verify_builtin_topology(root)
            self.assertFalse(valid)
            self.assertIn("missing", detail)

    def test_check_never_authorizes_execution(self):
        result = acceptance.check()
        self.assertFalse(result["execution_performed"])
        self.assertFalse(result["ready_for_automatic_execution"])
        self.assertEqual(result["mode"], "read_only")
        self.assertEqual(result["builtin_mode"], "local-qemu-dual-nic")
        self.assertIn(result["overall_status"], ("BLOCKED", "NOT TESTED"))

    def test_inventory_rejects_wrong_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            inventory = home / "inventory.yml"
            inventory.write_text("""
all:
  children:
    opla_hosts:
      hosts:
        opla-debian12:
          ansible_host: 192.168.1.1
          ansible_port: 22229
          ansible_user: opla
          ansible_connection: ssh
          ansible_ssh_private_key_file: /tmp/invalid
""", encoding="utf-8")

            valid, detail = acceptance.verify_inventory(inventory, home)
            self.assertFalse(valid)
            self.assertTrue(detail)

    def test_missing_inventory_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            valid, _ = acceptance.verify_inventory(
                home / "missing.yml", home
            )
            self.assertFalse(valid)

    def test_check_outputs_json_without_execution(self):
        with patch.object(acceptance, "check", return_value={
            "overall_status": "NOT TESTED",
            "execution_performed": False,
            "ready_for_automatic_execution": False,
        }), patch("builtins.print") as output:
            rc = acceptance.main(["--check"])

        self.assertEqual(rc, 0)
        result = json.loads(output.call_args.args[0])
        self.assertFalse(result["execution_performed"])

    def test_check_flag_is_mandatory(self):
        with self.assertRaises(SystemExit) as error:
            acceptance.main([])
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
