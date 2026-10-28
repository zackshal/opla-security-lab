"""Privileged OPLA integration tests in a disposable network namespace.

Never operates on /var/lib/opla or shared host services.
"""

import fcntl
import importlib.util
import json
import multiprocessing as mp
import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LAB = "lab-itest999"
BRIDGE = "br-op999"
TABLE = "opla_lab_itest999"


def load(name, filename):
    path = ROOT / "bin" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


preflight = load("opla_live_preflight", "opla-active-recovery-plan.py")
recovery = load("opla_live_recovery", "opla-active-creation-recover.py")


def run(*args, input=None):
    return subprocess.run(
        args,
        input=input,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )


def hold_lock(path, ready, release):
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        ready.set()
        if not release.wait(15):
            raise TimeoutError("lock holder timed out")
    finally:
        os.close(fd)


class ActiveRecoveryLiveTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise RuntimeError("Run with sudo")

        # Refuse to run network tests in the host's initial namespace.
        current = os.stat("/proc/self/ns/net").st_ino
        initial = os.stat("/proc/1/ns/net").st_ino
        if current == initial:
            raise RuntimeError(
                "Refusing to run outside an isolated network namespace"
            )

    def make_lab(self, root):
        labdir = root / LAB
        labdir.mkdir()
        (labdir / "state.env").write_text(
            f"LAB_ID={LAB}\n"
            f"BRIDGE={BRIDGE}\n"
            "SUBNET=10.255.255.0/29\n"
            "GW=10.255.255.1\n"
            "ATTACKER_IP=10.255.255.2\n"
            "VICTIM_IP=10.255.255.3\n"
            "CLIENT_IP=10.255.255.4\n"
        )
        return preflight.registry.persist(root, LAB, "creating")

    def make_network(self):
        run("ip", "link", "add", BRIDGE, "type", "bridge")
        run("ip", "addr", "add", "10.255.255.1/29", "dev", BRIDGE)
        run("ip", "link", "set", BRIDGE, "up")
        run("ip", "tuntap", "add", "dev", "op999a", "mode", "tap")
        run("ip", "link", "set", "op999a", "master", BRIDGE)
        run("ip", "link", "set", "op999a", "up")

        policy = f'''
table inet {TABLE} {{
    chain forward {{
        type filter hook forward priority -20; policy accept;
        iifname "{BRIDGE}" oifname != "{BRIDGE}" drop
        oifname "{BRIDGE}" iifname != "{BRIDGE}" drop
    }}
    chain input {{
        type filter hook input priority -20; policy accept;
        iifname "{BRIDGE}" ct state established,related accept
        iifname "{BRIDGE}" udp dport 67 accept
        iifname "{BRIDGE}" drop
    }}
}}
'''
        run("nft", "-f", "-", input=policy)

    def test_01_real_receipt_and_network_preflight(self):
        with tempfile.TemporaryDirectory(prefix="opla-live-") as td:
            root = Path(td)
            self.make_lab(root)
            self.make_network()

            report = preflight.audit(root, LAB)
            self.assertFalse(report["execution_allowed"])
            self.assertIn(
                "nft policy inspected", report["checks"]
            )

            run("ip", "link", "add", "foreign0", "type", "dummy")
            run("ip", "link", "set", "foreign0", "master", BRIDGE)
            run("ip", "link", "set", "foreign0", "up")

            with self.assertRaisesRegex(
                preflight.Blocked, "foreign bridge member"
            ):
                preflight.audit(root, LAB)

            run("ip", "link", "delete", "foreign0")

            run(
                "nft", "add", "rule", "inet", TABLE,
                "forward", "oifname", "foreign0", "accept"
            )

            with self.assertRaisesRegex(
                preflight.Blocked, "nft policy mismatch"
            ):
                preflight.audit(root, LAB)

            # Rejected audits must not have removed these resources.
            run("ip", "link", "show", BRIDGE)
            run("ip", "link", "show", "op999a")
            run("nft", "list", "table", "inet", TABLE)

    def test_02_tampered_receipt_rejected(self):
        with tempfile.TemporaryDirectory(prefix="opla-live-") as td:
            root = Path(td)
            receipt = self.make_lab(root)

            preflight.verify_receipt(root, LAB)

            data = json.loads(receipt.read_text())
            data["phase"] = "ready"
            receipt.write_text(json.dumps(data))

            with self.assertRaisesRegex(
                preflight.Blocked, "creation receipt differs"
            ):
                preflight.verify_receipt(root, LAB)

    def test_03_foreign_open_file_detected(self):
        with tempfile.TemporaryDirectory(prefix="opla-live-") as td:
            root = Path(td)
            labdir = root / LAB
            labdir.mkdir()
            disk = labdir / "disk.qcow2"
            disk.write_bytes(b"integration test\n")

            self.assertEqual(recovery.process_evidence(root, LAB), {})

            with disk.open("rb") as handle:
                process = subprocess.Popen(
                    ["sleep", "60"],
                    stdin=handle,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

            try:
                self.assertIsNone(process.poll())

                with self.assertRaisesRegex(
                    recovery.Blocked, str(process.pid)
                ):
                    recovery.process_evidence(root, LAB)

                self.assertIsNone(process.poll())
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()  # Only our test-created sleep.
                    process.wait(timeout=5)

            self.assertEqual(recovery.process_evidence(root, LAB), {})

    def test_04_concurrent_lifecycle_lock(self):
        with tempfile.TemporaryDirectory(prefix="opla-live-") as td:
            root = Path(td)
            path = root / ".opla-prune.lock"

            ready = mp.Event()
            release = mp.Event()
            holder = mp.Process(
                target=hold_lock,
                args=(str(path), ready, release),
            )

            calls = []

            def forbidden(*args, **kwargs):
                calls.append("UNEXPECTED")
                raise AssertionError("Recovery passed lock check")

            try:
                holder.start()
                self.assertTrue(ready.wait(5))
                self.assertTrue(holder.is_alive())

                with self.assertRaises(BlockingIOError):
                    recovery.locked_recover(
                        root,
                        LAB,
                        "RECOVER-CREATION:" + LAB,
                        audit=forbidden,
                        evidence=forbidden,
                        stop=forbidden,
                        offline=forbidden,
                    )

                self.assertEqual(calls, [])
                self.assertFalse((root / "operations").exists())
            finally:
                release.set()
                if holder.pid is not None:
                    holder.join(5)
                    if holder.is_alive():
                        holder.terminate()
                        holder.join(5)

            self.assertEqual(holder.exitcode, 0)

            fd = os.open(path, os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
