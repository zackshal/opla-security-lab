#!/usr/bin/env python3
"""Read-only OPLA acceptance preflight. No SSH, QEMU or provisioning."""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]



def verify_inventory(path, home):
    """Validate the pinned acceptance target without connecting to it."""
    try:
        import yaml
    except ImportError:
        return False, "PyYAML unavailable"

    if not path.is_file() or path.is_symlink():
        return False, "Inventory missing or symlink"

    try:
        inventory = yaml.safe_load(path.read_text(encoding="utf-8"))
        hosts = inventory["all"]["children"]["opla_hosts"]["hosts"]
        if not isinstance(hosts, dict) or list(hosts) != ["opla-debian12"]:
            return False, "Unexpected inventory hosts"

        host = hosts["opla-debian12"]
        expected = {
            "ansible_host": "127.0.0.1",
            "ansible_port": 22229,
            "ansible_user": "opla",
            "ansible_connection": "ssh",
            "ansible_ssh_private_key_file": str(home / ".ssh/id_ed25519"),
        }
        for key, value in expected.items():
            if type(host.get(key)) is not type(value) or host[key] != value:
                return False, f"Unexpected {key}"
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError) as exc:
        return False, f"Invalid inventory: {exc}"

    return True, "Pinned Debian 12 inventory validated"

def check():
    home = Path.home()
    guest_dir = home / ".local/share/opla-acceptance/debian12-amd64"
    venv = Path(os.environ.get(
        "OPLA_ANSIBLE_VENV", "/tmp/opla-ansible.RDp8NwWE"
    ))

    checks = []

    def record(name, status, detail):
        checks.append({
            "name": name,
            "status": status,
            "detail": detail,
        })

    required = {
        "automation_script": ROOT / "bin/opla-automation.sh",
        "provision_playbook": ROOT / "ansible/playbooks/provision.yml",
        "preflight_playbook": ROOT / "ansible/playbooks/preflight.yml",
        "acceptance_playbook": ROOT / "ansible/playbooks/acceptance.yml",
        "scenario_live": ROOT / "bin/opla-scenario-live.py",
        "incident_report": ROOT / "bin/opla-incident-report.py",
        "evidence_bundle": ROOT / "bin/opla-experiment-bundle.py",
        "zabbix_publisher": ROOT / "monitoring/experiment-publish.py",
    }

    for name, path in required.items():
        record(
            name,
            "PASS" if path.is_file() else "BLOCKED",
            "present" if path.is_file() else f"missing: {path}",
        )

    inventory = guest_dir / "inventory.yml"
    inventory_ok, inventory_detail = verify_inventory(inventory, home)
    record(
        "guest_inventory",
        "PASS" if inventory_ok else "BLOCKED",
        inventory_detail,
    )

    known_hosts = guest_dir / "known_hosts"
    record(
        "guest_known_hosts",
        "PASS" if known_hosts.is_file() else "BLOCKED",
        str(known_hosts),
    )

    ansible = venv / "bin/ansible-playbook"
    record(
        "ansible_environment",
        "PASS" if ansible.is_file() else "BLOCKED",
        str(ansible),
    )

    # These require execution in an authorized acceptance environment.
    for name in (
        "guest_identity",
        "guest_provisioning",
        "guest_idempotency",
        "kernel_bpf_verifier",
        "xdp_live",
        "suricata_live",
        "zabbix_delivery",
        "three_vm_experiment",
    ):
        record(
            name,
            "NOT TESTED",
            "Requires separate authorized acceptance execution",
        )

    blocked = sum(x["status"] == "BLOCKED" for x in checks)

    return {
        "schema_version": 1,
        "kind": "opla_acceptance_preflight",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "read_only",
        "execution_performed": False,
        "preflight_configuration_valid": blocked == 0,
        "ready_for_automatic_execution": False,
        "overall_status": "BLOCKED" if blocked else "NOT TESTED",
        "checks": checks,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", required=True, action="store_true",
        help="Perform read-only checks only",
    )
    args = parser.parse_args(argv)

    result = check()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["overall_status"] == "NOT TESTED" else 2


if __name__ == "__main__":
    sys.exit(main())
