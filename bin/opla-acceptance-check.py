#!/usr/bin/env python3
"""Read-only fixture preflight. No SSH, QEMU, provisioning or host admission."""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify_builtin_topology(root=ROOT):
    """Check the built-in dual-NIC source contract without executing it."""
    root = Path(root)
    paths = {
        "create": root / "bin/create-lab.sh",
        "resume": root / "bin/vm-disk.py",
        "state": root / "bin/state.py",
        "registry": root / "bin/opla-registry.py",
        "lifecycle": root / "bin/lab-lifecycle.py",
    }
    try:
        source = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
    except (OSError, UnicodeError) as exc:
        return False, f"Topology source unavailable: {exc}"
    required = {
        "create": ("MGMT_BRIDGE", "MGMT_SUBNET", "id=n0", "id=n1",
                   "set-name: ens3", "set-name: ens4", "MGMT_GW"),
        "resume": ("MGMT_BRIDGE", "id=n0", "id=n1", "mgmt_tap"),
        "state": ("MGMT_BRIDGE", "MGMT_SUBNET", "MGMT_GW", "SSH_IP"),
        "registry": ("management_bridge", "management_tap", "require_management"),
        "lifecycle": ("MGMT_BRIDGE", "management=True", "dual-NIC laboratory state required"),
    }
    missing = [f"{name}:{marker}" for name, markers in required.items()
               for marker in markers if marker not in source[name]]
    if missing:
        return False, "Built-in dual-NIC contract missing: " + ", ".join(missing)
    # ens4 has no gateway/default-route stanza in generated network-config.
    if "management:\n    match:" not in source["create"] or "gateway4" in source["create"]:
        return False, "Management interface route separation contract missing"
    return True, "Built-in local-QEMU dual-NIC source contract validated"



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

    topology_ok, topology_detail = verify_builtin_topology()
    record(
        "builtin_topology_contract",
        "PASS" if topology_ok else "BLOCKED",
        topology_detail,
    )
    record(
        "management_data_separation",
        "PASS" if topology_ok else "BLOCKED",
        "Source contract only; runtime bridge/NIC separation is NOT TESTED",
    )

    # This checker validates source plus the historical Debian-12 Ansible
    # fixture.  It cannot observe the physical host that might later run the
    # local-QEMU lab.  Keeping that distinction in the structured output
    # prevents a green fixture setup from being mistaken for Gate C admission.
    record(
        "physical_host_admission",
        "NOT TESTED",
        "Outside this fixture preflight; import a fresh dedicated-host observation with opla system admission-import",
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
        "live_acceptance_authorization",
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
        "fixture_mode": "ansible-debian12",
        "builtin_mode": "local-qemu-dual-nic",
        "assessment_scope": "fixture_and_source_only",
        "physical_host_assessment": "NOT TESTED",
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
