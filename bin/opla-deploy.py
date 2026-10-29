#!/usr/bin/env python3
"""OPLA P13: read-only validation and planning of custom infrastructure."""

import argparse
import ipaddress
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit(
        "BLOCKED: PyYAML unavailable. "
        "Install project dependencies in an isolated environment."
    )


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects ambiguous duplicate mapping keys."""


def _construct_unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark,
                "unhashable mapping key", key_node.start_mark,
            ) from None
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark,
                f"duplicate key {key!r}", key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)

COMPONENTS = {
    "xdp",
    "suricata",
    "telemetry-agent",
    "collector",
    "clickhouse",
    "zabbix",
}

CONNECTIVITY = {"direct", "existing_vpn", "managed_vpn"}
ENGINES = {"amneziawg", "xray"}

NAME = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{0,62}\Z")
USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
IFACE = re.compile(r"[a-zA-Z0-9_.:-]{1,15}\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)



def validate_connectivity(connection, label):
    require(isinstance(connection, dict),
            f"{label}: connectivity must be a mapping")
    require(connection.get("type") in CONNECTIVITY,
            f"{label}: unsupported connectivity type")

    require(set(connection) <= {"type", "engine", "gateway"},
            f"{label}: unknown connectivity field")

    mode = connection["type"]
    if mode == "managed_vpn":
        require(connection.get("engine") in ENGINES,
                f"{label}: unsupported VPN engine")
        gateway = connection.get("gateway")
        require(isinstance(gateway, str)
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", gateway),
                f"{label}: invalid gateway")
    else:
        require("engine" not in connection and "gateway" not in connection,
                f"{label}: unexpected VPN fields")

    return connection


TOP_FIELDS = {"apiVersion", "kind", "metadata", "connectivity", "nodes"}
NODE_FIELDS = {
    "name", "address", "ssh_user", "ssh_port",
    "components", "interfaces", "connectivity",
    "ssh_identity", "ssh_known_hosts", "ssh_bastion",
}


def check_fields(value, allowed, label):
    require(isinstance(value, dict), f"{label}: mapping required")
    extra = set(value) - allowed
    require(not extra, f"{label}: unknown fields: {sorted(extra)}")


def validate_ssh_path(value, label):
    require(isinstance(value, str) and 0 < len(value) <= 4096,
            f"{label}: invalid path")
    require(not any(ord(char) < 32 or ord(char) == 127 for char in value),
            f"{label}: control character in path")
    require(value.startswith("/") or value.startswith("~/"),
            f"{label}: absolute or ~/ path required")
    require(".." not in Path(value).parts,
            f"{label}: parent traversal is forbidden")


def validate_ssh_spec(node, name):
    for field in ("ssh_identity", "ssh_known_hosts"):
        if field in node:
            validate_ssh_path(node[field], f"{name}: {field}")

    if "ssh_bastion" not in node:
        return

    bastion = node["ssh_bastion"]
    check_fields(
        bastion,
        {"address", "ssh_user", "ssh_port"},
        f"{name}: ssh_bastion",
    )

    require("address" in bastion and "ssh_user" in bastion,
            f"{name}: incomplete ssh_bastion")

    try:
        address = ipaddress.ip_address(bastion["address"])
    except (ValueError, TypeError):
        raise ValueError(
            f"{name}: invalid bastion IP"
        ) from None

    require(not address.is_multicast and not address.is_unspecified,
            f"{name}: unsuitable bastion IP")

    user = bastion["ssh_user"]
    require(isinstance(user, str) and USER.fullmatch(user),
            f"{name}: invalid bastion SSH user")

    port = bastion.get("ssh_port", 22)
    require(type(port) is int and 1 <= port <= 65535,
            f"{name}: invalid bastion SSH port")

def load_manifest(filename):
    path = Path(filename)
    require(path.is_file() and not path.is_symlink(),
            "manifest missing or symlink")
    require(path.stat().st_size <= 256 * 1024,
            "manifest exceeds 256 KiB")

    data = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    require(isinstance(data, dict), "manifest must be a mapping")
    check_fields(data, TOP_FIELDS, "infrastructure")
    require(data.get("apiVersion") == "opla/v1",
            "unsupported apiVersion")
    require(data.get("kind") == "Infrastructure",
            "kind must be Infrastructure")

    metadata = data.get("metadata")
    require(isinstance(metadata, dict), "metadata required")
    check_fields(metadata, {"name"}, "metadata")
    require(isinstance(metadata.get("name"), str)
            and NAME.fullmatch(metadata["name"]),
            "invalid infrastructure name")

    connection = validate_connectivity(
        data.get("connectivity", {"type": "direct"}),
        "global",
    )

    nodes = data.get("nodes")
    require(isinstance(nodes, list) and bool(nodes),
            "at least one node required")
    require(len(nodes) <= 256, "maximum 256 nodes per manifest")

    seen_names = set()
    seen_ips = set()

    for index, node in enumerate(nodes, 1):
        label = f"nodes[{index}]"
        require(isinstance(node, dict), f"{label}: mapping required")
        check_fields(node, NODE_FIELDS, label)

        name = node.get("name")
        require(isinstance(name, str) and NAME.fullmatch(name),
                f"{label}: invalid name")
        require(name not in seen_names, f"duplicate node: {name}")
        seen_names.add(name)

        try:
            address = ipaddress.ip_address(node.get("address"))
        except (ValueError, TypeError):
            raise ValueError(f"{name}: invalid IP address") from None

        require(not address.is_multicast
                and not address.is_unspecified,
                f"{name}: unsuitable management IP")
        require(address not in seen_ips,
                f"duplicate management IP: {address}")
        seen_ips.add(address)

        if "connectivity" in node:
            validate_connectivity(
                node["connectivity"],
                f"{name}",
            )

        validate_ssh_spec(node, name)

        ssh_user = node.get("ssh_user")
        require(isinstance(ssh_user, str) and USER.fullmatch(ssh_user),
                f"{name}: invalid SSH user")

        port = node.get("ssh_port", 22)
        require(type(port) is int and 1 <= port <= 65535,
                f"{name}: invalid SSH port")

        components = node.get("components")
        require(isinstance(components, list) and bool(components),
                f"{name}: components required")
        require(all(isinstance(c, str) and c in COMPONENTS
                    for c in components),
                f"{name}: unsupported component")
        require(len(components) == len(set(components)),
                f"{name}: duplicate component")

        interfaces = node.get("interfaces", {})
        require(isinstance(interfaces, dict),
                f"{name}: interfaces must be a mapping")

        for purpose, interface in interfaces.items():
            require(
                purpose in {"protection", "capture"}
                and isinstance(interface, str)
                and IFACE.fullmatch(interface),
                f"{name}: invalid interface definition",
            )

        if "xdp" in components:
            require("protection" in interfaces,
                    f"{name}: xdp requires protection interface")
        if "suricata" in components:
            require("capture" in interfaces,
                    f"{name}: suricata requires capture interface")

    return data


def show_plan(data):
    connection = data.get("connectivity", {"type": "direct"})
    mode = connection["type"]

    print(f"OPLA DEPLOYMENT PLAN: {data['metadata']['name']}")
    print(f"Connectivity: {mode}")
    print(f"Nodes: {len(data['nodes'])}")
    print()

    for node in data["nodes"]:
        print(f"NODE: {node['name']}")
        print(f"  Management IP: {node['address']}")
        print(f"  SSH: {node['ssh_user']}:{node.get('ssh_port', 22)}")
        print(f"  Components: {', '.join(node['components'])}")

        for purpose, interface in node.get("interfaces", {}).items():
            print(f"  Interface [{purpose}]: {interface}")

        print("  Status: NOT TESTED")
        print()

    if mode == "managed_vpn":
        print("VPN provisioning: NOT IMPLEMENTED")
        print("VPN engine:", connection["engine"])
        print("Gateway:", connection["gateway"])

    print("No infrastructure changes performed.")
    print("No SSH connections attempted.")
    print("Deployment execution: NOT IMPLEMENTED")



def show_connectivity_plan(data):
    default = data.get("connectivity", {"type": "direct"})

    print("OPLA CONNECTIVITY PLAN")
    print("Infrastructure:", data["metadata"]["name"])
    print("Nodes:", len(data["nodes"]))
    print()

    for node in data["nodes"]:
        connection = node.get("connectivity", default)
        mode = connection["type"]

        print("NODE:", node["name"])
        print("  Management IP:", node["address"])
        print("  SSH port:", node.get("ssh_port", 22))
        print("  Transport:", mode)

        if mode == "managed_vpn":
            print("  Engine:", connection["engine"])
            print("  Gateway:", connection["gateway"])
            print("  Tunnel: NOT PROVISIONED")
        elif mode == "existing_vpn":
            print("  Tunnel: MUST ALREADY EXIST")
        else:
            print("  Route: DIRECT, NOT VERIFIED")

        print("  Reachability: NOT TESTED")
        print()

    print("No SSH/VPN connections attempted.")
    print("No routes or firewall rules changed.")
    print("Connectivity execution: NOT IMPLEMENTED")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("validate", "plan", "connectivity-plan"))
    parser.add_argument("manifest")
    args = parser.parse_args()

    try:
        data = load_manifest(args.manifest)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2

    print("PASS: infrastructure manifest validated")

    if args.action == "plan":
        show_plan(data)
    elif args.action == "connectivity-plan":
        show_connectivity_plan(data)

    return 0


if __name__ == "__main__":
    sys.exit(main())
