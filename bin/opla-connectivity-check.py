#!/usr/bin/env python3
"""OPLA connectivity preflight and explicitly authorized SSH check."""

import argparse
import importlib.util
import ipaddress
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "opla_deploy_connectivity", HERE / "opla-deploy.py"
)
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)

USER_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")


def safe_file(value, label, private=False):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{label}: invalid path")
    path = Path(value).expanduser()
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{label}: absolute path required")
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise ValueError(f"{label}: not a regular file")
    if st.st_uid not in (os.getuid(), 0):
        raise ValueError(f"{label}: unexpected file owner")
    if st.st_mode & 0o022:
        raise ValueError(f"{label}: writable by group or others")
    if private and st.st_mode & 0o077:
        raise ValueError(f"{label}: private key permissions too broad")
    return str(path)


def host_token(ip, port):
    if port == 22:
        return ip
    return f"[{ip}]:{port}"


def known_host(known_hosts, ip, port):
    result = subprocess.run(
        ["ssh-keygen", "-F", host_token(ip, port), "-f", known_hosts],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


def validate_bastion(bastion):
    if not isinstance(bastion, dict):
        raise ValueError("bastion must be a mapping")
    if set(bastion) != {"address", "ssh_user"} and (
        set(bastion) != {"address", "ssh_user", "ssh_port"}
    ):
        raise ValueError("bastion: unexpected or missing fields")

    address = str(ipaddress.ip_address(bastion["address"]))
    user = bastion["ssh_user"]
    port = bastion.get("ssh_port", 22)
    if not isinstance(user, str) or not USER_RE.fullmatch(user):
        raise ValueError("bastion: invalid SSH user")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("bastion: invalid SSH port")
    return address, user, port


def check_node(node, default, connect=False):
    name = node["name"]
    connection = node.get("connectivity", default)
    mode = connection["type"]

    if mode == "managed_vpn":
        return "NOT TESTED", "managed VPN is not provisioned"

    allowed = {
        "name", "address", "ssh_user", "ssh_port",
        "components", "interfaces", "connectivity",
        "ssh_known_hosts", "ssh_identity", "ssh_bastion",
    }
    extra = set(node) - allowed
    if extra:
        return "BLOCKED", f"unknown node fields: {sorted(extra)}"

    try:
        known_hosts = safe_file(
            node.get("ssh_known_hosts", "~/.ssh/known_hosts"),
            f"{name}: known_hosts",
        )
        identity = node.get("ssh_identity")
        if identity is not None:
            identity = safe_file(identity, f"{name}: SSH identity", True)

        address = str(ipaddress.ip_address(node["address"]))
        port = node.get("ssh_port", 22)
        if not known_host(known_hosts, address, port):
            return "BLOCKED", "target host key not pinned in known_hosts"

        bastion = node.get("ssh_bastion")
        if bastion is not None and connect:
            return (
                "BLOCKED",
                "bastion SSH execution requires verified jump-host policy",
            )
        jump = None
        if bastion is not None:
            jump_ip, jump_user, jump_port = validate_bastion(bastion)
            if not known_host(known_hosts, jump_ip, jump_port):
                return "BLOCKED", "bastion host key not pinned"
            if ":" in jump_ip:
                jump_ip = f"[{jump_ip}]"
            jump = f"{jump_user}@{jump_ip}:{jump_port}"

        if not connect:
            return "NOT TESTED", "host keys pinned; SSH not attempted"

        command = [
            "ssh", "-F", "/dev/null",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "UpdateHostKeys=no",
            "-o", "ConnectTimeout=5",
            "-o", "ConnectionAttempts=1",
            "-o", "ControlMaster=no",
            "-o", "ClearAllForwardings=yes",
            "-o", "PreferredAuthentications=publickey",
            "-T",
            "-p", str(port),
        ]

        if identity is not None:
            command += ["-o", "IdentitiesOnly=yes", "-i", identity]
        if jump is not None:
            command += ["-J", jump]

        command += ["--", f"{node['ssh_user']}@{address}", "true"]

        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

        if result.returncode:
            return "BLOCKED", f"SSH failed (exit {result.returncode})"
        return "PASS", "SSH authentication and remote true succeeded"

    except (
        OSError, ValueError, KeyError, TypeError,
        subprocess.TimeoutExpired,
    ) as exc:
        return "BLOCKED", str(exc)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest")
    parser.add_argument("--connect", action="store_true")
    args = parser.parse_args(argv)

    try:
        data = deploy.load_manifest(args.manifest)
    except (OSError, ValueError, deploy.yaml.YAMLError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2

    default = data.get("connectivity", {"type": "direct"})
    blocked = False
    for node in data["nodes"]:
        status, explanation = check_node(node, default, args.connect)
        print(f"{node['name']}: {status} — {explanation}")
        if status == "BLOCKED":
            blocked = True

    print(
        "Mode: explicit SSH check" if args.connect
        else "Mode: offline preflight (no network connections)"
    )
    return 2 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
