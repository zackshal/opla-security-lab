"""Safety contracts for OPLA Ansible provisioning."""

import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
ANSIBLE = ROOT / "ansible"


class AnsibleProvisioningTests(unittest.TestCase):

    def read_yaml(self, relative):
        return yaml.safe_load((ANSIBLE / relative).read_text())

    def test_preflight_has_no_privilege_escalation(self):
        play = self.read_yaml("playbooks/preflight.yml")[0]

        self.assertFalse(play["become"])

        for task in play["tasks"]:
            self.assertNotIn("ansible.builtin.apt", task)
            self.assertNotIn("ansible.builtin.service", task)
            self.assertNotIn("ansible.builtin.systemd", task)

    def test_provision_requires_approval(self):
        play = self.read_yaml("playbooks/provision.yml")[0]

        self.assertFalse(play["vars"]["opla_allow_provision"])
        self.assertFalse(play["become"])

        approval = play["pre_tasks"][0]
        self.assertIn("ansible.builtin.assert", approval)

    def test_package_role_is_opt_in(self):
        play = self.read_yaml("playbooks/provision.yml")[0]

        role_task = next(
            task for task in play["tasks"]
            if "ansible.builtin.include_role" in task
        )

        self.assertIn("opla_host_manage_packages", role_task["when"])
        self.assertIn("default(false)", role_task["when"])

    def test_platform_profile_is_loaded(self):
        play = self.read_yaml("playbooks/provision.yml")[0]

        profile_task = next(
            task for task in play["pre_tasks"]
            if task["name"] == "Load selected platform profile"
        )

        self.assertIn(
            "opla_selected_profile",
            profile_task["ansible.builtin.include_vars"]["file"],
        )

        profile = self.read_yaml("platforms/debian-amd64.yml")
        self.assertEqual(profile["opla_platform_id"], "debian-amd64")
        self.assertEqual(
            profile["opla_platform"]["package_manager"],
            "apt",
        )

    def test_docker_is_not_managed(self):
        defaults = self.read_yaml(
            "roles/opla_host/defaults/main.yml"
        )
        profile = self.read_yaml("platforms/debian-amd64.yml")
        packages = profile["opla_platform_packages"]

        self.assertIn("dnsmasq-base", packages)
        self.assertNotIn("dnsmasq", packages)
        self.assertFalse(defaults["opla_host_manage_packages"])

        self.assertFalse(
            any("docker" in package for package in packages)
        )

        tasks = self.read_yaml("roles/opla_host/tasks/main.yml")
        self.assertTrue(
            any("ansible.builtin.apt" in task for task in tasks)
        )
        self.assertFalse(
            any("ansible.builtin.service" in task for task in tasks)
        )


if __name__ == "__main__":
    unittest.main()
