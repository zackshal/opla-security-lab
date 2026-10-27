import importlib.util
import io
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location(
    "opla_unified_cli_test", ROOT / "bin/opla-cli.py"
)
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


class UnifiedCLITests(unittest.TestCase):

    def parse(self, *argv):
        parser, _ = cli.build_parser()
        return parser.parse_args(argv)

    def test_help_for_every_group(self):
        for group in cli.GROUPS:
            with self.subTest(group=group):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(cli.main([group, "--help"]), 0)
                self.assertIn("usage: opla", output.getvalue())

    def test_scenario_simulate_mapping(self):
        command = cli.make_command(
            self.parse("scenario", "simulate", "syn-scan-baseline")
        )
        self.assertIn("scenario-simulate", command)
        self.assertIn("SCENARIO=syn-scan-baseline", command)

    def test_lab_selection_mapping(self):
        command = cli.make_command(
            self.parse("lab", "select", "lab-ABC123")
        )
        self.assertIn("lab-select", command)
        self.assertIn("LAB=lab-ABC123", command)

    def test_lab_create_requires_confirmation(self):
        with self.assertRaisesRegex(ValueError, "confirm-host-changes"):
            cli.make_command(self.parse("lab", "create"))

    def test_lab_delete_requires_matching_id(self):
        with self.assertRaises(ValueError):
            cli.make_command(
                self.parse(
                    "lab", "delete", "lab-ABC123",
                    "--confirm-lab", "lab-OTHER",
                )
            )

    def test_vm_rollback_requires_confirmation(self):
        with self.assertRaisesRegex(ValueError, "rollback"):
            cli.make_command(
                self.parse(
                    "vm", "load",
                    "--vm", "client", "--tag", "checkpoint",
                )
            )

    def test_reject_shell_metacharacters(self):
        with self.assertRaises(ValueError):
            cli.make_command(
                self.parse("report", "experiment", "reports/a;echo")
            )

    def test_no_execution_on_help(self):
        with patch.object(cli.subprocess, "run") as run:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["--help"]), 0)
                self.assertEqual(cli.main(["report", "--help"]), 0)
            run.assert_not_called()

    def test_execution_routes_to_make(self):
        with patch.object(cli.subprocess, "run") as run:
            run.return_value.returncode = 0
            self.assertEqual(cli.main(["system", "versions"]), 0)
            run.assert_called_once()
            self.assertIn("versions", run.call_args.args[0])

    def test_legacy_command_gives_hint(self):
        with redirect_stderr(io.StringIO()) as output:
            self.assertEqual(cli.main(["labs"]), 2)
        self.assertIn("opla lab list", output.getvalue())


    def test_lab_delete_passes_exact_confirmation(self):
        args = self.parse(
            "lab", "delete", "lab-ABC123",
            "--confirm-lab", "lab-ABC123",
        )
        command = cli.make_command(args)
        self.assertIn("lab-delete", command)
        self.assertIn("LAB=lab-ABC123", command)
        self.assertIn("CONFIRM_DELETE=lab-ABC123", command)

    def test_live_run_preserves_executor_confirmation(self):
        args = self.parse(
            "scenario", "run", "syn-scan-baseline",
            "--lab", "lab-ABC123",
            "--confirm", "lab-ABC123",
        )
        command = cli.make_command(args)
        self.assertIn("scenario-live-run", command)
        self.assertIn("LAB=lab-ABC123", command)
        self.assertIn("CONFIRM=lab-ABC123", command)

    def test_vm_rollback_sets_rollback_variable(self):
        args = self.parse(
            "vm", "load", "--vm", "client",
            "--tag", "checkpoint", "--rollback",
        )
        self.assertIn("ROLLBACK=yes", cli.make_command(args))

    def test_bootstrap_requires_host_confirmation(self):
        with self.assertRaisesRegex(ValueError, "confirm-host-changes"):
            cli.make_command(self.parse("system", "bootstrap"))

    def test_all_targets_exist_in_makefile(self):
        import subprocess

        result = subprocess.run(
            ["make", "--no-print-directory", "-np", "-f", "Makefile",
             "-o", "Makefile", "help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        import re
        targets = set(re.findall(
            r"^([a-zA-Z0-9_.-]+):(?:\\s|$)",
            result.stdout,
            re.MULTILINE,
        ))

        for group, actions in cli.COMMANDS.items():
            for action, (target, _, _) in actions.items():
                with self.subTest(group=group, action=action):
                    self.assertIn(target, targets)


if __name__ == "__main__":
    unittest.main()
