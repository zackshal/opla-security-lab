import importlib.util
import io
import math
import signal
import subprocess
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

    def test_group_help_alias_never_dispatches_a_command(self):
        with patch.object(cli.subprocess, "run") as run:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cli.main(["lab", "help"]), 0)
            self.assertIn("usage: opla lab", output.getvalue())
            run.assert_not_called()

    def test_scenario_simulate_mapping(self):
        command = cli.make_command(
            self.parse("scenario", "simulate", "syn-scan-baseline")
        )
        self.assertIn("scenario-simulate", command)
        self.assertIn("SCENARIO=syn-scan-baseline", command)

    def test_scenario_help_identifies_argument_as_id(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(cli.main(["scenario", "validate", "--help"]), 0)
        self.assertIn("SCENARIO_ID", output.getvalue())

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

    def test_global_monitoring_down_requires_exact_confirmation(self):
        with self.assertRaisesRegex(ValueError, "confirm-global"):
            cli.make_command(self.parse("monitoring", "down", "--confirm-global", "wrong"))
        command = cli.make_command(self.parse(
            "monitoring", "down",
            "--confirm-global", "I_UNDERSTAND_GLOBAL_MONITORING_DOWN"))
        self.assertIn("monitoring-down", command)
        self.assertIn("CONFIRM_GLOBAL=I_UNDERSTAND_GLOBAL_MONITORING_DOWN", command)

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
            self.assertEqual(cli.main(["system", "versions"], runner=run), 0)
            run.assert_called_once()
            self.assertIn("versions", run.call_args.args[0])
            self.assertEqual(run.call_args.kwargs["timeout"], cli.DEFAULT_CLI_TIMEOUT)

    def test_make_nonzero_exit_is_preserved(self):
        runner = lambda *args, **kwargs: subprocess.CompletedProcess(args, 7)
        self.assertEqual(cli.main(["system", "versions"], runner=runner), 7)

    def test_cli_timeout_is_validated_before_runner(self):
        for timeout in (True, 0, -1, math.nan, math.inf, "10"):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    cli.validate_cli_timeout(timeout)

    def test_owned_cli_group_terminates_and_reaps(self):
        class Process:
            pid = 7788
            def __init__(self):
                self.waits = 0
            def wait(self, timeout=None):
                self.waits += 1
                if self.waits < 3:
                    raise subprocess.TimeoutExpired("make", timeout)
                return 137

        signals = []
        with self.assertRaises(subprocess.TimeoutExpired):
            cli._run_owned(["make", "check"], timeout=1,
                           popen_factory=lambda *a, **k: Process(),
                           killpg=lambda pid, sig: signals.append((pid, sig)))
        self.assertEqual(signals, [(7788, signal.SIGTERM), (7788, signal.SIGKILL)])

    def test_legacy_command_gives_hint(self):
        with redirect_stderr(io.StringIO()) as output:
            self.assertEqual(cli.main(["labs"]), 2)
        self.assertIn("opla lab list", output.getvalue())


    def test_lab_delete_maps_matching_id_to_executor_confirmation(self):
        args = self.parse(
            "lab", "delete", "lab-ABC123",
            "--confirm-lab", "lab-ABC123",
        )
        command = cli.make_command(args)
        self.assertIn("lab-delete", command)
        self.assertIn("LAB=lab-ABC123", command)
        self.assertIn("CONFIRM_DELETE=DELETE-LAB:lab-ABC123", command)

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

    def test_live_scenario_actions_preserve_controlling_tty(self):
        for action, extra in (
            ("check", []),
            ("run", ["--confirm", "lab-ABC123"]),
        ):
            with self.subTest(action=action), patch.object(cli.subprocess, "run") as run:
                run.return_value.returncode = 0
                self.assertEqual(cli.main([
                    "scenario", action, "syn-scan-baseline",
                    "--lab", "lab-ABC123", *extra,
                ]), 0)
                run.assert_called_once()
                self.assertNotIn("start_new_session", run.call_args.kwargs)
                self.assertNotIn("capture_output", run.call_args.kwargs)

    def test_vm_rollback_sets_rollback_variable(self):
        args = self.parse(
            "vm", "load", "--vm", "client",
            "--tag", "checkpoint", "--rollback",
        )
        self.assertIn("ROLLBACK=yes", cli.make_command(args))

    def test_bootstrap_requires_host_confirmation(self):
        with self.assertRaisesRegex(ValueError, "confirm-host-changes"):
            cli.make_command(self.parse("system", "bootstrap"))

    def test_host_admission_export_and_import_map_to_non_privileged_targets(self):
        export = cli.make_command(self.parse(
            "system", "admission-export", "--output", "reports/host.json",
            "--storage-root", "/srv/opla-data",
        ))
        imported = cli.make_command(self.parse(
            "system", "admission-import", "--report", "reports/host.json",
            "--expected-host-id", "a" * 32,
            "--expected-collector-sha256", "b" * 64,
            "--output", "reports/decision.json",
        ))
        self.assertIn("host-admission-export", export)
        self.assertIn("OUTPUT=reports/host.json", export)
        self.assertIn("STORAGE_ROOT=/srv/opla-data", export)
        self.assertIn("host-admission-import", imported)
        self.assertIn("EXPECTED_HOST_ID=" + "a" * 32, imported)
        self.assertIn("EXPECTED_COLLECTOR_SHA256=" + "b" * 64, imported)
        self.assertIn("DECISION=reports/decision.json", imported)
        self.assertNotIn("sudo", export)
        self.assertNotIn("sudo", imported)

    def test_host_admission_import_rejects_invalid_expected_identity_before_make(self):
        with self.assertRaisesRegex(ValueError, "expected-host-id"):
            cli.make_command(self.parse(
                "system", "admission-import", "--report", "reports/host.json",
                "--expected-host-id", "A" * 32,
                "--expected-collector-sha256", "b" * 64,
            ))

    def test_host_admission_import_requires_well_formed_collector_pin(self):
        with self.assertRaisesRegex(ValueError, "expected-collector-sha256"):
            cli.make_command(self.parse(
                "system", "admission-import", "--report", "reports/host.json",
                "--expected-host-id", "a" * 32,
                "--expected-collector-sha256", "short",
            ))

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
