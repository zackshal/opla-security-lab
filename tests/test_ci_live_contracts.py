"""Offline contract checks for the live-acceptance shell boundary."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
CLI_SPEC = importlib.util.spec_from_file_location("opla_cli_live_contract", ROOT / "bin/opla-cli.py")
cli = importlib.util.module_from_spec(CLI_SPEC)
CLI_SPEC.loader.exec_module(cli)


class LiveAcceptanceContracts(unittest.TestCase):
    def read(self, relative):
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_live_calls_use_actual_cli_syntax(self):
        lifecycle = self.read("ci/live/lib/lifecycle.sh")
        cleanup = self.read("ci/live/lib/common.sh")
        stale = self.read("ci/live/cleanup-stale-labs.sh")

        self.assertNotIn("lab ready --lab", lifecycle)
        self.assertNotIn("lab stop  --lab", lifecycle)
        self.assertNotIn("lab start --lab", lifecycle)
        self.assertNotIn("lab stop --lab", cleanup)
        self.assertNotIn("lab delete --lab", cleanup + stale)
        self.assertIn("--confirm-lab", cleanup + stale)

    def test_stale_cleanup_requires_one_exact_lab_id(self):
        stale = self.read("ci/live/cleanup-stale-labs.sh")
        self.assertIn('[[ "$#" -eq 1 && "$id" =~ ^lab-[A-Za-z0-9]{8}$ ]]', stale)
        self.assertNotIn("opla lab list", stale)
        self.assertNotIn("OPLA_LAB_PREFIX", stale)

    def test_invalid_old_invocations_are_rejected_without_dispatch(self):
        with patch.object(cli.subprocess, "run") as run:
            self.assertEqual(cli.main(["lab", "ready", "--lab", "lab-ABC12345"]), 2)
            self.assertEqual(cli.main(["lab", "delete", "--lab", "lab-ABC12345", "--confirm", "lab-ABC12345"]), 2)
            run.assert_not_called()

    def test_failed_create_has_no_last_lab_fallback(self):
        lifecycle = self.read("ci/live/lib/lifecycle.sh")
        self.assertIn("lab creation failed; refusing to select or clean up an inferred lab", lifecycle)
        self.assertIn("did not return a verified LAB_ID", lifecycle)
        self.assertNotIn("opla lab list", lifecycle)

    def test_preflight_encoder_produces_valid_json_for_shell_specials(self):
        # Exercise the same encoder contract without running host probes.
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "preflight.json"
            values = ["quote", 'value with "quotes" and \\slashes']
            script = (
                "import json,sys; from pathlib import Path; "
                "Path(sys.argv[1]).write_text(json.dumps(dict(zip(sys.argv[2::2], sys.argv[3::2])))+'\\n')"
            )
            result = subprocess.run(
                ["python3", "-c", script, str(output), "key", values[1]],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(output.read_text())["key"], values[1])
        self.assertNotIn("printf '  %q", self.read("ci/live/lib/preflight.sh"))

    def test_missing_evidence_is_not_passed_through(self):
        verifier = self.read("ci/live/verify-evidence.py")
        evidence = self.read("ci/live/lib/evidence.sh")
        self.assertIn('status:"INCOMPLETE"', evidence)
        self.assertIn("mandatory evidence is incomplete", verifier)
        self.assertIn('"student@$ADDR"', evidence)
        self.assertIn('SSH_KEY:-$HOME/.ssh/id_ed25519', evidence)
        self.assertNotIn('"root@$ADDR"', evidence)

    def test_live_verifier_failures_are_not_masked(self):
        runner = self.read("ci/live/run-live-acceptance.sh")
        evidence = self.read("ci/live/lib/evidence.sh")
        self.assertIn('python3 "$HERE/verify-evidence.py" --check "$OUTPUT_DIR"', runner)
        self.assertNotIn('verify-evidence.py" --check "$OUTPUT_DIR" || true', runner)
        self.assertIn('verify-evidence.py" --fill-hashes "$OUTPUT_DIR"', evidence)
        self.assertNotIn('verify-evidence.py" --fill-hashes "$OUTPUT_DIR" || true', evidence)

    def test_activation_failure_is_not_masked_or_omitted(self):
        lifecycle = self.read("ci/live/lib/lifecycle.sh")
        verifier = self.read("ci/live/verify-evidence.py")
        self.assertRegex(lifecycle, r'(?m)^  step lab_activate opla lab activate')
        self.assertNotRegex(lifecycle, r'(?m)^  step lab_activate[^\n]*\|\| log')
        self.assertIn('"lab_activate"', verifier)

    def test_preflight_checks_the_compose_plugin(self):
        preflight = self.read("ci/live/lib/preflight.sh")
        verifier = self.read("ci/live/verify-evidence.py")
        self.assertIn("docker compose version", preflight)
        self.assertIn('"docker_compose"', verifier)

    def test_portable_ci_jobs_install_jq_for_live_contracts(self):
        github = self.read(".github/workflows/check.yml")
        gitlab = self.read(".gitlab-ci.yml")
        self.assertRegex(github, r"python3-yaml qemu-utils jq")
        self.assertRegex(gitlab, r"python3-yaml qemu-utils jq")

    def test_dry_run_never_enters_host_or_lifecycle_probes(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "live-output"
            result = subprocess.run(
                ["bash", "ci/live/run-live-acceptance.sh"], cwd=ROOT,
                env={**__import__("os").environ,
                     "OPLA_DRY_RUN": "1", "OUTPUT_DIR": str(output)},
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            manifest = json.loads((output / "manifest.json").read_text())
            verification = json.loads((output / "verification.json").read_text())
            self.assertEqual(manifest["preflight"]["status"], "SKIPPED")
            self.assertEqual(verification["overall_status"], "BLOCKED")
            self.assertIn("OPLA_DRY_RUN=1", " ".join(verification["blockers"]))
            self.assertNotIn("PREFLIGHT FAILED", result.stdout)

    def test_verifier_rejects_artifact_path_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            root.mkdir()
            outside = Path(directory) / "outside.txt"
            outside.write_text("secret", encoding="utf-8")
            manifest = {
                "lab": {"id": "lab-ABCDEFGH"}, "steps": [], "git_dirty": False,
                "evidence": {"status": "INCOMPLETE"},
                "artifacts": [{"path": "../outside.txt", "sha256": "0" * 64}],
            }
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            result = subprocess.run(
                ["python3", "ci/live/verify-evidence.py", "--check", str(root)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("unsafe artifact", result.stdout)

    def test_verifier_rejects_hardlink_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            root.mkdir()
            outside = Path(directory) / "outside.txt"
            outside.write_text("sensitive", encoding="utf-8")
            linked = root / "linked.txt"
            linked.hardlink_to(outside)
            (root / "manifest.json").write_text(json.dumps({
                "lab": {"id": "lab-ABCDEFGH"}, "steps": [], "git_dirty": False,
                "evidence": {"status": "INCOMPLETE"},
                "artifacts": [{"path": "linked.txt", "size": linked.stat().st_size,
                               "sha256": "0" * 64}],
            }), encoding="utf-8")
            result = subprocess.run(
                ["python3", "ci/live/verify-evidence.py", "--check", str(root)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("unsafe artifact: linked.txt", result.stdout)

    def test_verifier_requires_hash_record_for_every_mandatory_evidence_file(self):
        required = (
            "preflight.json", "evidence-status.json", "bpftool-prog-before.json",
            "bpftool-map-before.json", "nft-ruleset-before.txt", "ip-addr-before.txt",
            "ip-route-before.txt", "ip-link-before.txt", "bpftool-prog-after.json",
            "bpftool-map-after.json", "nft-ruleset-after.txt", "ip-addr-after.txt",
            "ip-route-after.txt", "ip-link-after.txt", "vm-victim-dpkg.txt",
            "vm-attacker-dpkg.txt", "vm-client-dpkg.txt",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            evidence = root / "evidence"
            evidence.mkdir(parents=True)
            (evidence / "evidence-status.json").write_text('{"status":"PASS"}', encoding="utf-8")
            for name in required:
                target = evidence / name
                if not target.exists():
                    target.write_text("evidence", encoding="utf-8")
            (evidence / "client-probes.json").write_text(
                '{"samples":[{"t":1},{"t":2}]}', encoding="utf-8")
            steps = [{"name": name, "status": "PASS", "duration_s": 0, "exit_code": 0}
                     for name in ("bootstrap", "images", "lab_create", "lab_ready",
                                  "xdp_stats_before", "xdp_stats_after", "ids_status_before",
                                  "ids_status_after", "scenario_check", "scenario_run")]
            (root / "manifest.json").write_text(json.dumps({
                "lab": {"id": "lab-ABCDEFGH"}, "steps": steps, "git_dirty": False,
                "preflight": {}, "evidence": {"status": "PASS"}, "artifacts": [],
            }), encoding="utf-8")
            result = subprocess.run(
                ["python3", "ci/live/verify-evidence.py", "--check", str(root)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("missing artifact hash", result.stdout)

    def test_verifier_rejects_manifest_status_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            evidence = root / "evidence"
            evidence.mkdir(parents=True)
            (evidence / "evidence-status.json").write_text(
                '{"status":"INCOMPLETE","missing":["vm-client-dpkg"]}',
                encoding="utf-8")
            (root / "manifest.json").write_text(json.dumps({
                "lab": {"id": "lab-ABCDEFGH"}, "steps": [], "git_dirty": False,
                "evidence": {"status": "PASS"}, "artifacts": [],
            }), encoding="utf-8")
            result = subprocess.run(
                ["python3", "ci/live/verify-evidence.py", "--check", str(root)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("evidence-status.json status is not PASS", result.stdout)

    def test_verifier_rejects_non_list_client_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            evidence = root / "evidence"
            evidence.mkdir(parents=True)
            (evidence / "evidence-status.json").write_text(
                '{"status":"PASS","missing":[]}', encoding="utf-8")
            (evidence / "client-probes.json").write_text(
                '{"samples":"not-two-probes"}', encoding="utf-8")
            (root / "manifest.json").write_text(json.dumps({
                "lab": {"id": "lab-ABCDEFGH"}, "steps": [], "git_dirty": False,
                "evidence": {"status": "PASS"}, "artifacts": [],
            }), encoding="utf-8")
            result = subprocess.run(
                ["python3", "ci/live/verify-evidence.py", "--check", str(root)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("samples is not a list", result.stdout)

    def test_verifier_reports_malformed_manifest_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            root.mkdir()
            (root / "manifest.json").write_text(json.dumps({
                "lab": {"id": "lab-ABCDEFGH"}, "git_dirty": False,
                "steps": [{"status": "PASS"}], "evidence": {"status": "PASS"},
                "preflight": {}, "artifacts": [],
            }), encoding="utf-8")
            result = subprocess.run(
                ["python3", "ci/live/verify-evidence.py", "--check", str(root)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("malformed step record", result.stdout)
            self.assertNotIn("Traceback", result.stderr)

    def test_verifier_rejects_incomplete_required_step_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            root.mkdir()
            (root / "manifest.json").write_text(json.dumps({
                "lab": {"id": "lab-ABCDEFGH"}, "git_dirty": False,
                "steps": [{"name": "bootstrap"}], "evidence": {"status": "PASS"},
                "preflight": {}, "artifacts": [],
            }), encoding="utf-8")
            result = subprocess.run(
                ["python3", "ci/live/verify-evidence.py", "--check", str(root)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("malformed step record", result.stdout)
            self.assertNotIn("Traceback", result.stderr)

    def test_verifier_rejects_invalid_manifest_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            root.mkdir()
            (root / "manifest.json").write_text(json.dumps({
                "schema_version": 1, "platform": "local", "commit": "bad",
                "lab": {"id": "lab-wrong", "scenario": "syn-scan-baseline"},
                "git_dirty": False, "steps": [], "evidence": {"status": "PASS"},
                "preflight": {}, "artifacts": [],
            }), encoding="utf-8")
            result = subprocess.run(
                ["python3", "ci/live/verify-evidence.py", "--check", str(root)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("commit is not a 40-character lowercase SHA-1", result.stdout)
            self.assertIn("lab.id is invalid", result.stdout)

    def test_verifier_rejects_symlinked_output_root(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = parent / "real-output"
            target.mkdir()
            (target / "manifest.json").write_text("{}", encoding="utf-8")
            root = parent / "output"
            root.symlink_to(target, target_is_directory=True)
            result = subprocess.run(
                ["python3", "ci/live/verify-evidence.py", "--check", str(root)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("unsafe output root", result.stdout)

    def test_verifier_rejects_invalid_preflight_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            evidence = root / "evidence"
            evidence.mkdir(parents=True)
            (evidence / "preflight.json").write_text("not-json", encoding="utf-8")
            (root / "manifest.json").write_text(json.dumps({
                "schema_version": 1, "platform": "local", "commit": "a" * 40,
                "lab": {"id": "lab-ABCDEFGH", "scenario": "offline"},
                "git_dirty": False, "steps": [], "evidence": {"status": "PASS"},
                "preflight": {}, "artifacts": [],
            }), encoding="utf-8")
            result = subprocess.run(
                ["python3", "ci/live/verify-evidence.py", "--check", str(root)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("unreadable preflight.json", result.stdout)

    def test_verifier_rejects_invalid_bpftool_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            evidence = root / "evidence"
            evidence.mkdir(parents=True)
            (evidence / "bpftool-prog-before.json").write_text(
                "not-json", encoding="utf-8")
            (root / "manifest.json").write_text(json.dumps({
                "schema_version": 1, "platform": "local", "commit": "a" * 40,
                "lab": {"id": "lab-ABCDEFGH", "scenario": "offline"},
                "git_dirty": False, "steps": [], "evidence": {"status": "PASS"},
                "preflight": {}, "artifacts": [],
            }), encoding="utf-8")
            result = subprocess.run(
                ["python3", "ci/live/verify-evidence.py", "--check", str(root)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("unreadable JSON evidence evidence/bpftool-prog-before.json", result.stdout)

    def test_verifier_rejects_failed_preflight_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            evidence = root / "evidence"
            evidence.mkdir(parents=True)
            (evidence / "preflight.json").write_text(json.dumps({
                "platform": "Linux", "arch": "x86_64", "kernel": "test",
                "os_id": "debian", "os_version": "13", "kvm": "missing_or_no_access",
                "ram_available_mb": "8192", "disk_available_gib": "100",
                "sudo_nopasswd": "ok", "outbound_debian": "ok", "docker_compose": "ok",
                **{"tool_" + tool: "ok" for tool in (
                    "qemu-system-x86_64", "qemu-img", "virt-customize", "virt-resize",
                    "cloud-localds", "dnsmasq", "ip", "nft", "flock", "systemd-run",
                    "systemctl", "python3", "make", "git", "jq", "clang", "bpftool",
                    "curl", "ssh", "scp", "docker")},
            }), encoding="utf-8")
            (root / "manifest.json").write_text(json.dumps({
                "schema_version": 1, "platform": "local", "commit": "a" * 40,
                "lab": {"id": "lab-ABCDEFGH", "scenario": "offline"},
                "git_dirty": False, "steps": [], "evidence": {"status": "PASS"},
                "preflight": {}, "artifacts": [],
            }), encoding="utf-8")
            result = subprocess.run(
                ["python3", "ci/live/verify-evidence.py", "--check", str(root)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("preflight gate failed: kvm", result.stdout)

    def test_live_runner_rejects_symlinked_output_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = parent / "real-output"
            target.mkdir()
            root = parent / "output"
            root.symlink_to(target, target_is_directory=True)
            result = subprocess.run(
                ["bash", "ci/live/run-live-acceptance.sh"], cwd=ROOT,
                env={**__import__("os").environ,
                     "OPLA_DRY_RUN": "1", "OUTPUT_DIR": str(root)},
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("OUTPUT_DIR must be a real directory", result.stderr)
            self.assertEqual(list(target.iterdir()), [])

    def test_evidence_uses_actual_lab_state_path(self):
        common = self.read("ci/live/lib/common.sh")
        evidence = self.read("ci/live/lib/evidence.sh")
        self.assertIn('/var/lib/opla/$lab_id/state.env', common)
        self.assertIn('LAB_DIR="/var/lib/opla/$LAB_ID"', evidence)
        self.assertNotIn('/var/lib/opla/labs/', common + evidence)

    def test_cleanup_failure_blocks_delete_and_is_reported(self):
        common = self.read("ci/live/lib/common.sh")
        self.assertIn("refusing delete", common)
        self.assertIn("cleanup incomplete", common)
        self.assertNotIn("|| true", common[common.index("cleanup_lab()"):common.index("trap ")])

    def test_cleanup_runtime_refuses_delete_after_stop_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_opla = fake_bin / "opla"
            fake_opla.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >> \"$OPLA_CALL_LOG\"\n"
                "if [ \"$1 $2\" = 'lab stop' ]; then exit 7; fi\n"
                "exit 0\n"
            )
            fake_opla.chmod(0o755)
            calls = root / "calls.log"
            output = root / "output"
            script = (
                "set -e; "
                f"source {ROOT / 'ci/live/lib/common.sh'}; "
                "set +e; cleanup_lab lab-ABCDEFGH; rc=$?; set -e; "
                "printf 'rc=%s\\n' \"$rc\""
            )
            result = subprocess.run(
                ["bash", "-c", script],
                cwd=ROOT,
                env={**__import__("os").environ,
                     "PATH": f"{fake_bin}:{__import__('os').environ['PATH']}",
                     "OUTPUT_DIR": str(output),
                     "OPLA_CALL_LOG": str(calls),
                     "OPLA_KEEP_LAB": "0",
                     "OPLA_DRY_RUN": "0"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("rc=1", result.stdout)
            call_lines = calls.read_text().splitlines()
            self.assertIn("monitoring stop", call_lines)
            self.assertIn("lab stop", call_lines)
            self.assertNotIn("lab delete", call_lines)

    def test_cleanup_runtime_refuses_delete_after_monitoring_stop_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_opla = fake_bin / "opla"
            fake_opla.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >> \"$OPLA_CALL_LOG\"\n"
                "if [ \"$1 $2\" = 'monitoring stop' ]; then exit 9; fi\n"
                "exit 0\n"
            )
            fake_opla.chmod(0o755)
            calls = root / "calls.log"
            output = root / "output"
            script = (
                "set -e; "
                f"source {ROOT / 'ci/live/lib/common.sh'}; "
                "set +e; cleanup_lab lab-ABCDEFGH; rc=$?; set -e; "
                "printf 'rc=%s\\n' \"$rc\""
            )
            result = subprocess.run(
                ["bash", "-c", script],
                cwd=ROOT,
                env={**__import__("os").environ,
                     "PATH": f"{fake_bin}:{__import__('os').environ['PATH']}",
                     "OUTPUT_DIR": str(output),
                     "OPLA_CALL_LOG": str(calls),
                     "OPLA_KEEP_LAB": "0",
                     "OPLA_DRY_RUN": "0"},
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("rc=1", result.stdout)
            call_lines = calls.read_text().splitlines()
            self.assertIn("monitoring stop", call_lines)
            self.assertIn("lab stop", call_lines)
            self.assertNotIn("lab delete", call_lines)

    def test_mandatory_capture_failure_is_not_reported_as_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            target = output / "evidence.txt"
            script = (
                "source " + str(ROOT / "ci/live/lib/common.sh") + "; "
                "set +e; capture \"" + str(target) + "\" sh -c 'exit 7'; rc=$?; "
                "printf 'rc=%s\\n' \"$rc\""
            )
            result = subprocess.run(
                ["bash", "-c", script], cwd=ROOT,
                env={**__import__("os").environ, "OUTPUT_DIR": str(output)},
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("rc=7", result.stdout)
            self.assertIn("capture failed", result.stdout)
            self.assertEqual(target.read_text(), "")


if __name__ == "__main__":
    unittest.main()
