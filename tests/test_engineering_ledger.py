"""Offline engineering-ledger invariants; no Git writes or network."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("opla_engineering_harness", ROOT / "bin/opla-engineering-ledger.py")
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.root = self.directory / "source"
        self.root.mkdir()
        (self.root / "source.txt").write_text("baseline\n")
        self.state = {"version": 1, "tasks": {}}
        def local_git(root, *args):
            if args[0] == "rev-parse":
                return b"1111111111111111111111111111111111111111\n"
            return b"\0".join(path.relative_to(root).as_posix().encode()
                               for path in sorted(Path(root).rglob("*")) if path.is_file()) + b"\0"
        self.git_patch = patch.object(harness, "git", side_effect=local_git)
        self.git_patch.start()
        self.addCleanup(self.git_patch.stop)
        harness.claim(self.state, "task-a", "implementer-session", ["source.txt"], root=self.root)
        self.task = self.state["tasks"]["task-a"]

    def record(self, returncode=0, output=b"Ran 3 tests\nOK\n"):
        return harness.record_check(self.task, "compile", self.directory, root=self.root,
            runner=lambda argv, **kwargs: subprocess.CompletedProcess(argv, returncode, output, b""))

    def test_dirty_untracked_content_changes_baseline(self):
        before = harness.baseline(self.root)
        (self.root / "new.txt").write_text("uncommitted")
        self.assertNotEqual(before["tree_sha256"], harness.baseline(self.root)["tree_sha256"])

    def test_conflicting_path_and_dependency_claims_are_rejected(self):
        for paths, deps in ((["source.txt"], []), (["elsewhere"], ["missing"])):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                harness.claim(self.state, "task-b", "other", paths, dependencies=deps, root=self.root)

    def test_independent_review_and_execution_required(self):
        with self.assertRaises(ValueError):
            harness.complete(self.task, self.directory, root=self.root)
        self.record()
        with self.assertRaises(ValueError):
            harness.review(self.task, "implementer-session", root=self.root)
        harness.review(self.task, "independent-session", root=self.root)
        harness.complete(self.task, self.directory, root=self.root)
        self.assertEqual(self.task["status"], "complete")
        self.assertIsNone(self.task["usage"]["tokens"])

    def test_actual_safe_subprocess_check_is_captured(self):
        tests = self.root / "tests"
        tests.mkdir()
        (tests / "test_sample.py").write_text("import unittest\nclass Sample(unittest.TestCase):\n def test_value(self): self.assertEqual(2 + 2, 4)\n")
        with patch.dict(harness.CHECKS, {"sample": [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]}):
            result = harness.record_check(self.task, "sample", self.directory, root=self.root)
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(result["tests"], 1)
        self.assertEqual(result["status"], "executed")

    def test_claimed_pass_with_failed_execution_is_rejected(self):
        self.record(returncode=1, output=b"claimed PASS; actual failed\n")
        harness.review(self.task, "reviewer", root=self.root)
        with self.assertRaises(ValueError):
            harness.complete(self.task, self.directory, root=self.root)

    def test_tampered_or_missing_log_is_rejected(self):
        receipt = self.record()
        harness.review(self.task, "reviewer", root=self.root)
        (self.directory / receipt["log"]).write_text("forged PASS")
        with self.assertRaises(ValueError):
            harness.complete(self.task, self.directory, root=self.root)

    def test_source_change_invalidates_test_and_review(self):
        self.record()
        harness.review(self.task, "reviewer", root=self.root)
        (self.root / "source.txt").write_text("changed")
        with self.assertRaises(ValueError):
            harness.complete(self.task, self.directory, root=self.root)

    def test_out_of_scope_change_is_rejected(self):
        (self.root / "other.txt").write_text("unowned")
        self.record()
        harness.review(self.task, "reviewer", root=self.root)
        with self.assertRaisesRegex(ValueError, "outside assigned scope"):
            harness.complete(self.task, self.directory, root=self.root)

    def test_declared_required_check_cannot_be_omitted(self):
        self.task["required_checks"] = ["compile", "portable"]
        self.record()
        harness.review(self.task, "reviewer", root=self.root)
        with self.assertRaisesRegex(ValueError, "required acceptance"):
            harness.complete(self.task, self.directory, root=self.root)

    def test_interrupted_check_is_durable_and_not_accepted(self):
        path = self.directory / "task.json"
        def interrupted(argv, **kwargs):
            saved = json.loads(path.read_text())
            self.assertEqual(saved["tasks"]["task-a"]["status"], "checking")
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            harness.record_check(self.task, "compile", self.directory, root=self.root,
                runner=interrupted, checkpoint=lambda: harness.private_io.save_state(path, self.state))
        with harness.ledger(path) as resumed:
            self.assertEqual(resumed["tasks"]["task-a"]["checks"][0]["status"], "running")
            with self.assertRaises(ValueError):
                harness.review(resumed["tasks"]["task-a"], "reviewer", root=self.root)

    def test_timeout_is_blocked_not_pass(self):
        def timeout(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 300)
        receipt = harness.record_check(self.task, "compile", self.directory, root=self.root, runner=timeout)
        self.assertEqual(receipt["status"], "blocked")
        self.assertEqual(self.task["status"], "blocked")

    def test_red_fix_green_preserves_history_and_completes(self):
        self.record(returncode=1, output=b"FAILED\n")
        (self.root / "source.txt").write_text("fixed\n")
        self.record()
        harness.review(self.task, "reviewer", root=self.root)
        harness.complete(self.task, self.directory, root=self.root)
        self.assertEqual(self.task["rework"], 1)
        self.assertEqual([receipt["returncode"] for receipt in self.task["checks"]], [1, 0])

    def test_blocked_check_requires_independent_reconciliation_before_retry(self):
        self.task["status"] = "blocked"
        self.task["checks"] = [{"check": "compile", "status": "blocked"}]
        with self.assertRaises(ValueError):
            self.record()
        with self.assertRaises(ValueError):
            harness.reconcile(self.task, self.task["actor"], "reviewed", root=self.root)
        harness.reconcile(self.task, "independent-session", "verified no test process remains", root=self.root)
        self.record()
        harness.review(self.task, "reviewer", root=self.root)
        harness.complete(self.task, self.directory, root=self.root)
        self.assertIn("reconciliation", self.task["checks"][0])

    def test_cli_propagates_check_failure_and_blocked_status(self):
        path = self.directory / "state.json"
        for blocked in (False, True):
            with self.subTest(blocked=blocked):
                self.task["status"] = "running"
                harness.private_io.save_state(path, self.state)
                def fake_check(task, check, directory, **kwargs):
                    return {"status": "blocked" if blocked else "executed", "returncode": 7}
                with patch.object(harness, "record_check", side_effect=fake_check):
                    code = harness.main(["check", "--ledger", str(path), "--task", "task-a", "--check", "compile"])
                self.assertEqual(code, 2 if blocked else 1)

    def test_timed_out_test_runner_stops_its_owned_process_group(self):
        fake = unittest.mock.Mock()
        fake.pid = 456789
        fake.communicate.side_effect = [subprocess.TimeoutExpired(["mock"], 1), (b"", b""), (b"", b"")]
        with patch.object(harness.subprocess, "Popen", return_value=fake) as popen, \
             patch.object(harness.os, "killpg") as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                harness.supervised_check(["mock"], cwd=self.root, timeout=1, capture_output=True, check=False)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(kill.call_count, 2)
        self.assertTrue(all(call.args[0] == fake.pid for call in kill.call_args_list))

    def test_timeout_cleanup_oserrors_preserve_original_timeout(self):
        fake = unittest.mock.Mock()
        fake.pid = 456790
        fake.communicate.side_effect = [subprocess.TimeoutExpired(["mock"], 1), OSError("reap"), OSError("final reap")]
        with patch.object(harness.subprocess, "Popen", return_value=fake), \
             patch.object(harness.os, "killpg", side_effect=OSError("signal")):
            with self.assertRaises(subprocess.TimeoutExpired):
                harness.supervised_check(["mock"], cwd=self.root, timeout=1,
                                         capture_output=True, check=False)

    def test_symlinked_ledger_is_rejected(self):
        target = self.directory / "target"
        target.write_text("untouched")
        path = self.directory / "task.json"
        path.symlink_to(target)
        with self.assertRaises(harness.private_io.Blocked):
            with harness.ledger(path):
                self.fail("symlink must not open")
        self.assertEqual(target.read_text(), "untouched")

    def test_policy_events_and_metrics_are_explicit_and_unknown_resources_stay_unknown(self):
        self.record()
        harness.record_policy(self.task, "security-review", "hook-denial", "synthetic fixture only")
        harness.review(self.task, "reviewer", root=self.root)
        harness.complete(self.task, self.directory, root=self.root)
        self.assertEqual(len(self.task["policy_events"]), 1)
        with patch.object(harness, "ROOT", self.root):
            path = self.directory / "ledger.json"
            harness.private_io.save_state(path, self.state)
            with patch.object(harness, "ledger") as ledger:
                ledger.return_value.__enter__.return_value = self.state
                ledger.return_value.__exit__.return_value = False
                with patch("builtins.print") as output:
                    harness.main(["metrics", "--ledger", str(path)])
        metrics = json.loads(output.call_args.args[0])
        self.assertEqual(metrics["policy_violations"], 1)
        self.assertEqual(metrics["successful_tasks"], 1)
        self.assertEqual(metrics["resource_usage"]["source"], "native usage not imported")

    def test_policy_evidence_invalidates_prior_review(self):
        self.record()
        harness.review(self.task, "reviewer", root=self.root)
        harness.record_policy(self.task, "security-review", "hook-denial", "new evidence")
        with self.assertRaises(ValueError):
            harness.complete(self.task, self.directory, root=self.root)
        harness.review(self.task, "reviewer-2", root=self.root)
        harness.complete(self.task, self.directory, root=self.root)


class HookTests(unittest.TestCase):
    def test_fixed_policy_scenarios_without_executing_commands(self):
        cases = json.loads((ROOT / "engineering/fixtures/policy-cases.json").read_text())
        for case in cases:
            with self.subTest(command=case["command"]):
                result = harness.hook({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                       "tool_input": {"command": case["command"]}})
                self.assertEqual(bool(result), case["deny"])

    def test_policy_event_cli_is_in_the_reviewed_command_subset(self):
        self.assertIsNone(harness.shell_reason(
            "python3 bin/opla-engineering-ledger.py policy --ledger /tmp/task.json "
            "--task task-a --actor reviewer --violation hook-denial --note evidence"))

    def test_unknown_and_malformed_tools_deny(self):
        for tool, data in (("mcp__remote__execute", {}), ("Bash", []), ("Bash", {})):
            result = harness.hook({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": data})
            self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_protected_policy_edits_need_human_review(self):
        for file in ("AGENTS.md", "engineering/roles.json",
                     "bin/opla-lab-progress.py", "../escape"):
            result = harness.hook({"hook_event_name": "PreToolUse", "tool_name": "apply_patch",
                "tool_input": {"command": f"*** Begin Patch\n*** Update File: {file}\n@@\n-old\n+new\n*** End Patch"}})
            self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_regular_project_patch_is_not_a_policy_change(self):
        result = harness.hook({"hook_event_name": "PreToolUse", "tool_name": "apply_patch",
            "tool_input": {"command": "*** Begin Patch\n*** Update File: bin/example.py\n@@\n-old\n+new\n*** End Patch"}})
        self.assertEqual(result, {})

    def test_symlink_alias_cannot_bypass_protected_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "engineering").mkdir()
            (root / "alias").symlink_to(root / "engineering")
            (root / "outside").symlink_to("/tmp")
            with patch.object(harness, "ROOT", root):
                for path in ("alias/config.toml", "outside/elsewhere"):
                    result = harness.hook({"hook_event_name": "PreToolUse", "tool_name": "apply_patch",
                        "tool_input": {"command": f"*** Begin Patch\n*** Update File: {path}\n@@\n-old\n+new\n*** End Patch"}})
                    self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_start_and_compaction_context_do_not_run_tests(self):
        with patch.object(harness.subprocess, "run", side_effect=AssertionError("must not execute")):
            for event in ("SessionStart", "PreCompact"):
                result = harness.hook({"hook_event_name": event})
                self.assertIn("AGENTS.md", result["hookSpecificOutput"]["additionalContext"])

if __name__ == "__main__":
    unittest.main()
