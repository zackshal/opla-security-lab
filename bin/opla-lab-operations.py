"""Offline executor integration for existing lifecycle launchers.

There is deliberately no subprocess implementation or live CLI here. The injected
backend must declare offline mode; tests return process results without spawning.
"""

import asyncio
import hashlib
import importlib.util
import re
import uuid
from pathlib import Path

LAB = re.compile(r"lab-[A-Za-z0-9]{4,32}\Z")


class OperationFailure(RuntimeError):
    def __init__(self, message, evidence):
        super().__init__(message)
        self.evidence = evidence


def created_lab_id(stdout):
    values = [line.removeprefix("OPLA_CREATED_LAB_ID=")
              for line in stdout.splitlines() if line.startswith("OPLA_CREATED_LAB_ID=")]
    if len(values) != 1 or not LAB.fullmatch(values[0]):
        raise ValueError("missing, ambiguous or invalid created lab ID")
    return values[0]


class OperationsAdapter:
    """Bind generated lab identity and record injected command outcomes.

    backend.run(command_id, argv) is cancellable and returns CompletedProcess.
    backend.stop_process_tree(command_id) must terminate/wait for the whole mock
    process group; it returns JSON evidence. Stopping a process group does not
    reconcile VM/network resources. The remaining stages/probes use backend's
    existing execute/probe adapter contract with the actual lab ID.
    """

    mode = "offline"

    def __init__(self, backend):
        if getattr(backend, "mode", None) != "offline":
            raise ValueError("offline backend required")
        self.backend = backend
        self.actual_lab_id = None
        self.checkpoint = None

    def bind_checkpoint(self, checkpoint):
        self.checkpoint = checkpoint

    def restore(self, state):
        create = state["steps"]["create"]
        if create["status"] == "PASS":
            action = create.get("evidence", {}).get("action", {})
            actual = action.get("actual_lab_id")
            if (not isinstance(actual, str) or not LAB.fullmatch(actual)
                    or action.get("lab_id") != state["lab_id"]):
                raise ValueError("cannot restore created lab identity")
            if self.actual_lab_id is not None and self.actual_lab_id != actual:
                raise ValueError("created lab identity changed")
            self.actual_lab_id = actual

    def identity(self, step, correlation):
        if step not in ("preflight", "create") and self.actual_lab_id is None:
            raise ValueError("created lab identity unavailable")
        return self.actual_lab_id or correlation

    def normalize(self, result, correlation, expected):
        if not isinstance(result, dict) or result.get("lab_id") != expected:
            raise ValueError("backend lab identity mismatch")
        return {**result, "lab_id": correlation, "actual_lab_id": self.actual_lab_id}

    async def command(self, step, argv):
        if self.checkpoint is None:
            raise ValueError("persistent command checkpoint required")
        record = {"command_id": uuid.uuid4().hex, "argv": argv,
                  "mode": "offline", "status": "PREPARED", "reconciliation_required": True}
        self.checkpoint(step, record)
        try:
            result = await self.backend.run(record["command_id"], argv)
        except asyncio.CancelledError:
            record.update(status="CANCELLED", reconciliation_required=True)
            try:
                record["process_cleanup"] = await asyncio.wait_for(
                    self.backend.stop_process_tree(record["command_id"]), timeout=1.0)
            except Exception as exc:
                record["process_cleanup"] = {"status": "unknown", "error_type": type(exc).__name__}
            self.checkpoint(step, record)
            raise OperationFailure("command cancelled; reconcile resources before resume", record)
        except Exception as exc:
            record.update(status="UNKNOWN", reconciliation_required=True,
                          error_type=type(exc).__name__)
            self.checkpoint(step, record)
            raise OperationFailure("executor failed; reconcile resources", record) from exc
        record.update(returncode=result.returncode, status="COMPLETED")
        for name in ("stdout", "stderr"):
            output = getattr(result, name, "") or ""
            if not isinstance(output, str):
                raise OperationFailure("command output must be text", record)
            record[name + "_sha256"] = hashlib.sha256(output.encode()).hexdigest()
        if type(result.returncode) is not int or result.returncode != 0:
            record["reconciliation_required"] = True
            self.checkpoint(step, record)
            raise OperationFailure("lifecycle command failed", record)
        record["reconciliation_required"] = False
        self.checkpoint(step, record)
        return result.stdout, record

    async def execute(self, step, lab_id):
        actual = self.identity(step, lab_id)
        if step == "create":
            if self.actual_lab_id is not None:
                raise ValueError("creation cannot be replayed")
            stdout, command = await self.command(step, ["python3", "bin/opla-create-launcher.py"])
            try:
                self.actual_lab_id = created_lab_id(stdout)
            except ValueError as exc:
                command["reconciliation_required"] = True
                self.checkpoint(step, command)
                raise OperationFailure(str(exc), command) from exc
            return {"lab_id": lab_id, "actual_lab_id": self.actual_lab_id, "command": command}
        if step == "configure":
            _, command = await self.command(step, [
                "python3", "bin/opla-lab-configure-launcher.py", actual, actual])
            return {"lab_id": lab_id, "actual_lab_id": actual, "command": command}
        result = await self.backend.execute(step, actual)
        return self.normalize(result, lab_id, actual)

    async def probe(self, step, lab_id):
        actual = self.identity(step, lab_id)
        if step == "create" and self.actual_lab_id is None:
            raise ValueError("created lab identity unavailable")
        return self.normalize(await self.backend.probe(step, actual), lab_id, actual)


class RegistryAdapter:
    """Add receipt/resource parser observations without asserting ownership.

    inspector(kind, name) is mandatory: there is no fallback to live probes.
    The existing registry verifier reconstructs resource names from state.env.
    Its ownership flags remain false, so this layer cannot grant lifecycle PASS
    or deletion authority merely because a receipt lists existing resources.
    """

    mode = "offline"

    def __init__(self, operations, *, root, inspector, process_inspector=None,
                 ownership_attestor=None):
        if getattr(operations, "mode", None) != "offline":
            raise ValueError("offline operations required")
        self.operations = operations
        self.root = Path(root)
        if self.root.is_symlink():
            raise ValueError("registry root symlink refused")
        self.inspector = inspector
        self.process_inspector = process_inspector
        self.ownership_attestor = ownership_attestor
        spec = importlib.util.spec_from_file_location(
            "operations_registry_verifier",
            Path(__file__).with_name("opla-registry-verify.py"))
        self.verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.verifier)

    def bind_checkpoint(self, checkpoint):
        bind = getattr(self.operations, "bind_checkpoint", None)
        if bind is not None:
            bind(checkpoint)

    def restore(self, state):
        restore = getattr(self.operations, "restore", None)
        if restore is not None:
            restore(state)

    async def execute(self, step, lab_id):
        return await self.operations.execute(step, lab_id)

    async def probe(self, step, lab_id):
        result = dict(await self.operations.probe(step, lab_id))
        if step == "preflight":
            return result
        actual = result.get("actual_lab_id", result.get("lab_id"))
        if not isinstance(actual, str) or not LAB.fullmatch(actual):
            raise ValueError("registry probe requires actual lab identity")
        records = self.verifier.verify(self.root, actual, inspector=self.inspector)
        result["registry_observations"] = records
        if self.process_inspector is not None:
            result["process_observations"] = self.process_inspector(self.root, actual)
        record = records[0] if len(records) == 1 else {}
        checks = record.get("checks", [])
        result["ownership"] = bool(checks) and all(
            check.get("ownership_verified") is True for check in checks)
        if self.ownership_attestor is not None:
            try:
                expected = self.verifier.reg.receipt(self.root, actual, "ready")["resources"]
                attestation = self.ownership_attestor(actual, expected, records)
                result["ownership_attestation"] = attestation
                result["ownership"] = result["ownership"] or self._valid_attestation(
                    attestation, actual, expected, checks)
            except (OSError, TypeError, ValueError, KeyError, AttributeError) as exc:
                result["ownership_attestation"] = {
                    "status": "invalid", "error_type": type(exc).__name__}
        if step == "create":
            listed = self.verifier.reg.inspect(self.root, actual)
            result["registry"] = (
                record.get("status") == "observed_unverified" and bool(checks)
                and all(check["status"] in ("present", "active") for check in checks)
                and len(listed) == 1 and listed[0].get("status") == "recorded")
            guests = [check for check in checks if check["kind"] == "qemu_unit"]
            result["three_vms"] = len(guests) == 3 and all(
                check["status"] == "active" for check in guests)
        return result

    @staticmethod
    def _valid_attestation(attestation, actual, expected, checks):
        """Accept only explicit synthetic ownership evidence for this resource set.

        This callback is an offline contract, never a host probe or cleanup
        authorization. Unknown/malformed/cross-lab evidence remains false.
        """
        if not isinstance(attestation, dict):
            return False
        if (attestation.get("lab_id") != actual
                or attestation.get("exclusive") is not True
                or attestation.get("cross_lab_conflict") is not False
                or attestation.get("evidence_status") != "synthetic"):
            return False
        resources = attestation.get("resources")
        if not isinstance(resources, list) or any(not isinstance(item, dict) for item in resources):
            return False
        normalize = lambda seq: sorted((item.get("kind"), item.get("name")) for item in seq)
        if normalize(resources) != normalize(expected) or len(resources) != len(expected):
            return False
        return bool(checks) and all(check.get("status") in ("present", "active") for check in checks)
