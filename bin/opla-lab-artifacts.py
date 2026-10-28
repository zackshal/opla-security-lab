"""Offline lifecycle integration of existing image/scenario/evidence parsers.

No command executor is provided. Callers must inject an offline operation adapter
and a qemu-info runner. No VM, SSH or privileged operation is performed here.
"""

import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


images = load("artifact_images", "opla-image-verify.py")
scenarios = load("artifact_scenarios", "opla-scenario.py")
incidents = load("artifact_incidents", "opla-incident-report.py")
fingerprints = load("artifact_fingerprints", "opla-fingerprint-evidence.py")
collector = load("artifact_collector", "../xdp/collect.py")


class ArtifactAdapter:
    """Decorate an offline operation adapter with independently parsed evidence.

    operation_adapter supplies resource/health observations and action records.
    This layer replaces image, scenario, telemetry and report assertions with
    parser results. It intentionally cannot establish complete live evidence.
    Synchronous parsers consume bounded local fixture files, not live streams.
    """

    mode = "offline"

    def __init__(self, operation_adapter, *, image_directory, image_runner,
                 scenario, experiment, health_provider=None,
                 expected_host_key=None, clock=time.time, max_health_age=30,
                 strict_client_coverage=False, max_client_gap_seconds=2):
        if getattr(operation_adapter, "mode", None) != "offline":
            raise ValueError("offline operation adapter required")
        self.operations = operation_adapter
        self.image_directory = Path(image_directory)
        self.image_runner = image_runner
        self.scenario = scenario
        self.experiment = Path(experiment)
        if health_provider is not None and (not isinstance(expected_host_key, str)
                                           or not expected_host_key.startswith("SHA256:")):
            raise ValueError("independently pinned management host key required")
        if (isinstance(max_health_age, bool) or not isinstance(max_health_age, (int, float))
                or not math.isfinite(max_health_age) or max_health_age <= 0):
            raise ValueError("invalid health freshness limit")
        self.health_provider = health_provider
        self.expected_host_key = expected_host_key
        self.clock = clock
        self.max_health_age = max_health_age
        if type(strict_client_coverage) is not bool:
            raise ValueError("strict client coverage must be a boolean")
        if (type(max_client_gap_seconds) not in (int, float)
                or not math.isfinite(max_client_gap_seconds) or max_client_gap_seconds <= 0):
            raise ValueError("client maximum sampling gap must be finite and positive")
        self.strict_client_coverage = strict_client_coverage
        self.max_client_gap_seconds = max_client_gap_seconds

    def restore(self, state):
        restore = getattr(self.operations, "restore", None)
        if restore is not None:
            restore(state)

    def bind_checkpoint(self, checkpoint):
        bind = getattr(self.operations, "bind_checkpoint", None)
        if bind is not None:
            bind(checkpoint)

    def verify_images(self):
        return [images.verify(role, filename, size, images=self.image_directory,
                              runner=self.image_runner)
                for role, (filename, size) in images.ROLE_IMAGES.items()]

    def scenario_plan(self):
        plan = scenarios.validate(scenarios.load_scenario(self.scenario))
        if plan["scenario"] != self.scenario:
            raise ValueError("scenario identity mismatch")
        return plan

    def evidence(self):
        report = incidents.build_report(
            self.experiment, eve_path=self.experiment / "eve.json",
            scan_path=self.experiment / "events.jsonl",
            max_client_gap_seconds=self.max_client_gap_seconds,
        )
        fingerprint = fingerprints.verify_directory(self.experiment)
        return report, fingerprint

    def artifact_hashes(self, client_evidence=None):
        result = {}
        for name in ("interval.json", "before.json", "after.json", "eve.json",
                     "events.jsonl", "fingerprint-before.json", "fingerprint-after.json",
                     "suricata-evidence-meta.json", "scan-evidence-meta.json"):
            path = self.experiment / name
            try:
                file_stat = path.lstat()
            except OSError as exc:
                raise ValueError(f"missing or unsafe artifact: {name}") from exc
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1:
                raise ValueError(f"missing or unsafe artifact: {name}")
            result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        if os.path.lexists(self.experiment / "client-probes.json"):
            if client_evidence is None:
                client_evidence = incidents.client_continuity_report(
                    self.experiment, incidents.read_json(self.experiment / "interval.json"),
                    max_gap_seconds=self.max_client_gap_seconds)
            client_hash = client_evidence.get("artifact_sha256")
            if not isinstance(client_hash, str):
                raise ValueError("unsafe or unreadable client evidence")
            result["client-probes.json"] = client_hash
        return result

    def fresh(self, observation):
        sampled = observation.get("sampled_at")
        now = self.clock()
        if (type(sampled) not in (int, float) or not math.isfinite(sampled)
                or not 0 <= now - sampled <= self.max_health_age):
            raise ValueError("stale or invalid current-health observation")

    async def current_health(self, step, actual):
        observation = await self.health_provider(step, actual)
        if not isinstance(observation, dict) or observation.get("lab_id") != actual:
            raise ValueError("current-health identity mismatch")
        self.fresh(observation)
        management = observation.get("management", {})
        protected = observation.get("protected", {})
        if not isinstance(management, dict) or not isinstance(protected, dict):
            raise ValueError("invalid interface observation")
        for interface in (management, protected):
            if (type(interface.get("ifindex")) is not int or interface["ifindex"] <= 0
                    or not isinstance(interface.get("name"), str)
                    or re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface["name"]) is None):
                raise ValueError("invalid observed interface identity")
        if (management["ifindex"] == protected["ifindex"]
                or management["name"] == protected["name"]
                or management.get("route_interface") != management["name"]
                or management.get("host_key_fingerprint") != self.expected_host_key):
            raise ValueError("management path is shared, misrouted or unpinned")
        result = {"management_separate": True, "current_health": observation}
        if step in ("configure", "health", "scenario"):
            snapshot = observation.get("snapshot")
            correlated = incidents.counters.correlate(snapshot, snapshot)
            identity = observation.get("fingerprint")
            fingerprint = fingerprints.verify(identity, identity)
            mode = collector.attachment_mode(protected.get("xdp", {}), identity.get("program_id"))
            result["xdp_loaded"] = (correlated["availability"]["xdp"] == "available"
                                    and fingerprint["status"] == "verified"
                                    and mode == identity.get("attachment_mode"))
            result["suricata_active"] = (
                correlated["availability"]["suricata"] == "available"
                and observation.get("suricata_service") == "active")
            if step == "scenario" and not (result["xdp_loaded"] and result["suricata_active"]):
                raise ValueError("protection became unhealthy during scenario")
            if step in ("health", "scenario"):
                client = observation.get("client", {})
                self.fresh(client)
                result["client_alive"] = (
                    client.get("source_role") == "client" and client.get("target_role") == "victim"
                    and type(client.get("returncode")) is int and client["returncode"] == 0
                    and type(client.get("http_status")) is int and client["http_status"] == 200)
        return result

    async def execute(self, step, lab_id):
        # Validate local inputs before dispatching even an injected action.
        extra = {}
        if step == "preflight":
            extra["verified_images"] = self.verify_images()
        elif step == "scenario":
            extra["scenario_plan"] = self.scenario_plan()
        elif step in ("telemetry", "report"):
            report, fingerprint = self.evidence()
            extra = {"incident_report": report, "fingerprint": fingerprint,
                     "artifact_sha256": self.artifact_hashes(report["client_continuity"])}
        result = await self.operations.execute(step, lab_id)
        if not isinstance(result, dict):
            raise ValueError("invalid operation evidence")
        return {**result, **extra}

    async def probe(self, step, lab_id):
        result = dict(await self.operations.probe(step, lab_id))
        client_evidence = None
        if self.health_provider is not None:
            result.update(await self.current_health(step, result.get("actual_lab_id") or lab_id))
        if step == "preflight":
            result["verified_images"] = self.verify_images()
            result["images"] = True
        elif step == "scenario":
            result["scenario_plan"] = self.scenario_plan()
        elif step in ("telemetry", "report"):
            report, fingerprint = self.evidence()
            client_evidence = report["client_continuity"]
            hashes = self.artifact_hashes(report["client_continuity"])
            observations = report["counters"]["observations"]
            xdp = report["counters"]["availability"]["xdp"]
            result.update({"incident_report": report, "fingerprint": fingerprint,
                           "artifact_sha256": hashes})
            if step == "telemetry":
                result.update({
                    "xdp_counters": xdp == "available" and fingerprint["status"] == "verified",
                    "suricata_events": report["suricata"].get("matching_alerts", 0) > 0,
                    "correlation": observations["syn_traffic_observed"] is True
                        and report["scan_detector"].get("matching_events", 0) > 0,
                })
            else:
                result["report_generated"] = True
                result["evidence_complete"] = (
                    report["evidence_quality"]["complete_evidence_verified"] is True
                    and fingerprint["status"] == "verified"
                )
        if self.strict_client_coverage and step in ("scenario", "telemetry"):
            client = client_evidence
            if client is None:
                client = incidents.client_continuity_report(
                    self.experiment, incidents.read_json(self.experiment / "interval.json"),
                    max_gap_seconds=self.max_client_gap_seconds)
            actual = result.get("actual_lab_id") or lab_id
            if client.get("covered_at_cadence") is True and client.get("lab_id") != actual:
                raise ValueError("client evidence lab differs from requested laboratory")
            result["client_continuity"] = client
            covered = client.get("covered_at_cadence") is True
            if step == "scenario":
                result["client_alive"] = result.get("client_alive") is True and covered
            else:
                result["correlation"] = result.get("correlation") is True and covered
        # Verify serialization before returning data to the persistent journal.
        json.dumps(result, allow_nan=False)
        return result
