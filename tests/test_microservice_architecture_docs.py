from pathlib import Path
import importlib.util
import json
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "opla_service_contract", ROOT / "bin" / "opla_service_contract.py"
)
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)
TRANSPORT_SPEC = importlib.util.spec_from_file_location(
    "opla_service_transport", ROOT / "bin" / "opla_service_transport.py"
)
TRANSPORT = importlib.util.module_from_spec(TRANSPORT_SPEC)
TRANSPORT_SPEC.loader.exec_module(TRANSPORT)
HANDLER_SPEC = importlib.util.spec_from_file_location(
    "opla_service_handlers", ROOT / "bin" / "opla_service_handlers.py"
)
HANDLERS = importlib.util.module_from_spec(HANDLER_SPEC)
HANDLER_SPEC.loader.exec_module(HANDLERS)


class MicroserviceArchitectureDocsTests(unittest.TestCase):
    def test_adr_defines_all_service_boundaries(self):
        text = (ROOT / "docs" / "adr-microservice-architecture.md").read_text()
        for service in (
            "opla-control",
            "opla-host-backend",
            "opla-guest-agent",
            "opla-evidence",
            "opla-monitoring",
        ):
            self.assertIn(service, text)
        self.assertIn("единственный владелец состояния операции", text)
        self.assertIn("operation_id", text)
        self.assertIn("UnixServiceRouter", text)
        self.assertIn("JsonLineServiceWorker", text)

    def test_docs_do_not_claim_microservices_are_already_deployed(self):
        architecture = (ROOT / "docs" / "architecture.md").read_text()
        adr = (ROOT / "docs" / "adr-microservice-architecture.md").read_text()
        self.assertIn("Целевая микросервисная архитектура", architecture)
        self.assertIn("независимый production runtime ещё не заявлен", adr)
        self.assertIn("модульный монолит с целевыми сервисными границами", adr)

    def test_architecture_docs_follow_check_boundaries(self):
        architecture = (ROOT / "docs" / "architecture.md").read_text()
        platform = (ROOT / "docs" / "platform-compatibility.md").read_text()
        checks = (ROOT / "tests" / "check.py").read_text()
        self.assertIn("Live three-VM acceptance для текущей ветки не выполнена", architecture)
        self.assertIn("Остальные ОС и ISA должны отображаться как `UNKNOWN`, `BLOCKED` или `FEASIBLE`", architecture)
        self.assertIn("NOT RUN: clang -target bpf, kernel verifier, KVM, live Zabbix API and dashboard", checks)
        self.assertIn("no non-Debian live acceptance evidence exists", platform)

    def test_envelope_is_exact_and_identity_bound(self):
        envelope = CONTRACT.ServiceEnvelope(
            service="opla-host-backend",
            operation="probe",
            operation_id="op-123",
            lab_id="lab-ABC123",
            requested_at="2026-01-01T00:00:00Z",
            payload={"resource": "victim"},
            evidence={},
        )
        self.assertEqual(
            CONTRACT.ServiceEnvelope.from_dict(envelope.as_dict()), envelope
        )
        with self.assertRaises(ValueError):
            CONTRACT.ServiceEnvelope.from_dict({**envelope.as_dict(), "extra": 1})
        with self.assertRaises(ValueError):
            CONTRACT.ServiceEnvelope(
                service="opla-host-backend",
                operation="probe",
                operation_id="op-123",
                lab_id="lab-ABC123",
                requested_at="2026-01-01T00:00:00",
                payload={},
                evidence={},
            )

    def test_unix_jsonl_transport_round_trip(self):
        envelope = CONTRACT.ServiceEnvelope(
            service="opla-evidence",
            operation="probe",
            operation_id="op-transport",
            lab_id="lab-ABC123",
            requested_at="2026-01-01T00:00:00Z",
            payload={"step": "report"},
            evidence={},
        )
        class FakeSocket:
            def __init__(self, *_args):
                self.sent = b""

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, _timeout):
                pass

            def connect(self, path):
                self.path = path

            def sendall(self, data):
                self.sent += data

            def recv(self, _size):
                request = json.loads(self.sent.decode())
                return json.dumps({"lab_id": request["lab_id"], "ok": True}).encode() + b"\n"

        with patch.object(TRANSPORT.socket, "socket", FakeSocket):
            result = TRANSPORT.JsonLineServiceClient("/run/opla/evidence.sock", timeout=1).dispatch(envelope)
        self.assertEqual(result, {"lab_id": "lab-ABC123", "ok": True})

    def test_unix_service_router_selects_service_socket(self):
        envelope = CONTRACT.ServiceEnvelope(
            service="opla-guest-agent",
            operation="probe",
            operation_id="op-router",
            lab_id="lab-ABC123",
            requested_at="2026-01-01T00:00:00Z",
            payload={},
            evidence={},
        )

        class FakeClient:
            def __init__(self, path, timeout):
                self.path = path
                self.timeout = timeout

            def dispatch(self, request):
                return {"path": self.path, "lab_id": request.lab_id}

        with patch.object(TRANSPORT, "JsonLineServiceClient", FakeClient):
            router = TRANSPORT.UnixServiceRouter(
                {"opla-host-backend": "/run/opla/host.sock", "opla-guest-agent": "/run/opla/guest.sock"},
                timeout=1,
            )
            self.assertEqual(
                router.dispatch(envelope),
                {"path": "/run/opla/guest.sock", "lab_id": "lab-ABC123"},
            )
            with self.assertRaises(TRANSPORT.ServiceTransportError):
                router.dispatch(
                    CONTRACT.ServiceEnvelope(
                        service="opla-evidence",
                        operation="probe",
                        operation_id="op-router-2",
                        lab_id="lab-ABC123",
                        requested_at="2026-01-01T00:00:00Z",
                        payload={},
                        evidence={},
                    )
                )

    def test_worker_validates_and_handles_one_request(self):
        received = []

        def handler(envelope):
            received.append(envelope)
            return {"status": "PASS", "lab_id": envelope.lab_id}

        worker = TRANSPORT.JsonLineServiceWorker(CONTRACT.ServiceEnvelope, handler)

        class Connection:
            def __init__(self, data):
                self.data = data
                self.sent = b""

            def recv(self, _size):
                data, self.data = self.data, b""
                return data

            def sendall(self, data):
                self.sent += data

        connection = Connection((json.dumps({
            "schema_version": 1,
            "service": "opla-evidence",
            "operation": "probe",
            "operation_id": "op-worker",
            "lab_id": "lab-ABC123",
            "requested_at": "2026-01-01T00:00:00Z",
            "payload": {},
            "evidence": {},
        }) + "\n").encode())
        worker.serve_connection(connection)
        self.assertEqual(json.loads(connection.sent), {"status": "PASS", "lab_id": "lab-ABC123"})
        self.assertEqual(received[0].service, "opla-evidence")

    def test_worker_rejects_malformed_request_without_handler_call(self):
        called = []
        worker = TRANSPORT.JsonLineServiceWorker(
            CONTRACT.ServiceEnvelope, lambda _envelope: called.append(True)
        )
        class Connection:
            def __init__(self):
                self.sent = b""

            def recv(self, _size):
                return b"{}\n"

            def sendall(self, data):
                self.sent += data

        connection = Connection()
        worker.serve_connection(connection)
        self.assertEqual(
            json.loads(connection.sent),
            {"error": "invalid service request", "status": "BLOCKED"},
        )
        self.assertEqual(called, [])

    def test_service_handler_enforces_boundary_and_preserves_adapter(self):
        class Adapter:
            async def execute(self, step, lab_id):
                return {"lab_id": lab_id, "step": step, "action": True}

            async def probe(self, step, lab_id):
                return {"lab_id": lab_id, "step": step, "probe": True}

        handler = HANDLERS.AdapterServiceHandler("opla-guest-agent", Adapter())
        envelope = CONTRACT.ServiceEnvelope(
            service="opla-guest-agent",
            operation="probe",
            operation_id="op-handler",
            lab_id="lab-ABC123",
            requested_at="2026-01-01T00:00:00Z",
            payload={"step": "health"},
            evidence={},
        )
        import asyncio
        self.assertEqual(
            asyncio.run(handler(envelope)),
            {"lab_id": "lab-ABC123", "step": "health", "probe": True},
        )
        with self.assertRaises(ValueError):
            asyncio.run(handler(CONTRACT.ServiceEnvelope(
                service="opla-guest-agent",
                operation="probe",
                operation_id="op-handler-bad",
                lab_id="lab-ABC123",
                requested_at="2026-01-01T00:00:00Z",
                payload={"step": "create"},
                evidence={},
            )))


if __name__ == "__main__":
    unittest.main()
