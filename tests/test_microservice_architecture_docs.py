from pathlib import Path
import importlib.util
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "opla_service_contract", ROOT / "bin" / "opla_service_contract.py"
)
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)


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


if __name__ == "__main__":
    unittest.main()
