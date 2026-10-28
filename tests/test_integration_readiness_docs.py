"""Contract checks for integration readiness documents; no live operations."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class IntegrationReadinessDocumentTests(unittest.TestCase):
    def read(self, name):
        return (ROOT / "docs" / name).read_text(encoding="utf-8")

    def test_required_documents_exist_and_keep_blockers_explicit(self):
        for name in (
            "integration-readiness-plan.md",
            "adr-trust-gate-b.md",
            "test-host-spec.md",
            "e2e-test-plan.md",
            "integration-runbook.md",
        ):
            with self.subTest(name=name):
                text = self.read(name)
                self.assertIn("BLOCKED", text)
                self.assertIn("NOT TESTED", text)

    def test_host_spec_matches_source_contract(self):
        text = self.read("test-host-spec.md")
        for marker in ("/dev/kvm", "ens3", "ens4", "1024 MiB", "2048 MiB",
                       "512 MiB", "qemu-system-x86_64", "dnsmasq"):
            self.assertIn(marker, text)

    def test_trust_adr_does_not_claim_activation(self):
        text = self.read("adr-trust-gate-b.md")
        for marker in ("Ed25519", "detached", "production", "test keys",
                       "revoked", "NOT TRUSTED"):
            self.assertIn(marker, text)
        self.assertIn("decision pending", text)

    def test_runbook_has_non_retry_and_cleanup_guards(self):
        text = self.read("integration-runbook.md")
        for marker in ("do not retry", "ownership", "QEMU", "Suricata",
                       "client", "cleanup", "host key"):
            self.assertIn(marker, text)


if __name__ == "__main__":
    unittest.main()
