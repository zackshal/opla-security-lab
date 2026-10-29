import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class LaboratoryConfigurationTests(unittest.TestCase):

    def test_configuration_requires_exact_identity(self):
        source = (
            ROOT / "bin/opla-lab-configure.sh"
        ).read_text()

        self.assertIn('"$CONFIRM" != "$LAB_ID"', source)
        self.assertIn('ACTUAL_ID="$(python3 bin/state.py', source)
        self.assertIn('"$ACTUAL_ID" != "$LAB_ID"', source)

    def test_initialization_order(self):
        source = (
            ROOT / "bin/opla-lab-configure.sh"
        ).read_text()

        steps = (
            'make --no-print-directory ready',
            'command -v suricata',
            'make --no-print-directory xdp-all',
            'bin/security-http.sh apply',
            'bin/scan-detector.sh start',
            'curl --fail --silent --show-error --max-time 5',
            'make --no-print-directory ids ',
            'make --no-print-directory ids-status',
            'make --no-print-directory xdp-stats',
        )

        positions = [source.index(step) for step in steps]
        self.assertEqual(positions, sorted(positions))

    def test_missing_victim_dependencies_block_before_guest_changes(self):
        source = (ROOT / "bin/opla-lab-configure.sh").read_text()
        preflight = source.index('command -v suricata')
        first_change = source.index('make --no-print-directory xdp-all')
        self.assertLess(preflight, first_change)
        self.assertIn('rebuild the victim role image and create a new lab', source)

    def test_configuration_probes_http_before_final_telemetry_refresh(self):
        source = (ROOT / "bin/opla-lab-configure.sh").read_text()
        http_probe = source.index('HTTP JSON telemetry probe')
        ids_active = source.index('Suricata service active')
        refresh = source.index('Verify XDP, HTTP, scan and IDS telemetry')
        self.assertLess(http_probe, ids_active)
        self.assertLess(ids_active, refresh)

    def test_no_automatic_vm_deletion(self):
        source = (
            ROOT / "bin/opla-lab-configure.sh"
        ).read_text()

        self.assertNotIn("cleanup-lab.sh", source)
        self.assertNotIn("lab-delete", source)

    def test_make_target_exists(self):
        makefile = (ROOT / "Makefile").read_text()

        self.assertIn("lab-configure:", makefile)
        self.assertIn(
            "bin/opla-lab-configure-launcher.py",
            makefile,
        )

        launcher = (
            ROOT / "bin/opla-lab-configure-launcher.py"
        ).read_text()

        self.assertIn(
            'str(HERE / "opla-lab-configure.sh")',
            launcher,
        )


if __name__ == "__main__":
    unittest.main()
