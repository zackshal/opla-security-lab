import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('acceptance_evidence', ROOT / 'bin/opla-service-acceptance.py')
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class AcceptanceEvidenceTests(unittest.TestCase):
    def report(self):
        return {'schema_version': 1, 'status': 'PASS', 'source_unchanged': True,
                'tests_run': 11, 'failures': 0, 'errors': 0, 'skipped': 0,
                'live_lab_status': 'NOT TESTED', 'sources': acceptance.source_hashes()}

    def test_fresh_report_matches_but_changed_hash_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'report.json'
            report = self.report()
            path.write_text(json.dumps(report))
            self.assertEqual(acceptance.verify_report(path)['status'], 'PASS')
            report['sources']['bin/opla_service_runtime.py'] = '0' * 64
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, 'stale report'):
                acceptance.verify_report(path)

    def test_skipped_tests_or_live_claim_cannot_satisfy_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'report.json'
            for changed in ({'skipped': 1}, {'live_lab_status': 'PASS'}, {'schema_version': True}):
                path.write_text(json.dumps({**self.report(), **changed}))
                with self.assertRaises(ValueError):
                    acceptance.verify_report(path)
