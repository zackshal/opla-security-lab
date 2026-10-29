import asyncio
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
spec = importlib.util.spec_from_file_location('opla_services_test', ROOT / 'bin/opla-services.py')
services = importlib.util.module_from_spec(spec)
spec.loader.exec_module(services)


class ServiceStatusTests(unittest.TestCase):
    def test_missing_sockets_describe_real_implementation_boundaries(self):
        with tempfile.TemporaryDirectory() as temp:
            result = asyncio.run(services.inspect_services(Path(temp)))
        self.assertEqual(set(result), set(services.SERVICE_CAPABILITIES))
        self.assertTrue(all(item['status'] == 'NOT_STARTED' for item in result.values()))
        self.assertEqual(result['opla-evidence']['implementation'], 'IMPLEMENTED_LOCAL_WORKER')
        self.assertEqual(result['opla-evidence']['operations'], ['incident_report'])
        for name in ('opla-control', 'opla-host-backend', 'opla-guest-agent', 'opla-monitoring'):
            self.assertEqual(result[name]['implementation'], 'OFFLINE_CONTRACT_ONLY')
            self.assertEqual(result[name]['operations'], [])


if __name__ == '__main__':
    unittest.main()
