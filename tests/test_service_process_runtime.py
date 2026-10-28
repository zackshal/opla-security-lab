"""Real local sockets/processes; business operations use synthetic adapters."""
import asyncio
from contextlib import contextmanager
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
from opla_service_contract import ServiceEnvelope
from opla_service_runtime import AsyncServiceClient, AsyncServiceRouter, ServiceServer, decode
from opla_service_transport import ServiceTransportError

spec = importlib.util.spec_from_file_location('process_test_orchestrator', ROOT / 'bin/opla-lab-orchestrator.py')
orchestrator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = orchestrator
spec.loader.exec_module(orchestrator)


def request(service='opla-host-backend', operation='health', step=None):
    return ServiceEnvelope(service, operation, 'test-operation', 'lab-ABCD',
                           datetime.now(timezone.utc).isoformat(),
                           {} if step is None else {'step': step}, {})


class ServiceRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'host.sock'
        self.server = ServiceServer('opla-host-backend', self.path)
        await self.server.start()
        self.addAsyncCleanup(self.server.close)

    async def test_real_socket_health_is_not_lab_readiness(self):
        result = await AsyncServiceClient(self.path).dispatch(request())
        self.assertEqual(result['pid'], os.getpid())
        self.assertEqual(result['uid'], os.getuid())
        self.assertEqual(result['lab_readiness'], 'NOT TESTED')
        self.assertFalse(result['business_adapter'])

    async def test_wrong_service_and_unconfigured_business_request_block(self):
        for envelope in (request('opla-evidence'), request(operation='execute', step='create')):
            with self.assertRaises(ServiceTransportError):
                await AsyncServiceClient(self.path).dispatch(envelope)

    async def test_second_server_cannot_replace_first_socket(self):
        other = ServiceServer('opla-host-backend', self.path)
        with self.assertRaises(ValueError):
            await other.start()
        result = await AsyncServiceClient(self.path).dispatch(request())
        self.assertEqual(result['service'], 'opla-host-backend')

    async def test_insecure_socket_permissions_block_before_connect(self):
        self.path.chmod(0o666)
        with self.assertRaises(ServiceTransportError):
            await AsyncServiceClient(self.path).dispatch(request())

    async def test_timeout_cancels_async_handler(self):
        cancelled = asyncio.Event()
        async def slow(envelope):
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()
        self.server.handler = slow
        self.server.timeout = 0.05
        with self.assertRaises(ServiceTransportError):
            await AsyncServiceClient(self.path).dispatch(request(operation='execute', step='create'))
        self.assertTrue(cancelled.is_set())

    async def test_wrong_peer_uid_is_rejected(self):
        with patch('opla_service_runtime.peer_uid', return_value=os.getuid() + 1):
            with self.assertRaises(ServiceTransportError):
                await AsyncServiceClient(self.path).dispatch(request())

    async def test_forged_response_operation_is_rejected(self):
        from opla_service_runtime import encode
        async def forged(writer, envelope, status, result):
            writer.write(encode({'schema_version': 1, 'service': envelope.service,
                                 'operation_id': 'another-operation', 'lab_id': envelope.lab_id,
                                 'status': 'OK', 'result': result}))
            await writer.drain()
        with patch.object(self.server, '_reply', forged):
            with self.assertRaisesRegex(ServiceTransportError, 'identity mismatch'):
                await AsyncServiceClient(self.path).dispatch(request())

    async def test_closing_unstarted_server_cannot_remove_existing_socket(self):
        other = ServiceServer('opla-host-backend', self.path)
        await other.close()
        self.assertTrue(self.path.is_socket())

    def test_duplicate_keys_and_nonfinite_values_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.assertRaises(ValueError):
                decode(raw)


@unittest.skipIf(os.geteuid() == 0, 'service executable intentionally refuses root; run unprivileged')
class ServiceProcessAcceptanceTests(unittest.TestCase):
    @contextmanager
    def workers(self, directory, *, adapters=True):
        processes = []
        sockets = {}
        try:
            for short, name in (('h', 'opla-host-backend'), ('g', 'opla-guest-agent'), ('e', 'opla-evidence')):
                path = directory / f'{name}.sock'
                command = [sys.executable, str(ROOT / 'bin/opla-service.py'), '--service', name,
                           '--socket', str(path)]
                if adapters:
                    command += ['--adapter', str(ROOT / 'tests/fixtures/service_adapter.py')]
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
                )
                processes.append(process)
                ready, _, _ = select.select([process.stdout], [], [], 5)
                self.assertTrue(ready, 'worker did not signal readiness within five seconds')
                line = process.stdout.readline()
                if not line.startswith('LISTENING'):
                    _, error = process.communicate(timeout=3)
                    self.fail(f'worker startup failed: {error}')
                sockets[name] = path
            yield processes, sockets
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=3)

    def test_full_offline_lifecycle_crosses_three_process_boundaries(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            with self.workers(directory) as (processes, sockets):
                pids = set()
                for service, path in sockets.items():
                    result = asyncio.run(AsyncServiceClient(path).dispatch(request(service)))
                    pids.add(result['pid'])
                self.assertEqual(pids, {process.pid for process in processes})
                router = AsyncServiceRouter(sockets)
                journal = directory / 'journal.json'
                result = orchestrator.run_acceptance(router, journal, 'lab-ABCD')
                self.assertEqual(result['status'], 'PASS', result)
                self.assertEqual(result['live_status'], 'NOT TESTED')
                self.assertTrue(result['steps']['create']['evidence']['action']['synthetic'])
                # A real service outage must fail revalidation, never fall back.
                processes[1].terminate()
                processes[1].wait(timeout=3)
                resumed = orchestrator.run_acceptance(router, journal, 'lab-ABCD', resume=True)
                self.assertNotEqual(resumed['status'], 'PASS')

    def test_cli_report_uses_real_evidence_worker_and_preserves_uncertainty(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / 'opla'
            directory.mkdir(mode=0o700)
            experiment = Path(temp) / 'experiment-ABCD'
            experiment.mkdir()
            interval = {'schema_version': 1, 'lab_id': 'lab-ABCD', 'clock_source': 'victim',
                        'start': '2026-10-27T13:00:00Z', 'end': '2026-10-27T13:00:10Z',
                        'source_ip': '100.64.0.2', 'target_ip': '100.64.0.3'}
            (experiment / 'interval.json').write_text(json.dumps(interval))
            for name, syn in (('before.json', 100), ('after.json', 150)):
                (experiment / name).write_text(json.dumps({'loaded': 1, 'syn': syn, 'drop': 0}))
            with self.workers(directory, adapters=False) as (_, sockets):
                command = [sys.executable, str(ROOT / 'bin/opla-cli.py'), 'report', 'incident',
                           str(experiment), '--via-service', '--lab', 'lab-ABCD']
                result = subprocess.run(command, cwd=temp, env={**os.environ, 'XDG_RUNTIME_DIR': temp},
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report['counters']['metrics']['xdp']['syn'], 50)
                self.assertEqual(report['suricata']['status'], 'unavailable')
                self.assertFalse(report['evidence_quality']['complete_evidence_verified'])
                interval['lab_id'] = 'lab-OTHER'
                (experiment / 'interval.json').write_text(json.dumps(interval))
                result = subprocess.run(command, cwd=temp, env={**os.environ, 'XDG_RUNTIME_DIR': temp},
                                        capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('Traceback', result.stderr)
