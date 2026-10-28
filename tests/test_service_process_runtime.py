"""Real local sockets/processes; business operations use synthetic adapters."""
import asyncio
from contextlib import contextmanager
from datetime import datetime, timezone
import errno
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
from opla_service_contract import ServiceEnvelope
from opla_service_runtime import AsyncServiceClient, AsyncServiceRouter, ServiceServer, decode
from opla_service_transport import ServiceTransportError
import opla_service_operations as service_operations

spec = importlib.util.spec_from_file_location('process_test_orchestrator', ROOT / 'bin/opla-lab-orchestrator.py')
orchestrator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = orchestrator
spec.loader.exec_module(orchestrator)


def request(service='opla-host-backend', operation='health', step=None):
    return ServiceEnvelope(service, operation, 'test-operation', 'lab-ABCD',
                           datetime.now(timezone.utc).isoformat(),
                           {} if step is None else {'step': step}, {})


def require_unix_socket_support(test_case):
    """Mark socket acceptance blocked when this sandbox denies local AF_UNIX."""
    with tempfile.TemporaryDirectory() as temp:
        probe_path = Path(temp) / 'capability.sock'
        probe = None
        try:
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.bind(str(probe_path))
        except PermissionError as exc:
            if exc.errno == errno.EPERM:
                test_case.skipTest('sandbox denies AF_UNIX create/bind (EPERM); socket runtime not tested')
            raise
        finally:
            if probe is not None:
                probe.close()


class SocketCapabilityTests(unittest.TestCase):
    def test_creation_denied_is_explicit_skip(self):
        with patch.object(socket, 'socket', side_effect=PermissionError(errno.EPERM, 'denied')):
            with self.assertRaisesRegex(unittest.SkipTest, 'socket runtime not tested'):
                require_unix_socket_support(self)

    def test_bind_denied_closes_probe(self):
        with patch.object(socket, 'socket') as factory:
            factory.return_value.bind.side_effect = PermissionError(errno.EPERM, 'denied')
            with self.assertRaises(unittest.SkipTest):
                require_unix_socket_support(self)
            factory.return_value.close.assert_called_once_with()

    def test_unexpected_error_is_not_hidden(self):
        with patch.object(socket, 'socket', side_effect=OSError(errno.EMFILE, 'too many files')):
            with self.assertRaises(OSError) as error:
                require_unix_socket_support(self)
            self.assertEqual(error.exception.errno, errno.EMFILE)


class ServiceRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        require_unix_socket_support(self)
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

class ServiceDecodeTests(unittest.TestCase):
    def test_duplicate_keys_and_nonfinite_values_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.assertRaises(ValueError):
                decode(raw)


class ReporterSupervisorTests(unittest.IsolatedAsyncioTestCase):
    class Stream:
        def __init__(self, chunks=(), *, block=False):
            self.chunks = list(chunks)
            self.block = block
            self.cancelled = False
            self._blocked = asyncio.Event()

        async def read(self, size):
            if self.chunks:
                return self.chunks.pop(0)
            if self.block:
                try:
                    await self._blocked.wait()
                finally:
                    self.cancelled = True
            return b''

    class Process:
        pid = 424242

        def __init__(self, stdout=None, stderr=None, *, wait_blocks=True):
            self.stdout = stdout or ReporterSupervisorTests.Stream(block=True)
            self.stderr = stderr or ReporterSupervisorTests.Stream(block=True)
            self.returncode = None
            self.wait_blocks = wait_blocks
            self.wait_count = 0
            self.kill_count = 0
            self._done = asyncio.Event()

        async def wait(self):
            self.wait_count += 1
            if self.wait_blocks:
                await self._done.wait()
            return self.returncode

        def kill(self):
            self.kill_count += 1
            self.returncode = -9
            self._done.set()

    async def spawn_fake(self, process):
        async def spawn(*argv, **kwargs):
            self.assertEqual(kwargs['start_new_session'], True)
            return process
        return spawn

    async def test_spawn_failure_is_not_retried(self):
        spawn = AsyncMock(side_effect=OSError('spawn denied'))
        with self.assertRaisesRegex(OSError, 'spawn denied'):
            await service_operations.run_reporter(['reporter'], spawn=spawn)
        spawn.assert_awaited_once()

    async def test_stdout_overflow_kills_child_and_cancels_other_reader(self):
        stdout = self.Stream([b'12345'])
        stderr = self.Stream(block=True)
        process = self.Process(stdout, stderr)
        spawn = await self.spawn_fake(process)
        with patch.object(service_operations.os, 'killpg', side_effect=lambda *_: process.kill()):
            with self.assertRaisesRegex(ValueError, 'byte limit'):
                await service_operations.run_reporter(
                    ['reporter'], spawn=spawn, stdout_limit=4, cleanup_timeout=0.1)
        self.assertEqual(process.returncode, -9)
        self.assertTrue(stderr.cancelled)
        self.assertEqual(process.wait_count, 0)  # the fake group kill reaped it directly

    async def test_stderr_overflow_kills_child_and_cancels_other_reader(self):
        stdout = self.Stream(block=True)
        stderr = self.Stream([b'12345'])
        process = self.Process(stdout, stderr)
        spawn = await self.spawn_fake(process)
        with patch.object(service_operations.os, 'killpg', side_effect=lambda *_: process.kill()):
            with self.assertRaisesRegex(ValueError, 'byte limit'):
                await service_operations.run_reporter(
                    ['reporter'], spawn=spawn, stderr_limit=4, cleanup_timeout=0.1)
        self.assertTrue(stdout.cancelled)
        self.assertEqual(process.returncode, -9)

    async def test_timeout_kills_and_boundedly_reaps_child(self):
        process = self.Process()
        spawn = await self.spawn_fake(process)
        with patch.object(service_operations.os, 'killpg', side_effect=lambda *_: process.kill()) as killpg:
            with self.assertRaises(TimeoutError):
                await service_operations.run_reporter(
                    ['reporter'], spawn=spawn, timeout=0.01, cleanup_timeout=0.1)
        killpg.assert_called_once_with(process.pid, service_operations.signal.SIGKILL)
        self.assertEqual(process.returncode, -9)
        self.assertTrue(process.stdout.cancelled)
        self.assertTrue(process.stderr.cancelled)

    async def test_real_owned_child_timeout_is_reaped(self):
        spawned = []
        async def spawn(*argv, **kwargs):
            process = await asyncio.create_subprocess_exec(*argv, **kwargs)
            spawned.append(process)
            return process
        with self.assertRaises(TimeoutError):
            await service_operations.run_reporter(
                [sys.executable, '-c', 'import time; time.sleep(30)'],
                spawn=spawn, timeout=0.1, cleanup_timeout=1.0)
        self.assertEqual(len(spawned), 1)
        self.assertIsNotNone(spawned[0].returncode)

    async def test_timeout_kills_owned_group_after_reporter_leader_exits(self):
        if not Path('/proc/self/stat').exists():
            self.skipTest('Linux /proc process state required for orphan assertion')
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            pid_file = directory / 'child.pid'
            helper = directory / 'spawn-child.py'
            helper.write_text(
                'import pathlib, subprocess, sys\n'
                'child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])\n'
                'pathlib.Path(sys.argv[1]).write_text(str(child.pid))\n'
            )
            spawned = []
            async def spawn(*argv, **kwargs):
                process = await asyncio.create_subprocess_exec(*argv, **kwargs)
                spawned.append(process)
                return process
            with self.assertRaises(TimeoutError):
                await service_operations.run_reporter(
                    [sys.executable, str(helper), str(pid_file)],
                    spawn=spawn, timeout=0.15, cleanup_timeout=1.0)
            child_pid = int(pid_file.read_text())
            self.assertEqual(len(spawned), 1)
            self.assertEqual(spawned[0].returncode, 0)  # leader exited before pipe timeout
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    state = Path(f'/proc/{child_pid}/stat').read_text().split()[2]
                except (FileNotFoundError, ProcessLookupError):
                    break
                if state == 'Z':
                    break
                await asyncio.sleep(0.02)
            else:
                self.fail('owned descendant survived process-group cleanup')

    async def test_cancellation_stops_child_before_propagating(self):
        process = self.Process()
        spawn = await self.spawn_fake(process)
        with patch.object(service_operations.os, 'killpg', side_effect=lambda *_: process.kill()) as killpg:
            task = asyncio.create_task(service_operations.run_reporter(
                ['reporter'], spawn=spawn, timeout=5, cleanup_timeout=0.1))
            await asyncio.sleep(0.01)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        killpg.assert_called_once()
        self.assertEqual(process.returncode, -9)

    async def test_killpg_error_uses_direct_fallback_and_reports_uncertainty(self):
        process = self.Process()
        spawn = await self.spawn_fake(process)
        with patch.object(service_operations.os, 'killpg', side_effect=PermissionError):
            with self.assertRaisesRegex(RuntimeError, 'killpg failed'):
                await service_operations.run_reporter(
                    ['reporter'], spawn=spawn, timeout=0.01, cleanup_timeout=0.1)
        self.assertEqual(process.kill_count, 1)
        self.assertEqual(process.returncode, -9)

    async def test_reap_deadline_falls_back_without_hanging(self):
        process = self.Process(wait_blocks=True)
        spawn = await self.spawn_fake(process)
        start = time.monotonic()
        with patch.object(service_operations.os, 'killpg'):
            with self.assertRaisesRegex(RuntimeError, 'reap timed out'):
                await service_operations.run_reporter(
                    ['reporter'], spawn=spawn, timeout=0.01, cleanup_timeout=0.02)
        self.assertLess(time.monotonic() - start, 0.2)
        self.assertEqual(process.kill_count, 1)
        self.assertEqual(process.returncode, -9)
        self.assertGreaterEqual(process.wait_count, 2)  # includes a post-fallback-kill reap

    async def test_wait_oserror_still_uses_direct_kill_and_reap(self):
        class WaitErrorProcess(self.Process):
            async def wait(self):
                self.wait_count += 1
                if self.wait_count <= 2:
                    raise OSError('wait interrupted')
                await self._done.wait()
                return self.returncode
        process = WaitErrorProcess()
        spawn = await self.spawn_fake(process)
        with patch.object(service_operations.os, 'killpg'):
            with self.assertRaisesRegex(RuntimeError, 'reporter wait failed'):
                await service_operations.run_reporter(
                    ['reporter'], spawn=spawn, timeout=0.1, cleanup_timeout=0.1)
        self.assertEqual(process.kill_count, 1)
        self.assertEqual(process.returncode, -9)

    async def test_nonzero_reporter_exit_is_rejected_without_retry(self):
        envelope = ServiceEnvelope('opla-evidence', 'incident_report', 'test-operation', 'lab-ABCD',
                                    datetime.now(timezone.utc).isoformat(), {'path': '/tmp/evidence'}, {})
        run = AsyncMock(return_value=(7, b'{}', b'private child error'))
        with patch.object(service_operations, 'run_reporter', run):
            with self.assertRaisesRegex(ValueError, 'rejected evidence'):
                await service_operations.incident_report(envelope)
        run.assert_awaited_once()


@unittest.skipIf(os.geteuid() == 0, 'service executable intentionally refuses root; run unprivileged')
class ServiceProcessAcceptanceTests(unittest.TestCase):
    def setUp(self):
        require_unix_socket_support(self)

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
