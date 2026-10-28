"""Authenticated local process boundaries for OPLA services.

Runtime health is independent of laboratory readiness. Business adapters are
explicit, user-owned Python plugins, not a sandbox or a privileged API.
"""
import asyncio
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import stat
import struct

from opla_service_contract import SERVICES, ServiceEnvelope
from opla_service_transport import MAX_FRAME, ServiceTransportError

PROTOCOL = 1


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON key')
        value[key] = item
    return value


def decode(raw):
    def reject_constant(value):
        raise ValueError(f'non-finite JSON constant: {value}')
    return json.loads(raw, object_pairs_hook=_object, parse_constant=reject_constant)


def encode(value):
    raw = json.dumps(value, allow_nan=False, separators=(',', ':')).encode() + b'\n'
    if len(raw) > MAX_FRAME:
        raise ValueError('service frame exceeds byte limit')
    return raw


def private_directory(path):
    path = Path(path).absolute()
    for entry in (path, *path.parents):
        if entry.is_symlink():
            raise ValueError('socket directory has symlink ancestor')
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('socket directory must be user-owned and private (0700)')
    return path


def peer_uid(writer):
    connection = writer.get_extra_info('socket')
    if not hasattr(socket, 'SO_PEERCRED'):
        raise ValueError('SO_PEERCRED is required for local service authentication')
    return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def validate_timeout(timeout):
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('service timeout must be finite and positive')


class AsyncServiceClient:
    """One bounded request; no retry or fallback to in-process execution."""

    def __init__(self, socket_path, *, timeout=5.0):
        validate_timeout(timeout)
        self.path = Path(socket_path).absolute()
        self.timeout = timeout

    async def dispatch(self, envelope):
        ServiceEnvelope.from_dict(envelope.as_dict())
        private_directory(self.path.parent)
        info = self.path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ServiceTransportError('unsafe service socket')
        writer = None
        try:
            async with asyncio.timeout(self.timeout):
                reader, writer = await asyncio.open_unix_connection(str(self.path), limit=MAX_FRAME)
                if peer_uid(writer) != os.getuid():
                    raise ServiceTransportError('unexpected service peer UID')
                writer.write(encode(envelope.as_dict()))
                await writer.drain()
                raw = await reader.readuntil(b'\n')
                if len(raw) > MAX_FRAME:
                    raise ServiceTransportError('oversized service response')
                response = decode(raw)
                expected = {'schema_version', 'service', 'operation_id', 'lab_id', 'status', 'result'}
                if not isinstance(response, dict) or set(response) != expected:
                    raise ServiceTransportError('invalid service response fields')
                if (type(response['schema_version']) is not int or response['schema_version'] != PROTOCOL
                        or response['service'] != envelope.service
                        or response['operation_id'] != envelope.operation_id
                        or response['lab_id'] != envelope.lab_id):
                    raise ServiceTransportError('service response identity mismatch')
                if response['status'] != 'OK' or not isinstance(response['result'], dict):
                    raise ServiceTransportError('service blocked request; inspect operation evidence before retry')
                return response['result']
        except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError) as exc:
            raise ServiceTransportError(f'service request failed: {type(exc).__name__}') from exc
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1)
                except (OSError, TimeoutError):
                    pass


class AsyncServiceRouter:
    """Explicit offline adapter for the existing acceptance orchestrator.

    The label is caller intent, not confinement of peer processes or plugins.
    """
    mode = 'offline'

    def __init__(self, sockets, *, timeout=5.0):
        if not isinstance(sockets, dict) or not sockets or set(sockets) - SERVICES:
            raise ValueError('explicit known service sockets are required')
        self.clients = {name: AsyncServiceClient(path, timeout=timeout) for name, path in sockets.items()}

    async def dispatch(self, envelope):
        if envelope.service not in self.clients:
            raise ServiceTransportError('service not configured; no fallback permitted')
        return await self.clients[envelope.service].dispatch(envelope)


class ServiceServer:
    def __init__(self, service, socket_path, *, handler=None, timeout=5.0):
        if service not in SERVICES:
            raise ValueError('unknown service')
        validate_timeout(timeout)
        self.service = service
        self.path = Path(socket_path).absolute()
        self.handler = handler
        self.timeout = timeout
        self.server = None
        self.identity = None
        self.slots = asyncio.Semaphore(8)
        self.connections = set()

    async def start(self):
        private_directory(self.path.parent)
        # Never unlink an existing/stale socket or replace another process.
        if self.path.exists() or self.path.is_symlink():
            raise ValueError('socket already exists; inspect owning process')
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            # Bind directly: asyncio's path= API may unlink an existing socket.
            listener.bind(str(self.path))
            self.path.chmod(0o600)
            info = self.path.lstat()
            self.identity = (info.st_dev, info.st_ino)
            listener.setblocking(False)
            self.server = await asyncio.start_unix_server(self._connection, sock=listener, limit=MAX_FRAME)
        except BaseException:
            listener.close()
            await self.close()
            raise

    async def close(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        for task in list(self.connections):
            task.cancel()
        if self.connections:
            await asyncio.gather(*list(self.connections), return_exceptions=True)
        try:
            info = self.path.lstat()
            if self.identity == (info.st_dev, info.st_ino):
                self.path.unlink()
        except FileNotFoundError:
            pass

    async def _connection(self, reader, writer):
        task = asyncio.current_task()
        self.connections.add(task)
        envelope = None
        try:
            if peer_uid(writer) != os.getuid() or self.slots.locked():
                return
            async with self.slots, asyncio.timeout(self.timeout):
                raw = await reader.readuntil(b'\n')
                if len(raw) > MAX_FRAME:
                    raise ValueError('request exceeds byte limit')
                envelope = ServiceEnvelope.from_dict(decode(raw))
                if envelope.service != self.service:
                    raise ValueError('wrong service boundary')
                if envelope.operation == 'health':
                    result = {'service': self.service, 'pid': os.getpid(), 'uid': os.getuid(),
                              'protocol': PROTOCOL, 'business_adapter': self.handler is not None,
                              'runtime_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                              'lab_readiness': 'NOT TESTED'}
                else:
                    if self.handler is None:
                        raise ValueError('business adapter not configured')
                    result = await self.handler(envelope)
                if not isinstance(result, dict):
                    raise ValueError('handler must return an object')
                await self._reply(writer, envelope, 'OK', result)
        except Exception:
            # No traceback, secrets or arbitrary exception text on the wire.
            if envelope is not None:
                try:
                    await self._reply(writer, envelope, 'BLOCKED', {})
                except (OSError, ValueError, TimeoutError):
                    pass
        finally:
            writer.close()
            self.connections.discard(task)

    async def _reply(self, writer, envelope, status, result):
        writer.write(encode({'schema_version': PROTOCOL, 'service': self.service,
                             'operation_id': envelope.operation_id, 'lab_id': envelope.lab_id,
                             'status': status, 'result': result}))
        await asyncio.wait_for(writer.drain(), timeout=1)
