"""Small local transport for OPLA service envelopes.

The transport is intentionally Unix-domain and line framed.  It has no retry,
no implicit privilege escalation and no network fallback; callers must persist
operation state before dispatching a command.
"""

import json
import asyncio
import inspect
import math
import socket
import time
from typing import Any


class ServiceTransportError(RuntimeError):
    pass


MAX_FRAME = 1_048_576


async def _bounded_handler(result):
    return await asyncio.wait_for(result, timeout=5.0)


def _read_frame(connection, limit, timeout):
    deadline = time.monotonic() + timeout
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ServiceTransportError("service frame deadline exceeded")
        connection.settimeout(remaining)
        chunk = connection.recv(min(65536, limit + 1 - len(data)))
        if not chunk:
            raise ServiceTransportError("incomplete service frame")
        data.extend(chunk)
        if len(data) > limit:
            raise ServiceTransportError("service frame too large")
        if b"\n" in data:
            line, trailing = bytes(data).split(b"\n", 1)
            if trailing:
                raise ServiceTransportError("multiple service frames are forbidden")
            return line


class JsonLineServiceClient:
    def __init__(self, socket_path: str, *, timeout: float = 5.0):
        if not isinstance(socket_path, str) or not socket_path:
            raise ValueError("socket_path must be non-empty")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive")
        self.socket_path = socket_path
        self.timeout = float(timeout)

    def dispatch(self, envelope: Any) -> dict[str, Any]:
        if not hasattr(envelope, "as_dict"):
            raise ValueError("envelope must provide as_dict()")
        try:
            wire = json.dumps(envelope.as_dict(), sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ServiceTransportError("envelope is not serializable") from exc
        if len(wire.encode("utf-8")) + 1 > MAX_FRAME:
            raise ServiceTransportError("request frame too large")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall((wire + "\n").encode("utf-8"))
                raw = _read_frame(sock, MAX_FRAME, self.timeout)
        except (OSError, TimeoutError) as exc:
            raise ServiceTransportError(f"service dispatch failed: {exc}") from exc
        if not raw:
            raise ServiceTransportError("service returned empty response")
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ServiceTransportError("service returned malformed JSON") from exc
        if not isinstance(result, dict):
            raise ServiceTransportError("service response must be an object")
        return result


class UnixServiceRouter:
    """Offline-adapter compatible router for independently hosted services."""

    mode = "offline"

    def __init__(self, sockets: dict[str, str], *, timeout: float = 5.0):
        if not isinstance(sockets, dict) or not sockets:
            raise ValueError("sockets must be a non-empty mapping")
        self._clients = {
            service: JsonLineServiceClient(path, timeout=timeout)
            for service, path in sockets.items()
        }

    def dispatch(self, envelope: Any) -> dict[str, Any]:
        service = getattr(envelope, "service", None)
        client = self._clients.get(service)
        if client is None:
            raise ServiceTransportError(f"no socket configured for service: {service}")
        return client.dispatch(envelope)


class JsonLineServiceWorker:
    """Worker-side one-request handler for a dedicated service process."""

    def __init__(self, envelope_type: Any, handler, *, max_frame: int = 1_048_576):
        if not callable(getattr(envelope_type, "from_dict", None)):
            raise ValueError("envelope_type must provide from_dict()")
        if not callable(handler):
            raise ValueError("handler must be callable")
        if isinstance(max_frame, bool) or not isinstance(max_frame, int) or max_frame < 256:
            raise ValueError("max_frame must be an integer >= 256")
        self.envelope_type = envelope_type
        self.handler = handler
        self.max_frame = max_frame

    def process_line(self, raw: bytes) -> bytes:
        if not raw or len(raw) > self.max_frame:
            raise ServiceTransportError("request frame is empty or too large")
        try:
            request = json.loads(raw.decode("utf-8"))
            envelope = self.envelope_type.from_dict(request)
            result = self.handler(envelope)
            if inspect.isawaitable(result):
                result = asyncio.run(_bounded_handler(result))
            if not isinstance(result, dict):
                raise ServiceTransportError("service handler must return an object")
            response = (json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
            if len(response) > self.max_frame:
                raise ServiceTransportError("response frame too large")
            return response
        except ServiceTransportError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
            raise ServiceTransportError("invalid service request") from exc
        except Exception as exc:
            raise ServiceTransportError("service handler failed; reconciliation required") from exc

    def serve_connection(self, connection) -> None:
        """Serve exactly one newline-delimited request on an accepted socket."""
        try:
            line = _read_frame(connection, self.max_frame, 5.0)
            response = self.process_line(line)
        except (ServiceTransportError, OSError) as exc:
            response = json.dumps({"status": "BLOCKED", "error": str(exc)}).encode() + b"\n"
        connection.sendall(response)
