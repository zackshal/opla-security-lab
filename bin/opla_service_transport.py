"""Small local transport for OPLA service envelopes.

The transport is intentionally Unix-domain and line framed.  It has no retry,
no implicit privilege escalation and no network fallback; callers must persist
operation state before dispatching a command.
"""

import json
import socket
from typing import Any


class ServiceTransportError(RuntimeError):
    pass


class JsonLineServiceClient:
    def __init__(self, socket_path: str, *, timeout: float = 5.0):
        if not isinstance(socket_path, str) or not socket_path:
            raise ValueError("socket_path must be non-empty")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("timeout must be positive")
        self.socket_path = socket_path
        self.timeout = float(timeout)

    def dispatch(self, envelope: Any) -> dict[str, Any]:
        if not hasattr(envelope, "as_dict"):
            raise ValueError("envelope must provide as_dict()")
        try:
            wire = json.dumps(envelope.as_dict(), sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ServiceTransportError("envelope is not serializable") from exc
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall((wire + "\n").encode("utf-8"))
                chunks = []
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if b"\n" in chunk:
                        break
        except (OSError, TimeoutError) as exc:
            raise ServiceTransportError(f"service dispatch failed: {exc}") from exc
        raw = b"".join(chunks).split(b"\n", 1)[0]
        if not raw:
            raise ServiceTransportError("service returned empty response")
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ServiceTransportError("service returned malformed JSON") from exc
        if not isinstance(result, dict):
            raise ServiceTransportError("service response must be an object")
        return result
