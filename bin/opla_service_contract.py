"""Versioned, identity-bound envelope shared by OPLA service adapters.

This module is deliberately transport-neutral.  Phase 0 uses it with injected
Python adapters; a later local Unix-socket transport can serialize the same
contract without changing lifecycle semantics.
"""

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Any


SCHEMA_VERSION = 1
SERVICES = frozenset(
    {
        "opla-control",
        "opla-host-backend",
        "opla-guest-agent",
        "opla-evidence",
        "opla-monitoring",
    }
)
_LAB_ID = re.compile(r"^lab-[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


@dataclass(frozen=True)
class ServiceEnvelope:
    service: str
    operation: str
    operation_id: str
    lab_id: str
    requested_at: str
    payload: dict[str, Any]
    evidence: dict[str, Any]
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported service envelope schema")
        if not isinstance(self.service, str) or self.service not in SERVICES:
            raise ValueError("unknown service")
        _nonempty_string(self.operation, "operation")
        if not isinstance(self.operation_id, str) or not _OPERATION_ID.fullmatch(self.operation_id):
            raise ValueError("invalid operation_id")
        if not isinstance(self.lab_id, str) or not _LAB_ID.fullmatch(self.lab_id):
            raise ValueError("invalid lab_id")
        try:
            parsed = datetime.fromisoformat(self.requested_at.replace("Z", "+00:00"))
        except (AttributeError, ValueError):
            raise ValueError("requested_at must be an ISO-8601 timestamp") from None
        if parsed.tzinfo is None:
            raise ValueError("requested_at must include timezone")
        if not isinstance(self.payload, dict) or not isinstance(self.evidence, dict):
            raise ValueError("payload and evidence must be objects")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "service": self.service,
            "operation": self.operation,
            "operation_id": self.operation_id,
            "lab_id": self.lab_id,
            "requested_at": self.requested_at,
            "payload": self.payload,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ServiceEnvelope":
        if not isinstance(value, dict):
            raise ValueError("service envelope must be an object")
        required = {
            "schema_version",
            "service",
            "operation",
            "operation_id",
            "lab_id",
            "requested_at",
            "payload",
            "evidence",
        }
        if set(value) != required:
            raise ValueError("service envelope fields are not exact")
        return cls(**value)
