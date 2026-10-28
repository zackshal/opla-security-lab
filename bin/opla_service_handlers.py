"""Service-bound handlers backed by the existing offline adapter contract."""

from typing import Any


SERVICE_STEPS = {
    "opla-host-backend": frozenset({"preflight", "create"}),
    "opla-guest-agent": frozenset({"configure", "health", "scenario"}),
    "opla-evidence": frozenset({"telemetry", "report"}),
    "opla-monitoring": frozenset({"publish"}),
    "opla-control": frozenset(),
}


class ServiceHandlerError(ValueError):
    pass


class AdapterServiceHandler:
    """Expose one adapter through exactly one service boundary.

    The adapter remains injected for offline acceptance; a worker process can
    construct this handler around an adapter implemented by that service.
    """

    def __init__(self, service: str, adapter: Any):
        if service not in SERVICE_STEPS:
            raise ServiceHandlerError("unknown service")
        if not hasattr(adapter, "execute") or not hasattr(adapter, "probe"):
            raise ServiceHandlerError("adapter must provide execute and probe")
        self.service = service
        self.adapter = adapter

    async def __call__(self, envelope):
        if envelope.service != self.service:
            raise ServiceHandlerError("envelope service does not match handler")
        step = envelope.payload.get("step")
        if step not in SERVICE_STEPS[self.service]:
            raise ServiceHandlerError("step is outside service boundary")
        method_name = envelope.operation
        if method_name not in {"execute", "probe"}:
            raise ServiceHandlerError("unsupported service operation")
        result = await getattr(self.adapter, method_name)(step, envelope.lab_id)
        if not isinstance(result, dict) or result.get("lab_id") != envelope.lab_id:
            raise ServiceHandlerError("adapter returned invalid identity-bound result")
        return result
