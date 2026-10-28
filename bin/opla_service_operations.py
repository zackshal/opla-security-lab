"""Built-in evidence API; reuses the existing incident reporter."""
import asyncio
import os
from pathlib import Path
import signal
import sys

from opla_service_runtime import decode
from opla_service_transport import MAX_FRAME


async def _bounded_read(stream, limit):
    data = bytearray()
    while True:
        chunk = await stream.read(min(65536, limit + 1 - len(data)))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
        if len(data) > limit:
            raise ValueError('reporter output exceeds byte limit')


async def incident_report(envelope):
    if envelope.service != 'opla-evidence' or envelope.operation != 'incident_report':
        raise ValueError('unsupported evidence operation')
    if set(envelope.payload) != {'path'} or not isinstance(envelope.payload['path'], str):
        raise ValueError('incident_report requires exactly one path')
    path = Path(envelope.payload['path'])
    if not path.is_absolute():
        raise ValueError('evidence path must be absolute')
    script = Path(__file__).with_name('opla-incident-report.py')
    process = await asyncio.create_subprocess_exec(
        sys.executable, str(script), str(path),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    try:
        async with asyncio.timeout(30):
            stdout, _ = await asyncio.gather(_bounded_read(process.stdout, MAX_FRAME),
                                             _bounded_read(process.stderr, 32768))
            code = await process.wait()
        if code != 0:
            raise ValueError('incident reporter rejected evidence')
        report = decode(stdout)
        if (not isinstance(report, dict) or not isinstance(report.get('interval'), dict)
                or report['interval'].get('lab_id') != envelope.lab_id):
            raise ValueError('incident evidence lacks matching lab_id')
        return {'lab_id': envelope.lab_id, 'report': report}
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if process.returncode is None:
            await process.wait()
