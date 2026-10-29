"""Built-in evidence API; reuses the existing incident reporter."""
import asyncio
import os
from pathlib import Path
import signal
import sys

from opla_service_runtime import decode
from opla_service_transport import MAX_FRAME

REPORTER_TIMEOUT = 30.0
REPORTER_CLEANUP_TIMEOUT = 1.5
REPORTER_FALLBACK_REAP_TIMEOUT = 0.5
REPORTER_STDERR_LIMIT = 32768


async def _bounded_read(stream, limit):
    data = bytearray()
    while True:
        chunk = await stream.read(min(65536, limit + 1 - len(data)))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
        if len(data) > limit:
            raise ValueError('reporter output exceeds byte limit')


async def _cleanup_reporter(process, readers, *, timeout=REPORTER_CLEANUP_TIMEOUT):
    """Stop the owned process group and join readers/reap within one deadline."""
    failures = []
    # start_new_session makes process.pid the session/process-group ID. The
    # leader may have exited while a reporter child still holds either pipe.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        failures.append(f'killpg failed: {type(exc).__name__}')
        if process.returncode is None:
            try:
                process.kill()
            except OSError as fallback:
                failures.append(f'process kill failed: {type(fallback).__name__}')

    for task in readers:
        if not task.done():
            task.cancel()
    deadline = asyncio.get_running_loop().time() + timeout

    async def bounded(awaitable):
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            close = getattr(awaitable, 'close', None)
            if close is not None:
                close()
            raise TimeoutError
        return await asyncio.wait_for(awaitable, timeout=remaining)

    if readers:
        try:
            await bounded(asyncio.gather(*readers, return_exceptions=True))
        except (TimeoutError, OSError) as exc:
            failures.append(f'reader cleanup failed: {type(exc).__name__}')

    if process.returncode is None:
        try:
            await bounded(process.wait())
        except TimeoutError:
            failures.append('reporter reap timed out')
            try:
                process.kill()
            except OSError as exc:
                failures.append(f'process kill failed: {type(exc).__name__}')
            try:
                await asyncio.wait_for(process.wait(), timeout=REPORTER_FALLBACK_REAP_TIMEOUT)
            except (TimeoutError, OSError) as exc:
                failures.append(f'reporter reap failed: {type(exc).__name__}')
        except OSError as exc:
            failures.append(f'reporter wait failed: {type(exc).__name__}')
            try:
                process.kill()
            except OSError as fallback:
                failures.append(f'process kill failed: {type(fallback).__name__}')
            try:
                await asyncio.wait_for(process.wait(), timeout=REPORTER_FALLBACK_REAP_TIMEOUT)
            except (TimeoutError, OSError) as fallback:
                failures.append(f'reporter reap failed: {type(fallback).__name__}')
    return '; '.join(failures) or None


async def run_reporter(argv, *, spawn=None, timeout=REPORTER_TIMEOUT,
                       stdout_limit=MAX_FRAME, stderr_limit=REPORTER_STDERR_LIMIT,
                       cleanup_timeout=REPORTER_CLEANUP_TIMEOUT):
    """Run one owned reporter child with bounded pipes, cancellation and reap."""
    if spawn is None:
        spawn = asyncio.create_subprocess_exec
    process = await spawn(*argv, stdout=asyncio.subprocess.PIPE,
                          stderr=asyncio.subprocess.PIPE, start_new_session=True)
    readers = [asyncio.create_task(_bounded_read(process.stdout, stdout_limit)),
               asyncio.create_task(_bounded_read(process.stderr, stderr_limit))]
    try:
        async with asyncio.timeout(timeout):
            stdout, stderr = await asyncio.gather(*readers)
            code = await process.wait()
        return code, stdout, stderr
    except BaseException as original:
        cleanup_error = await _cleanup_reporter(process, readers, timeout=cleanup_timeout)
        if cleanup_error:
            if isinstance(original, asyncio.CancelledError):
                original.add_note(f'reporter cleanup incomplete: {cleanup_error}')
            else:
                raise RuntimeError(f'reporter cleanup incomplete: {cleanup_error}') from original
        raise


async def incident_report(envelope):
    if envelope.service != 'opla-evidence' or envelope.operation != 'incident_report':
        raise ValueError('unsupported evidence operation')
    if set(envelope.payload) != {'path'} or not isinstance(envelope.payload['path'], str):
        raise ValueError('incident_report requires exactly one path')
    path = Path(envelope.payload['path'])
    if not path.is_absolute():
        raise ValueError('evidence path must be absolute')
    script = Path(__file__).with_name('opla-incident-report.py')
    code, stdout, _ = await run_reporter([sys.executable, str(script), str(path)])
    if code != 0:
        raise ValueError('incident reporter rejected evidence')
    report = decode(stdout)
    if (not isinstance(report, dict) or not isinstance(report.get('interval'), dict)
            or report['interval'].get('lab_id') != envelope.lab_id):
        raise ValueError('incident evidence lacks matching lab_id')
    return {'lab_id': envelope.lab_id, 'report': report}
