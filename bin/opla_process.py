"""Bounded local subprocess execution for OPLA adapters and collectors."""

from __future__ import annotations

import math
import os
import selectors
import signal
import subprocess
import time


TERMINATION_GRACE_SECONDS = 2.0


def _group_exists(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def terminate_owned_group(process, *, grace=TERMINATION_GRACE_SECONDS):
    """TERM, then KILL and reap the child session; report unresolved state."""
    errors = []
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError as exc:
        errors.append(f"SIGTERM: {type(exc).__name__}")
        try:
            process.terminate()
        except OSError as fallback:
            errors.append(f"terminate: {type(fallback).__name__}")

    deadline = time.monotonic() + grace
    while time.monotonic() < deadline and _group_exists(process.pid):
        try:
            process.wait(timeout=min(0.05, max(0.001, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            pass
        except OSError as exc:
            errors.append(f"wait: {type(exc).__name__}")
            break
        time.sleep(0.01)

    if _group_exists(process.pid):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            errors.append(f"SIGKILL: {type(exc).__name__}")
            try:
                process.kill()
            except OSError as fallback:
                errors.append(f"kill: {type(fallback).__name__}")
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
    except (subprocess.TimeoutExpired, OSError) as exc:
        errors.append(f"reap: {type(exc).__name__}")
    try:
        if _group_exists(process.pid):
            errors.append("process group remains after termination and reap")
    except OSError as exc:
        errors.append(f"final group check: {type(exc).__name__}")
    return "; ".join(errors) or None


def _positive_finite(value, name):
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value <= 0):
        raise ValueError(f"{name} must be finite and positive")


def run_bounded(argv, *, cwd=None, env=None, timeout=30,
                max_output_bytes=16 * 1024, popen_factory=None):
    """Capture bounded stdout/stderr and own the local process group.

    An output-limit hit returns a CompletedProcess with `output_limited=True`.
    A timeout or interruption terminates the process group and re-raises the
    original exception, attaching any cleanup uncertainty.
    """
    _positive_finite(timeout, "process timeout")
    if (isinstance(max_output_bytes, bool) or not isinstance(max_output_bytes, int)
            or max_output_bytes <= 0):
        raise ValueError("process output limit must be a positive integer")

    dispatch = subprocess.Popen if popen_factory is None else popen_factory
    process = dispatch(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    selector = selectors.DefaultSelector()
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)

    deadline = time.monotonic() + timeout
    output_limited = False
    cleanup_error = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            for key, _ in selector.select(min(remaining, 0.1)):
                stream = key.fileobj
                captured = streams[stream]
                chunk = os.read(
                    stream.fileno(),
                    min(65536, max_output_bytes - len(captured) + 1),
                )
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                room = max_output_bytes - len(captured)
                captured.extend(chunk[:room])
                if len(chunk) > room:
                    output_limited = True
                    cleanup_error = terminate_owned_group(process)
                    break
            if output_limited:
                break
        if not output_limited:
            remaining = max(0.001, deadline - time.monotonic())
            returncode = process.wait(timeout=remaining)
    except BaseException as exc:
        cleanup_error = terminate_owned_group(process)
        exc.stdout = streams[process.stdout].decode("utf-8", "replace")
        exc.stderr = streams[process.stderr].decode("utf-8", "replace")
        if cleanup_error:
            exc.cleanup_error = cleanup_error
        raise
    finally:
        selector.close()
        for stream in streams:
            if not stream.closed:
                stream.close()

    if output_limited:
        returncode = process.returncode if process.returncode is not None else 1
    result = subprocess.CompletedProcess(
        argv,
        returncode,
        streams[process.stdout].decode("utf-8", "replace"),
        streams[process.stderr].decode("utf-8", "replace"),
    )
    result.output_limited = output_limited
    if cleanup_error:
        result.cleanup_error = cleanup_error
    return result
