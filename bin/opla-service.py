#!/usr/bin/env python3
"""Run one OPLA Unix-socket service as the current unprivileged user."""
import argparse
import asyncio
import importlib.util
import os
from pathlib import Path
import signal
import sys

from opla_service_contract import SERVICES
from opla_service_handlers import AdapterServiceHandler
from opla_service_runtime import ServiceServer


async def serve(args):
    handler = None
    if args.service == 'opla-evidence' and args.adapter is None:
        from opla_service_operations import incident_report
        handler = incident_report
    if args.adapter is not None:
        # Explicit code execution by its owner; no implicit plugin discovery.
        path = args.adapter.absolute()
        info = path.lstat()
        if path.is_symlink() or not path.is_file() or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError('adapter must be an owner-controlled regular Python file')
        spec = importlib.util.spec_from_file_location('opla_selected_adapter', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        adapter = module.build_adapter()
        if getattr(adapter, 'mode', None) != 'offline':
            raise ValueError('only explicit offline business adapters are enabled')
        handler = AdapterServiceHandler(args.service, adapter)
    server = ServiceServer(args.service, args.socket, handler=handler, timeout=args.timeout)
    await server.start()
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stopped.set)
    try:
        print(f'LISTENING {args.service} {args.socket}', flush=True)
        await stopped.wait()
    finally:
        await server.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service', required=True, choices=sorted(SERVICES))
    parser.add_argument('--socket', required=True, type=Path)
    parser.add_argument('--adapter', type=Path, help='explicit offline adapter file providing build_adapter()')
    parser.add_argument('--timeout', type=float, default=5)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('run as a regular user; privileged API is not enabled')
    try:
        asyncio.run(serve(args))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f'BLOCKED: {exc}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
