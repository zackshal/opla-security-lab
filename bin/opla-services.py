#!/usr/bin/env python3
"""Inspect service process health. Never starts services or laboratories."""
import argparse
import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import uuid

from opla_service_contract import SERVICES, ServiceEnvelope
from opla_service_runtime import AsyncServiceClient


async def inspect_services(directory):
    async def inspect(name):
        path = directory / f'{name}.sock'
        if not path.exists() and not path.is_symlink():
            return name, {'status': 'NOT_STARTED'}
        try:
            envelope = ServiceEnvelope(name, 'health', uuid.uuid4().hex, 'lab-runtime',
                                       datetime.now(timezone.utc).isoformat(), {}, {})
            result = await AsyncServiceClient(path).dispatch(envelope)
            return name, {'status': 'RESPONDING', **result}
        except (OSError, ValueError, RuntimeError) as exc:
            return name, {'status': 'BLOCKED', 'reason': str(exc)}
    return dict(await asyncio.gather(*(inspect(name) for name in sorted(SERVICES))))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-dir', type=Path)
    args = parser.parse_args()
    directory = args.runtime_dir
    if directory is None:
        runtime = os.environ.get('XDG_RUNTIME_DIR')
        if not runtime:
            parser.error('XDG_RUNTIME_DIR is not set; supply --runtime-dir')
        directory = Path(runtime) / 'opla'
    result = {'schema_version': 1, 'lab_readiness': 'NOT TESTED',
              'services': asyncio.run(inspect_services(directory))}
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 2 if any(item['status'] == 'BLOCKED' for item in result['services'].values()) else 0


if __name__ == '__main__':
    sys.exit(main())
