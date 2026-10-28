"""Synthetic business operations for process-level acceptance only."""
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('fixture_service_orchestrator', ROOT / 'bin/opla-lab-orchestrator.py')
orchestrator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = orchestrator
spec.loader.exec_module(orchestrator)


class FixtureAdapter:
    mode = 'offline'

    async def execute(self, step, lab_id):
        return {'lab_id': lab_id, 'synthetic': True, 'step': step}

    async def probe(self, step, lab_id):
        return {'lab_id': lab_id, 'synthetic': True,
                **dict.fromkeys(orchestrator.REQUIRED_PROBES[step], True)}


def build_adapter():
    return FixtureAdapter()
