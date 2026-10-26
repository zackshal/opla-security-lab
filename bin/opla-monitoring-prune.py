#!/usr/bin/env python3
"""Explicit purge for the dedicated OPLA Compose monitoring stack.

Fails closed if Docker ownership labels, services, networks, mounts or paths
are unexpected. Does not inspect/remove unrelated GitLab containers or volumes.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

PROJECT = 'opla-monitoring'
SERVICES = {'db', 'server', 'web'}
VOLUME = 'opla-monitoring_db-data'

class Blocked(Exception):
    pass

def docker(*args):
    try:
        p = subprocess.run(['docker', *args], check=False, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Blocked(f'Docker unavailable: {exc}') from exc
    if p.returncode:
        raise Blocked(f'Docker command failed ({args[0]}): {p.stderr.strip()}')
    return p.stdout.strip()

def inspect(kind, name):
    try:
        data = json.loads(docker('inspect', '--type', kind, name))
    except (ValueError, TypeError) as exc:
        raise Blocked('Docker inspect returned invalid JSON') from exc
    if len(data) != 1:
        raise Blocked('unexpected Docker inspect result count')
    return data[0]

def container_ids():
    return [x for x in docker('ps', '-a', '-q', '--filter', f'label=com.docker.compose.project={PROJECT}').splitlines() if x]

def all_container_ids():
    return [x for x in docker('ps', '-a', '-q').splitlines() if x]

def audit(repo, *, docker_api=None):
    """Return validated immutable-ish plan; actual execution rechecks it."""
    global docker
    saved = docker
    if docker_api is not None:
        docker = docker_api
    try:
        return _audit(Path(repo).resolve())
    finally:
        docker = saved

def _audit(repo):
    cfg = repo / 'monitoring' / 'compose.yaml'
    if not cfg.is_file() or cfg.is_symlink() or cfg.read_text().splitlines()[0].strip() != 'name: opla-monitoring':
        raise Blocked('unexpected or missing OPLA Compose configuration')
    project_dir = (repo / 'monitoring').resolve()
    ids = container_ids()
    objects = [inspect('container', item) for item in ids]
    services = {}
    for obj in objects:
        labels = obj.get('Config', {}).get('Labels') or {}
        service = labels.get('com.docker.compose.service')
        config_files = labels.get('com.docker.compose.project.config_files', '').split(',')
        work_dir = labels.get('com.docker.compose.project.working_dir', '')
        if (labels.get('com.docker.compose.project') != PROJECT or
                service not in SERVICES or service in services or
                str(cfg.resolve()) not in config_files or
                not work_dir or Path(work_dir).resolve() != project_dir):
            raise Blocked('container labels/config path not exclusively associated with this OPLA checkout')
        services[service] = obj['Id']
    if set(services) not in (set(), SERVICES):
        raise Blocked('partial Compose service set; manual review required')
    # Check the one allowed database volume: explicitly label-owned by Compose.
    volumes = json.loads(docker('volume', 'ls', '--format', '{{json .}}')) if False else None
    volnames = [x for x in docker('volume', 'ls', '-q', '--filter', f'label=com.docker.compose.project={PROJECT}').splitlines() if x]
    if any(x != VOLUME for x in volnames):
        raise Blocked('unexpected additional project volume')
    volume = None
    if VOLUME in volnames:
        volume = inspect('volume', VOLUME)
        labels = volume.get('Labels') or {}
        if labels.get('com.docker.compose.project') != PROJECT or labels.get('com.docker.compose.volume') != 'db-data':
            raise Blocked('volume ownership labels mismatch')
        if volume.get('Name') != VOLUME or volume.get('Driver') != 'local' or volume.get('Scope') != 'local':
            raise Blocked('unexpected database volume identity/driver/scope')
    if not services and not volume:
        return {'project': PROJECT, 'containers': {}, 'volume': None, 'networks': [], 'orphan_volume': False, 'empty': True}
    # Other containers must not mount our volume; only the expected db may mount it.
    for cid in all_container_ids():
        c = inspect('container', cid)
        if any(m.get('Name') == VOLUME for m in c.get('Mounts', [])):
            if cid not in services.values() or cid != services.get('db'):
                raise Blocked('database volume mounted by an unexpected container')
    if volume and services:
        db = inspect('container', services['db'])
        if not any(m.get('Name') == VOLUME for m in db.get('Mounts', [])):
            raise Blocked('db container does not mount expected database volume')
    # Inspect all networks attributed to this Compose project; do not remove
    # arbitrary networks whose endpoints are not entirely from this project.
    netnames = [x for x in docker('network', 'ls', '-q', '--filter', f'label=com.docker.compose.project={PROJECT}').splitlines() if x]
    networks = []
    for item in netnames:
        net = inspect('network', item)
        lbl = net.get('Labels') or {}
        if lbl.get('com.docker.compose.project') != PROJECT:
            raise Blocked('network project label mismatch')
        attached = set((net.get('Containers') or {}).keys())
        if any(not any(full.startswith(short) or short.startswith(full) for full in services.values()) for short in attached):
            raise Blocked('non-OPLA container attached to project network')
        networks.append(net['Id'])
    # Orphan mode is strictly a single project-labelled local volume: no
    # containers or networks are allowed, and no container may mount the volume.
    orphan = bool(volume and not services and not networks)
    if volume and not services and networks:
        raise Blocked('orphan database volume has remaining project networks; manual review required')
    return {'project': PROJECT, 'containers': services, 'volume': VOLUME if volume else None,
            'networks': sorted(networks), 'orphan_volume': orphan, 'empty': False}

def ensure_no_retained_labs(root=Path('/var/lib/opla')):
    # Global Compose services may be shared across labs; no destructive
    # monitoring operation is authorized while any lab might depend on it.
    registry = root / 'registry'
    if root.is_symlink() or (registry.exists() and registry.is_symlink()):
        raise Blocked('unexpected symlink in OPLA data root')
    if root.exists():
        if not root.is_dir():
            raise Blocked('OPLA data root is not a directory')
        if any(root.glob('lab-*')):
            raise Blocked('lab directories still exist; review monitoring dependencies first')
    if registry.exists() and any(registry.iterdir()):
        raise Blocked('registry is not empty; review dependencies first')


def purge(repo, confirmation, *, check=audit, execute=docker, root=Path('/var/lib/opla')):
    """Delete only the audited resources after confirming the exact mode.

    The caller must not interpret a successful dry-run as permission to purge.
    """
    full_token = f'PURGE:{PROJECT}:{VOLUME}'
    orphan_token = f'PURGE-ORPHAN:{PROJECT}:{VOLUME}'
    if confirmation not in (full_token, orphan_token):
        raise Blocked('explicit confirmation required; see the purge plan for the exact confirmation')
    ensure_no_retained_labs(root)
    plan = check(repo)
    if plan['empty']:
        return plan
    if plan.get('orphan_volume'):
        if confirmation != orphan_token:
            raise Blocked(f'orphan-volume confirmation required: CONFIRM_PURGE={orphan_token}')
        if plan['containers'] or plan['networks'] or plan['volume'] != VOLUME:
            raise Blocked('orphan state unexpectedly includes containers or networks')
        ensure_no_retained_labs(root)
        if check(repo) != plan:
            raise Blocked('Docker resources changed since inspection')
        execute('volume', 'rm', VOLUME)
        return plan
    if confirmation != full_token:
        raise Blocked(f'full-stack confirmation required: CONFIRM_PURGE={full_token}')
    if set(plan['containers']) != SERVICES or plan['volume'] != VOLUME:
        raise Blocked('expected containers and named database volume must all exist')
    if not plan['networks']:
        raise Blocked('Compose project network missing; manual review required')
    ensure_no_retained_labs(root)
    if check(repo) != plan:
        raise Blocked('Docker resources changed since inspection')
    for role in ('web', 'server', 'db'):
        execute('container', 'rm', '-f', plan['containers'][role])
    for network in plan['networks']:
        execute('network', 'rm', network)
    execute('volume', 'rm', VOLUME)
    return plan

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('action', choices=('plan', 'purge'))
    ap.add_argument('--repo', default=str(Path(__file__).resolve().parents[1]))
    ap.add_argument('--confirm', default='')
    args = ap.parse_args(argv)
    try:
        plan = audit(args.repo)
        print(json.dumps(plan, indent=2, ensure_ascii=False))
        if plan.get('orphan_volume'):
            print('Orphan database data detected. Verify backup, then use the separate PURGE-ORPHAN confirmation if deletion is intended.')
        if args.action == 'plan':
            print('READ ONLY. No resource was changed.')
            return 0
        purge(args.repo, args.confirm)
        print('OPLA monitoring resources removed; system packages and other Docker projects untouched.')
    except (Blocked, OSError) as exc:
        print(f'BLOCKED: {exc}', file=sys.stderr)
        return 2
    return 0

if __name__ == '__main__':
    sys.exit(main())
