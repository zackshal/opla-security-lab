#!/usr/bin/env python3
"""Install an explicitly approved local snapshot; never provision a laboratory.

The digest is operator approval of local bytes, not publisher authentication.
Existing installations are never overwritten.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

EXCLUDED = {'.git', '.venv', '.venv-docs', '__pycache__', '.codex', '.agents', '.aws', 'root'}


def inventory(source):
    source = Path(source).absolute()
    records = []
    for base, dirs, files in os.walk(source, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED)
        for name in dirs + sorted(files):
            path = Path(base) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise ValueError(f'unsupported source entry: {path}')
            if path.is_file():
                with path.open('rb') as stream:
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                records.append([str(path.relative_to(source)), digest, bool(info.st_mode & 0o111)])
    records.sort()
    if not {'Makefile', 'bin/opla-cli.py', 'bin/opla-create-launcher.py'} <= {r[0] for r in records}:
        raise ValueError('source is not a complete OPLA tree')
    return hashlib.sha256(json.dumps(records, separators=(',', ':')).encode()).hexdigest(), records


def install(source, destination, expected):
    source, destination = Path(source).absolute(), Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError('destination already exists; no overwrite permitted')
    if source == destination or source in destination.parents:
        raise ValueError('destination cannot be inside source')
    digest, records = inventory(source)
    if digest != expected:
        raise ValueError('source changed or approved digest mismatch')
    staging = Path(tempfile.mkdtemp(prefix='.opla-install-', dir=destination.parent))
    try:
        for relative, approved, executable in records:
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with (source / relative).open('rb') as incoming, target.open('xb') as outgoing:
                shutil.copyfileobj(incoming, outgoing)
            with target.open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != approved:
                    raise ValueError(f'source changed during copy: {relative}')
            target.chmod(0o755 if executable else 0o644)
        for base, _, _ in os.walk(staging):
            Path(base).chmod(0o755)
        # mkdir reserves the exact target without overwriting any concurrent install.
        destination.mkdir(mode=0o755)
        try:
            for child in staging.iterdir():
                child.rename(destination / child.name)
        except BaseException:
            # Only the directory exclusively reserved above belongs to this attempt.
            shutil.rmtree(destination)
            raise
    finally:
        shutil.rmtree(staging)
    return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--destination', type=Path, default=Path('/opt/opla'))
    parser.add_argument('--expected-sha256')
    parser.add_argument('--install', action='store_true')
    args = parser.parse_args()
    try:
        if not args.install:
            print(inventory(args.source)[0])
            return
        if os.geteuid() != 0:
            raise ValueError('system installation requires root')
        if not args.expected_sha256:
            raise ValueError('--expected-sha256 is required')
        for parent in (args.destination.absolute().parent, *args.destination.absolute().parent.parents):
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError(f'untrusted installation parent: {parent}')
        print('Installed local snapshot:', install(args.source, args.destination, args.expected_sha256))
        print('No lab created. Register user CLI: python3 /opt/opla/bin/opla-cli-install.py install')
    except (OSError, ValueError) as exc:
        parser.exit(2, f'BLOCKED: {exc}\n')


if __name__ == '__main__':
    main()
