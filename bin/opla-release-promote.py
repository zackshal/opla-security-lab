#!/usr/bin/env python3
"""Unprivileged simulation of versioned release promotion; NEVER a root installer.

The trust root is an externally approved digest supplied by the operator.
Do not treat this local simulation as a trusted /opt/opla deployment.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('opla_stage_promote', HERE / 'opla-release-stage.py')
stage_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage_mod)
DIGEST = re.compile(r'[0-9a-f]{64}\Z')


def managed_root(root):
    if os.geteuid() == 0:
        raise ValueError('root execution forbidden: simulation only')
    root = Path(root).absolute()
    if root == Path('/') or not root.parent.exists():
        raise ValueError('invalid review root')
    stage_mod.safe_directory(root.parent)
    parent_st = root.parent.stat()
    if parent_st.st_uid != os.getuid() or parent_st.st_mode & 0o022:
        raise ValueError('review parent must be user-owned and private from group/others')
    if root.is_symlink():
        raise ValueError('review root cannot be symlink')
    if root.exists():
        stage_mod.safe_directory(root)
        st = root.stat()
        if st.st_uid != os.getuid() or st.st_mode & 0o022:
            raise ValueError('review root is not private')
    return root


def promote(bundle, root, expected_sha256):
    if not DIGEST.fullmatch(expected_sha256):
        raise ValueError('SHA-256 must contain 64 lowercase hexadecimal digits')
    root = managed_root(root)
    if not root.exists():
        root.mkdir(mode=0o700)
    release_dir = root / 'releases'
    if not release_dir.exists():
        release_dir.mkdir(mode=0o700)
    stage_mod.safe_directory(release_dir)
    if release_dir.stat().st_uid != os.getuid() or release_dir.stat().st_mode & 0o022:
        raise ValueError('releases directory is not private')
    ident = 'sha256-' + expected_sha256
    target = release_dir / ident
    if target.exists() or target.is_symlink():
        raise ValueError('release already staged; no overwrite permitted')
    # Stage verifies the bundle hash and the embedded member manifest.
    count = stage_mod.stage(bundle, target, expected_sha256)
    current = root / 'current'
    if current.exists() or current.is_symlink():
        # Fail closed rather than replacing unexpected files or external links.
        if not current.is_symlink():
            raise ValueError('current is not a managed symlink')
        old = os.readlink(current)
        if not re.fullmatch(r'releases/sha256-[0-9a-f]{64}', old):
            raise ValueError('current points outside managed releases')
        if not (root / old).is_dir():
            raise ValueError('current points to missing release')
    new_link = root / ('.current-' + expected_sha256)
    if new_link.exists() or new_link.is_symlink():
        raise ValueError('temporary activation link already exists')
    try:
        new_link.symlink_to('releases/' + ident)
        stage_mod._fsync_directory(root)
        os.replace(new_link, current)
        stage_mod._fsync_directory(root)
    finally:
        if new_link.is_symlink():
            new_link.unlink()
    return ident, count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--review-root', required=True)
    parser.add_argument('--expected-sha256', required=True)
    a = parser.parse_args()
    try:
        release, count = promote(a.bundle, a.review_root, a.expected_sha256)
    except (OSError, ValueError) as error:
        parser.exit(2, f'BLOCKED: {error}\n')
    print(f'PASS: review promotion {release} ({count} files); NOT a trusted install')


if __name__ == '__main__':
    main()
