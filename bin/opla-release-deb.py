#!/usr/bin/env python3
"""Build an inert Debian package from an independently pinned OPLA source bundle.

No root use, no lifecycle actions, no maintainer scripts, no 'current' symlink.
Installing/activating packages is an independent administrator-controlled step.
"""
import argparse
import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    'opla_stage_for_deb', HERE / 'opla-release-stage.py'
)
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)

SHA = re.compile(r'[0-9a-f]{64}\Z')
EXECUTABLES = {
    'bootstrap.sh',
    'bin/create-lab.sh',
    'bin/opla-lab-configure.sh'
}
MAX_DEB = 40 * 1024 * 1024


def build(bundle, expected, output):
    if os.geteuid() == 0:
        raise ValueError('root execution forbidden')

    if not isinstance(expected, str) or not SHA.fullmatch(expected):
        raise ValueError('expected lowercase SHA-256 required')

    output = Path(output).absolute()

    if output.exists() or output.is_symlink():
        raise ValueError('output exists')

    stage.safe_directory(output.parent)

    if (
        output.parent.stat().st_uid != os.getuid()
        or output.parent.stat().st_mode & 0o022
    ):
        raise ValueError('output parent must be private and user-owned')

    ident = expected[:16]
    package_name = 'opla-code-' + ident

    with tempfile.TemporaryDirectory(
        prefix='.opla-deb-', dir=output.parent
    ) as tmp:
        tmp = Path(tmp)
        staged = tmp / 'stage'

        count = stage.stage(bundle, staged, expected)

        pkg = tmp / 'pkg'
        destination = (
            pkg / 'opt' / 'opla' / 'releases'
            / ('sha256-' + expected)
        )
        destination.mkdir(parents=True)

        # All package directories must be non-writable by group/others.
        for parent in (
            pkg,
            pkg / "opt",
            pkg / "opt" / "opla",
            pkg / "opt" / "opla" / "releases",
            destination,
        ):
            parent.chmod(0o755)

        # The extracted tree has already been verified.
        # Copy without symbolic links.
        for src in sorted(staged.rglob('*')):
            if src.name == 'REVIEW.json':
                continue

            rel = src.relative_to(staged)
            dest = destination / rel

            if src.is_symlink():
                raise ValueError('symlink in staged code')

            if src.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
                dest.chmod(0o755)

            elif src.is_file():
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, dest)
                dest.chmod(
                    0o755 if rel.as_posix() in EXECUTABLES
                    else 0o644
                )
            else:
                raise ValueError('unexpected staged file type')

        # No postinst/prerm: package installation must not run code.
        control_dir = pkg / 'DEBIAN'
        control_dir.mkdir()

        (control_dir / 'control').write_text(
            f'Package: {package_name}\n'
            'Version: 0.0.1\n'
            'Section: admin\n'
            'Priority: optional\n'
            'Architecture: all\n'
            'Maintainer: OPLA local review <root@localhost>\n'
            'Description: Inert OPLA code release (not activated)\n'
        )

        result = subprocess.run(
            [
                'dpkg-deb',
                '--root-owner-group',
                '--build',
                str(pkg),
                str(output),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        if result.returncode != 0:
            output.unlink(missing_ok=True)
            raise ValueError(
                'dpkg-deb failed: ' + result.stderr[-500:]
            )

        if output.stat().st_size > MAX_DEB:
            output.unlink(missing_ok=True)
            raise ValueError('output exceeds size limit')

    return count, package_name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()

    try:
        count, package = build(
            args.bundle,
            args.expected_sha256,
            args.output,
        )
    except (
        OSError,
        ValueError,
        subprocess.TimeoutExpired,
        tarfile.TarError,
    ) as exc:
        parser.exit(2, f'BLOCKED: {exc}\n')

    print(
        f'PASS: built inert package {package} '
        f'({count} files); NOT INSTALLED'
    )


if __name__ == '__main__':
    main()
