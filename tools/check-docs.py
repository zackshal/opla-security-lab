#!/usr/bin/env python3
"""Check document pairing and local file links without network access."""
from pathlib import Path
import re
import sys
import subprocess
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]


def main():
    errors = []
    listed = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-c', '-o',
        '--exclude-standard', '-z', '--', '*.md'])
    files = sorted({ROOT / name.decode() for name in listed.split(b'\0') if name})
    for file in files:
        relative = file.relative_to(ROOT)
        if relative.as_posix() == 'README.md':
            pair = ROOT / 'README.ru.md'
        elif relative.as_posix() == 'README.ru.md':
            pair = ROOT / 'README.md'
        elif file.name.endswith('.en.md'):
            pair = file.with_name(file.name[:-6] + '.md')
        else:
            pair = file.with_name(file.stem + '.en.md')
        if not pair.is_file():
            errors.append(f'{relative}: missing language pair {pair.name}')
        text = file.read_text()
        # Code fences can contain examples that are not Markdown links.
        prose = re.sub(r'^```[^\n]*\n.*?^```\s*$', '', text, flags=re.M | re.S)
        for match in re.finditer(r'\]\(([^\s)]+)\)', prose):
            url = match[1]
            if url.startswith(('#', 'https:', 'http:', 'mailto:', 'data:')):
                continue
            destination = (file.parent / unquote(url.split('#', 1)[0])).resolve()
            if not destination.is_relative_to(ROOT) or not destination.exists():
                errors.append(f'{relative}: broken local link {url}')
        if not re.search(r'\[Русский\]|\*\*Русский\*\*', prose):
            errors.append(f'{relative}: missing language navigation')
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print(f'PASS: {len(files)} Markdown files, language pairs and local file links')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
