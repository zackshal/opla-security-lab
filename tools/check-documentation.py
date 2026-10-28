#!/usr/bin/env python3
"""Check local Markdown links and literal CLI examples without executing them."""
import argparse
import importlib.util
from pathlib import Path
import re
import shlex
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def check(paths):
    errors, links, examples = [], 0, 0
    spec = importlib.util.spec_from_file_location('documentation_cli', ROOT / 'bin/opla-cli.py')
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    for path in paths:
        text = path.read_text(encoding='utf-8')
        for match in re.finditer(r'!?\[[^\]\n]*\]\(([^)\n]+)\)', text):
            target = match.group(1).strip().split(' "', 1)[0].strip('<>')
            parsed = urlsplit(target)
            if parsed.scheme or not parsed.path:
                continue
            links += 1
            if not (path.parent / unquote(parsed.path)).exists():
                errors.append(f'{path.relative_to(ROOT)}: missing local link {target}')
        for block in re.findall(r'```(?:bash|sh)\n(.*?)```', text, re.S):
            for line in block.splitlines():
                if not line.strip().startswith('opla '):
                    continue
                arguments = shlex.split(line, comments=True)[1:]
                if arguments and arguments[0] == 'help':
                    arguments = arguments[1:] + ['--help']
                try:
                    parser, _ = cli.build_parser()
                    parsed_args = parser.parse_args(arguments)
                    if parsed_args.group and parsed_args.action:
                        cli.make_command(parsed_args)
                    examples += 1
                except (SystemExit, ValueError) as exc:
                    if isinstance(exc, SystemExit) and exc.code == 0:
                        examples += 1
                    else:
                        errors.append(f'{path.relative_to(ROOT)}: invalid CLI example: {line}')
    return links, examples, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('paths', nargs='*', type=Path)
    args = parser.parse_args()
    paths = args.paths or [ROOT / 'README.md', *sorted((ROOT / 'docs').rglob('*.md')),
                           ROOT / 'assets/demo/services/README.md']
    paths = [path.absolute() for path in paths]
    links, examples, errors = check(paths)
    for error in errors:
        print(error, file=sys.stderr)
    print(f'{len(paths)} Markdown files; {links} local links; {examples} CLI examples; {len(errors)} errors')
    return bool(errors)


if __name__ == '__main__':
    sys.exit(main())
