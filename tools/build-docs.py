#!/usr/bin/env python3
"""Совместимый вход: теперь печатные приложения экспортируются вне docs/."""
from pathlib import Path
import subprocess
import sys

if __name__ == '__main__':
    subprocess.run([sys.executable, str(Path(__file__).with_name('export-pdf.py'))], check=True)
