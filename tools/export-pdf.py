#!/usr/bin/env python3
"""Compatibility entry point for the canonical GOST PDF exporter."""
from pathlib import Path
import runpy

runpy.run_path(str(Path(__file__).with_name('export-pdf-gost.py')), run_name='__main__')
