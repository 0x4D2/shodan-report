"""Zentrale Pfad-Konfiguration.

Alle Ausgabeverzeichnisse (reports, snapshots, archive, cache) werden relativ
zu OUTPUT_BASE_DIR aufgelöst. Ist OUTPUT_BASE_DIR nicht gesetzt, wird das
aktuelle Arbeitsverzeichnis (CWD) verwendet – identisches Verhalten wie vorher.

.env-Beispiel:
    OUTPUT_BASE_DIR=C:/Users/x/x/x/Code/shodan-report
"""

from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()


def _base() -> Path:
    base = os.environ.get("OUTPUT_BASE_DIR")
    return Path(base) if base else Path.cwd()


def reports_dir() -> Path:
    return _base() / "reports"


def snapshots_dir() -> Path:
    return _base() / "snapshots"


def archive_dir() -> Path:
    return _base() / "archive"


def cache_dir() -> Path:
    return _base() / ".cache"
