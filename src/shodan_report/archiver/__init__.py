"""
Archivierungsmodule für Shodan Report.

Dieses Paket bietet revisionssichere Archivierung gemäß README-Spezifikation:
- archive/{customer_slug}/{YYYY-MM}/{YYYY-MM}_{ip}_v{N}.pdf
- archive/{customer_slug}/{YYYY-MM}/{YYYY-MM}_{ip}.meta.json
"""

from .snapshot_archiver import (
    archive_snapshot,
    list_archived_snapshots,
    retrieve_archived_snapshot,
    _customer_dir
)

from shodan_report.archiver.report_archiver import ReportArchiver
from shodan_report.archiver.version_manager import VersionManager

__all__ = [
    'archive_snapshot',
    'list_archived_snapshots', 
    'retrieve_archived_snapshot',
    '_customer_dir',
    'ReportArchiver',
    'VersionManager',
]