"""
Revisionssichere Report-Archivierung gemäß README-Spezifikation.
"""

from calendar import month
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import tempfile
import shutil

from shodan_report.utils.slug import create_slug
from shodan_report.archiver.version_manager import VersionManager


class ReportArchiver:
    """
    Spezifikation:
    - archive/{customer_slug}/{YYYY-MM}/{YYYY-MM}_{ip}_v{N}.pdf
    - archive/{customer_slug}/{YYYY-MM}/{YYYY-MM}_{ip}.meta.json
    """

    def __init__(self, archive_root: Path = Path("archive")):

        self.archive_root = archive_root
        self.archive_root.mkdir(parents=True, exist_ok=True)
        self.version_manager = VersionManager(archive_root)

        # debug
        # print(f"[DEBUG] VersionManager methods: {dir(self.version_manager)}")
        # print(f"[DEBUG] Has get_next_version? {'get_next_version' in dir(self.version_manager)}")

    def archive_report(
        self,
        pdf_path: Path,
        customer_name: str,
        month: str,
        ip: str,
        extra_metadata: Optional[Dict] = None,
    ) -> Dict[str, Any]:

        # Validierung
        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF nicht gefunden: {pdf_path}")

        if not self._is_valid_month(month):
            raise ValueError(f"Ungültiges Monatsformat: {month}. Erwartet: YYYY-MM")

        # Slug erstellen
        customer_slug = create_slug(customer_name)

        # Ziel-Verzeichnis erstellen
        target_dir = self.archive_root / customer_slug / month
        target_dir.mkdir(parents=True, exist_ok=True)

        # Basis-Dateiname und Version
        base_filename = f"{month}_{ip}"
        try:
            version = self.version_manager.get_next_version(customer_slug, month, ip)
        except AttributeError:
            # Fallback: Manuell berechnen
            version = self._manual_get_next_version(customer_slug, month, base_filename)

        # PDF mit Version kopieren (atomar)
        target_pdf = target_dir / f"{base_filename}_v{version}.pdf"
        self._atomic_copy(pdf_path, target_pdf)

        # Metadaten berechnen
        metadata = self._create_metadata(
            pdf_path=target_pdf,
            customer_name=customer_name,
            customer_slug=customer_slug,
            month=month,
            ip=ip,
            version=version,
            extra_metadata=extra_metadata,
        )

        # Metadaten speichern/aktualisieren
        self._save_metadata(target_dir, base_filename, metadata, version)

        return metadata

    def find_previous_report(
        self, customer_name: str, month: str, ip: str
    ) -> Optional[Dict[str, Any]]:

        customer_slug = create_slug(customer_name)
        customer_dir = self.archive_root / customer_slug

        if not customer_dir.exists():
            return None

        # Alle vorherigen Monate finden (absteigend sortiert)
        previous_months = sorted(
            [
                d.name
                for d in customer_dir.iterdir()
                if d.is_dir() and d.name < month and self._is_valid_month(d.name)
            ],
            reverse=True,
        )

        for prev_month in previous_months:
            metadata = self.version_manager.get_metadata(
                customer_slug=customer_slug,
                month=prev_month,
                base_filename=f"{prev_month}_{ip}",
            )

            if metadata:
                return metadata

        return None

    def list_customer_reports(self, customer_name: str) -> Dict[str, Any]:
        customer_slug = create_slug(customer_name)
        customer_dir = self.archive_root / customer_slug

        reports = []

        if customer_dir.exists():
            for month_dir in sorted(customer_dir.iterdir()):
                if month_dir.is_dir() and self._is_valid_month(month_dir.name):
                    month_reports = []

                    for meta_file in month_dir.glob("*.meta.json"):
                        try:
                            with meta_file.open("r", encoding="utf-8") as f:
                                metadata = json.load(f)
                            month_reports.append(metadata)
                        except (json.JSONDecodeError, FileNotFoundError):
                            continue

                    if month_reports:
                        reports.append(
                            {
                                "month": month_dir.name,
                                "reports": sorted(
                                    month_reports,
                                    key=lambda x: x.get("created_at", ""),
                                    reverse=True,
                                ),
                            }
                        )

        # KONSISTENTES FORMAT für alle Fälle:
        return {
            "customer": customer_name,
            "customer_slug": customer_slug,
            "total_reports": sum(len(r["reports"]) for r in reports),
            "months": reports,  # Immer "months", auch wenn leer
        }
        # PRIVATE HELPER METHODS

    def _atomic_copy(self, src: Path, dst: Path) -> None:
        import time

        dst.parent.mkdir(parents=True, exist_ok=True)

        # Versuche mit temp file (atomar)
        for attempt in range(3):
            try:
                # 1. Zuerst zu temp file im gleichen Verzeichnis kopieren
                temp_dst = dst.parent / f".tmp_{dst.name}"
                shutil.copy2(src, temp_dst)

                # 2. Dann umbenennen (atomar auf den meisten Filesystemen)
                temp_dst.replace(dst)
                return

            except (PermissionError, OSError) as e:
                if attempt == 2:
                    # Fallback: Direktes Kopieren
                    try:
                        shutil.copy2(src, dst)
                        return
                    except PermissionError:
                        raise PermissionError(
                            f"Kann PDF nicht archivieren nach {attempt+1} Versuchen. "
                            f"Möglicherweise ist die Datei gesperrt. "
                            f"Fehler: {e}"
                        )

                # Warte kurz und versuche es erneut
                time.sleep(0.1 * (attempt + 1))

                # Versuche temp file zu löschen falls existiert
                if "temp_dst" in locals() and temp_dst.exists():
                    try:
                        temp_dst.unlink()
                    except:
                        pass

    def _create_metadata(
        self,
        pdf_path: Path,
        customer_name: str,
        customer_slug: str,
        month: str,
        ip: str,
        version: int,
        extra_metadata: Optional[Dict] = None,
    ) -> Dict[str, Any]:

        # PDF Hash berechnen
        pdf_bytes = pdf_path.read_bytes()
        pdf_hash = hashlib.sha256(pdf_bytes).hexdigest()

        metadata = {
            "customer_slug": customer_slug,
            "customer_name": customer_name,
            "ip": ip,
            "month": month,
            "pdf_path": str(pdf_path.relative_to(self.archive_root)),
            "sha256": pdf_hash,
            "size_bytes": pdf_path.stat().st_size,
            "version": version,
            "generator": "shodan-report",
            "created_at": datetime.now().isoformat(),
            "extra": extra_metadata or {},
        }

        return metadata

    def _save_metadata(
        self,
        target_dir: Path,
        base_filename: str,
        metadata: Dict[str, Any],
        version: int,
    ) -> None:

        meta_path = target_dir / f"{base_filename}.meta.json"

        all_metadata = {"versions": {}}
        if meta_path.exists():
            try:
                with meta_path.open("r", encoding="utf-8") as f:
                    existing = json.load(f)
                all_metadata.update(existing)
            except json.JSONDecodeError:
                pass

        all_metadata["versions"][str(version)] = metadata
        all_metadata["latest_version"] = version
        all_metadata["updated_at"] = datetime.now().isoformat()

        with meta_path.open("w", encoding="utf-8") as f:
            json.dump(all_metadata, f, indent=2, ensure_ascii=False)

    def _is_valid_month(self, month_str: str) -> bool:
        try:
            datetime.strptime(month_str, "%Y-%m")
            return True
        except ValueError:
            return False

    def _manual_get_next_version(
        self, customer_slug: str, month: str, base_filename: str
    ) -> int:

        version = 1
        target_dir = self.archive_root / customer_slug / month

        if not target_dir.exists():
            return version

        pattern = f"{base_filename}_v*.pdf"
        for file in target_dir.glob(pattern):
            try:
                stem = file.stem
                if "_v" in stem:
                    v_str = stem.split("_v")[-1]
                    v = int(v_str)
                    version = max(version, v + 1)
            except (ValueError, IndexError):
                continue

        return version
