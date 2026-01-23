from pathlib import Path
from typing import Optional, Dict, Any
import json
from datetime import datetime


class VersionManager:

    def __init__(self, archive_root: Path = Path("archive")):
        self.archive_root = archive_root
        self.archive_root.mkdir(parents=True, exist_ok=True)

    def _parse_version(self, stem: str) -> int | None:
        """Parse a version suffix from a filename stem like '..._v2'. Returns int or None."""
        if "_v" not in stem:
            return None
        try:
            # split from the right in case filename contains '_v' earlier
            v_str = stem.rsplit("_v", 1)[1]
            # strip potential non-digit suffixes
            v_num = int(''.join(ch for ch in v_str if ch.isdigit()))
            return v_num
        except (ValueError, IndexError):
            return None

    def get_next_version(self, customer_slug: str, month: str, ip: str) -> int:
        version = 1
        target_dir = self.archive_root / customer_slug / month

        if not target_dir.exists():
            return version

        pattern = f"{month}_{ip}_v*.pdf"
        for file in target_dir.glob(pattern):
            stem = file.stem
            v = self._parse_version(stem)
            if v is not None:
                version = max(version, v + 1)

        return version

    def find_latest_version(
        self, customer_slug: str, month: str, base_filename: str
    ) -> Optional[int]:
        latest_version = None
        target_dir = self.archive_root / customer_slug / month

        if not target_dir.exists():
            return None

        pattern = f"{base_filename}_v*.pdf"
        for file in target_dir.glob(pattern):
            stem = file.stem
            v = self._parse_version(stem)
            if v is not None and (latest_version is None or v > latest_version):
                latest_version = v

        return latest_version

    def list_all_versions(
        self, customer_slug: str, month: str, base_filename: str
    ) -> Dict[int, Path]:
        version = {}
        target_dir = self.archive_root / customer_slug / month

        if not target_dir.exists():
            return version

        pattern = f"{base_filename}_v*.pdf"
        for file in target_dir.glob(pattern):
            stem = file.stem
            v = self._parse_version(stem)
            if v is not None:
                version[v] = file

        return dict(sorted(version.items()))

    def get_metadata(
        self,
        customer_slug: str,
        month: str,
        base_filename: str,
        version: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        meta_path = (
            self.archive_root / customer_slug / month / f"{base_filename}.meta.json"
        )

        if not meta_path.exists():
            # no metadata file
            # if caller provided a version, we cannot satisfy it
            if version is None:
                # try to infer from existing pdf files
                version = self.find_latest_version(customer_slug, month, base_filename)
                if version is None:
                    return None
            else:
                return None

        try:
            with meta_path.open("r", encoding="utf-8") as f:
                metadata = json.load(f)

            # If version not provided, prefer explicit latest_version in meta
            if version is None:
                if isinstance(metadata.get("latest_version"), int):
                    version = metadata.get("latest_version")
                elif "versions" in metadata and metadata["versions"]:
                    try:
                        version = max(int(k) for k in metadata["versions"].keys())
                    except Exception:
                        version = None

            if version is None:
                return None

            # Filtere nach Version falls nötig
            if "versions" in metadata and str(version) in metadata["versions"]:
                return metadata["versions"][str(version)]
            elif metadata.get("version") == version:
                return metadata
            else:
                return None

        except (json.JSONDecodeError, FileNotFoundError):
            return None
