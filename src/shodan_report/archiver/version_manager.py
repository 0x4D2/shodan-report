from pathlib import Path
from typing import Optional, Dict, Any
import json
from datetime import datetime

class VersionManager:

    def __init__(self, archive_root: Path = Path("archive")):
        self.archive_root = archive_root
        self.archive_root.mkdir(parents=True, exist_ok=True)

    def get_next_version(self,customer_slug: str, month: str, ip: str) -> int:
        version = 1
        target_dir = self.archive_root / customer_slug / month

        if not target_dir.exists():
            return version
            
        pattern = f"{month}_{ip}_v*.pdf"
        for file in target_dir.glob(pattern):
            try:
                # Extrahiere Versionsnummer aus filename_v{N}.pdf
                stem = file.stem # 2025-01_1.2.3.4_v2"
                if '_v' in stem:
                    v_str = stem.split('_v')[-1]
                    v = int(v_str)
                    version = max(version, v + 1)
            except (ValueError, IndexError):
                continue
            
        return version

    def find_latest_version(self, customer_slug: str, month: str, base_filename: str) -> Optional[int]:
        latest_version = None
        target_dir = self.archive_root / customer_slug / month

        if not target_dir.exists():
            return None
        
        pattern = f"{base_filename}_v*.pdf"
        for file in target_dir.glob(pattern):
            try:
                stem = file.stem  # z.B. "2025-01_1.2.3.4_v2"
                if '_v' in stem:
                    v_str = stem.split('_v')[-1]
                    v = int(v_str)
                    if latest_version is None or v > latest_version:
                        latest_version = v
            except (ValueError, IndexError):
                continue

        return latest_version
    
    def list_all_versions(self, customer_slug: str, month: str, base_filename: str) -> Dict[int, Path]:
        version = {}
        target_dir = self.archive_root / customer_slug / month

        if not target_dir.exists():
            return version

        pattern = f"{base_filename}_v*.pdf"
        for file in target_dir.glob(pattern):
            try:
                stem = file.stem  # z.B. "2025-01_1.2.3.4_v2"
                if '_v' in stem:
                    v_str = stem.split('_v')[-1]
                    v = int(v_str)
                    version[v] = file
            except (ValueError, IndexError):
                continue

        return dict(sorted(version.items()))
    
    def get_metadata(self, customer_slug: str, month: str, base_filename: str, version: Optional[int] = None) -> Optional[Dict[str, Any]]:
    
        if version is None:
            version = self.find_latest_version(customer_slug, month, base_filename)
        
        if version is None:
            return None
        
        meta_path = self.archive_root / customer_slug / month / f"{base_filename}.meta.json"
        
        if not meta_path.exists():
            return None
        
        try:
            with meta_path.open("r", encoding="utf-8") as f:
                metadata = json.load(f)
            
            # Filtere nach Version falls nötig
            if "versions" in metadata and str(version) in metadata["versions"]:
                return metadata["versions"][str(version)]
            elif metadata.get("version") == version:
                return metadata
            else:
                return None
                
        except (json.JSONDecodeError, FileNotFoundError):
            return None