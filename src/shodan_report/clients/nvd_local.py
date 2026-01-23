"""Local NVD feed lookup helper.

Loads JSON files from `.cache/nvd/*.json` and builds a mapping CVE_ID -> item
so callers can quickly lookup CVE details without hitting NVD API or HTML.
"""
from pathlib import Path
from typing import Optional, Dict, Any
import json


class LocalNvdClient:
    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = Path(cache_dir or '.cache/nvd')
        self._index: Dict[str, Dict[str, Any]] = {}
        self._loaded = False

    def _ensure_loaded(self):
        if self._loaded:
            return
        self._loaded = True
        if not self.cache_dir.exists():
            return
        for f in sorted(self.cache_dir.glob('*.json')):
            try:
                j = json.loads(f.read_text(encoding='utf-8') or '{}')
            except Exception:
                continue
            # Expect NVD feed shape: top-level 'CVE_Items' or 'vulnerabilities' etc.
            items = j.get('CVE_Items') or j.get('vulnerabilities') or []
            if isinstance(items, dict):
                # some feeds may wrap as dict
                items = []
            for item in items:
                try:
                    # NVD item path variations
                    cid = None
                    if isinstance(item, dict):
                        # try multiple keys
                        cid = (
                            item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
                            or item.get('id')
                            or item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
                        )
                        if not cid:
                            # some newer feeds use 'cve'->'id' or top-level 'id'
                            cid = item.get('id')
                    if not cid:
                        continue
                    cid = str(cid).strip()
                    if cid:
                        # store the raw item as-is for compatibility with fetch_cve_json
                        self._index[cid] = item
                except Exception:
                    continue

    def fetch_cve_json(self, cve_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_loaded()
        return self._index.get(cve_id)
