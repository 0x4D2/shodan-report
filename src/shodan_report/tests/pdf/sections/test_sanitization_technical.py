import json
from pathlib import Path

from shodan_report.pdf.sections.technical import _normalize_product, _clean_display_field


def _load_snapshot():
    import shodan_report as pkg
    repo_root = Path(pkg.__file__).resolve().parents[2]
    snap_path = repo_root / "snapshots" / "Clean" / "2026-01_82.100.220.31.json"
    assert snap_path.exists(), f"Snapshot not found at {snap_path}"
    with open(snap_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def test_technical_sanitization_on_ssh_key():
    snap = _load_snapshot()
    services = snap.get("services", [])
    svc2222 = next((s for s in services if s.get("port") == 2222), None)
    assert svc2222 is not None, "Snapshot must contain port 2222 entry"

    prod_raw = svc2222.get("product")
    ver_raw = svc2222.get("version")

    # product should be normalized to SSH or SSH (mod_sftp)
    prod_normalized = _normalize_product(prod_raw)
    assert prod_normalized in ("SSH", "SSH (mod_sftp)"), f"Unexpected normalized product: {prod_normalized}"

    # version contains a long base64-like string and should be redacted by the cleaner
    ver_clean = _clean_display_field(ver_raw)
    assert "[SSH-Key entfernt]" in ver_clean or len(ver_clean) < 120, "Version was not sanitized as expected"
