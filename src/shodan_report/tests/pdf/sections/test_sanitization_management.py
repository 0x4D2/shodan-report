import json
from pathlib import Path

from shodan_report.pdf.sections.data.management_data import prepare_management_data


def _load_snapshot():
    import shodan_report as pkg
    repo_root = Path(pkg.__file__).resolve().parents[2]
    snap_path = repo_root / "snapshots" / "Clean" / "2026-01_82.100.220.31.json"
    assert snap_path.exists(), f"Snapshot not found at {snap_path}"
    with open(snap_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def test_management_service_rows_sanitized():
    snap = _load_snapshot()
    # pass empty evaluation to reduce side effects
    mdata = prepare_management_data(snap, {})
    rows = mdata.get("service_rows") or []

    # find entries for ports 21 and 2222
    row21 = next((r for r in rows if r[0] == 21), None)
    row2222 = next((r for r in rows if r[0] == 2222), None)

    assert row21 is not None, "Management rows must contain port 21"
    assert row2222 is not None, "Management rows must contain port 2222"

    prod21 = str(row21[1] or "")
    prod2222 = str(row2222[1] or "")

    # product for port 21 should not include leading numeric FTP codes like '220 '
    assert not prod21.strip().startswith("220"), f"Port 21 product still contains FTP numeric banner: {prod21}"

    # product for port 2222 should not contain long base64-like substrings (check for 'AAAAB3')
    assert "AAAAB3" not in prod2222, f"Port 2222 product contains raw key material: {prod2222}"
