import json
from pathlib import Path

from shodan_report.archiver.version_manager import VersionManager


def test_get_next_version_and_listing(tmp_path):
    archive_root = tmp_path / "archive"
    vm = VersionManager(archive_root=archive_root)

    customer = "testcust"
    month = "2025-01"
    base = f"{month}_1.2.3.4"
    target_dir = archive_root / customer / month
    target_dir.mkdir(parents=True, exist_ok=True)

    # no files yet -> next version 1
    assert vm.get_next_version(customer, month, "1.2.3.4") == 1

    # create v1 and v2 files
    (target_dir / f"{base}_v1.pdf").write_text("x")
    (target_dir / f"{base}_v2.pdf").write_text("x")

    assert vm.get_next_version(customer, month, "1.2.3.4") == 3

    # list_all_versions should return mapping with versions 1 and 2
    versions = vm.list_all_versions(customer, month, base)
    assert 1 in versions and 2 in versions


def test_get_metadata_reads_meta(tmp_path):
    archive_root = tmp_path / "archive"
    vm = VersionManager(archive_root=archive_root)

    customer = "meta_cust"
    month = "2025-03"
    base = f"{month}_9.9.9.9"
    target_dir = archive_root / customer / month
    target_dir.mkdir(parents=True, exist_ok=True)

    meta = {
        "versions": {
            "1": {"version": 1, "foo": "bar"},
            "2": {"version": 2, "foo": "baz"},
        },
        "latest_version": 2,
    }

    meta_path = target_dir / f"{base}.meta.json"
    meta_path.write_text(json.dumps(meta), encoding="utf-8")

    # find_latest_version should not detect a version when no pdf files exist
    latest = vm.find_latest_version(customer, month, base)
    assert latest is None

    # get_metadata without version should read meta and return latest (2)
    m = vm.get_metadata(customer, month, base)
    assert m is not None and m.get("version") == 2

    # get specific version
    m1 = vm.get_metadata(customer, month, base, version=1)
    assert m1 is not None and m1.get("version") == 1


# ── _parse_version Edge Cases ─────────────────────────────────────────────────

import pytest

@pytest.mark.parametrize("stem,expected", [
    ("2026-01_1.2.3.4_v1",    1),
    ("2026-01_1.2.3.4_v10",   10),
    ("2026-01_1.2.3.4_v2abc", 2),   # Buchstaben nach Ziffer → nur Ziffern extrahiert
    ("2026-01_1.2.3.4_vABC",  None), # nur Buchstaben → int('') ValueError → None
    ("2026-01_1.2.3.4_v",     None), # kein Zeichen nach _v
    ("2026-01_1.2.3.4",       None), # kein _v-Suffix
    ("",                       None),
])
def test_parse_version(tmp_path, stem, expected):
    vm = VersionManager(archive_root=tmp_path)
    assert vm._parse_version(stem) == expected


# ── get_metadata Edge Cases ───────────────────────────────────────────────────

def test_get_metadata_corrupted_json_returns_none(tmp_path):
    archive_root = tmp_path / "archive"
    vm = VersionManager(archive_root=archive_root)
    d = archive_root / "cust" / "2026-01"
    d.mkdir(parents=True, exist_ok=True)
    (d / "base.meta.json").write_text("{ bad json !!!", encoding="utf-8")
    assert vm.get_metadata("cust", "2026-01", "base") is None


def test_get_metadata_empty_versions_dict_returns_none(tmp_path):
    """versions={} → max() auf leerem Iterable → Exception gefangen → None."""
    archive_root = tmp_path / "archive"
    vm = VersionManager(archive_root=archive_root)
    d = archive_root / "cust" / "2026-01"
    d.mkdir(parents=True, exist_ok=True)
    import json as _json
    (d / "base.meta.json").write_text(_json.dumps({"versions": {}}), encoding="utf-8")
    assert vm.get_metadata("cust", "2026-01", "base") is None


def test_get_metadata_explicit_version_not_in_versions_returns_none(tmp_path):
    archive_root = tmp_path / "archive"
    vm = VersionManager(archive_root=archive_root)
    d = archive_root / "cust" / "2026-01"
    d.mkdir(parents=True, exist_ok=True)
    import json as _json
    (d / "base.meta.json").write_text(
        _json.dumps({"versions": {"1": {"sha256": "abc"}}}), encoding="utf-8"
    )
    assert vm.get_metadata("cust", "2026-01", "base", version=99) is None


def test_get_metadata_no_meta_no_pdfs_returns_none(tmp_path):
    vm = VersionManager(archive_root=tmp_path)
    assert vm.get_metadata("ghost", "2026-01", "base") is None


# ── find_latest_version Edge Cases ────────────────────────────────────────────

def test_find_latest_version_nonexistent_dir_returns_none(tmp_path):
    vm = VersionManager(archive_root=tmp_path)
    assert vm.find_latest_version("ghost", "2026-01", "base") is None


def test_find_latest_version_multiple_returns_highest(tmp_path):
    archive_root = tmp_path / "archive"
    vm = VersionManager(archive_root=archive_root)
    d = archive_root / "cust" / "2026-01"
    d.mkdir(parents=True, exist_ok=True)
    for v in [1, 5, 2]:
        (d / f"base_v{v}.pdf").write_text("x")
    assert vm.find_latest_version("cust", "2026-01", "base") == 5


# ── list_all_versions Edge Cases ──────────────────────────────────────────────

def test_list_all_versions_sorted(tmp_path):
    archive_root = tmp_path / "archive"
    vm = VersionManager(archive_root=archive_root)
    d = archive_root / "cust" / "2026-01"
    d.mkdir(parents=True, exist_ok=True)
    for v in [3, 1, 2]:
        (d / f"base_v{v}.pdf").write_text("x")
    result = vm.list_all_versions("cust", "2026-01", "base")
    assert list(result.keys()) == [1, 2, 3]


def test_list_all_versions_files_without_suffix_ignored(tmp_path):
    archive_root = tmp_path / "archive"
    vm = VersionManager(archive_root=archive_root)
    d = archive_root / "cust" / "2026-01"
    d.mkdir(parents=True, exist_ok=True)
    (d / "base.pdf").write_text("x")          # kein _v-Suffix → ignoriert
    (d / "base_v2.pdf").write_text("x")
    result = vm.list_all_versions("cust", "2026-01", "base")
    assert list(result.keys()) == [2]
