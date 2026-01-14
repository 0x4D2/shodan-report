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
