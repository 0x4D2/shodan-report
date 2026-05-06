"""Tests für clients/nvd_local.py — LocalNvdClient."""
import json
import pytest
from pathlib import Path
from shodan_report.clients.nvd_local import LocalNvdClient


def _item(cve_id: str) -> dict:
    return {"cve": {"CVE_data_meta": {"ID": cve_id}}}


def _write_feed(path: Path, items: list, key: str = "CVE_Items"):
    path.write_text(json.dumps({key: items}), encoding="utf-8")


# ── Cache-Verzeichnis fehlt ───────────────────────────────────────────────────

def test_fetch_returns_none_when_cache_dir_missing(tmp_path):
    client = LocalNvdClient(cache_dir=str(tmp_path / "nonexistent"))
    assert client.fetch_cve_json("CVE-2024-1") is None


def test_loaded_flag_set_even_when_dir_missing(tmp_path):
    client = LocalNvdClient(cache_dir=str(tmp_path / "nonexistent"))
    client._ensure_loaded()
    assert client._loaded is True


# ── Leeres Cache-Verzeichnis ──────────────────────────────────────────────────

def test_fetch_returns_none_for_empty_cache_dir(tmp_path):
    client = LocalNvdClient(cache_dir=str(tmp_path))
    assert client.fetch_cve_json("CVE-2024-1") is None
    assert client._loaded is True


# ── CVE_Items-Format ──────────────────────────────────────────────────────────

def test_fetch_finds_cve_in_cve_items_feed(tmp_path):
    _write_feed(tmp_path / "feed.json", [_item("CVE-2024-1")], key="CVE_Items")
    client = LocalNvdClient(cache_dir=str(tmp_path))
    result = client.fetch_cve_json("CVE-2024-1")
    assert result is not None
    assert result["cve"]["CVE_data_meta"]["ID"] == "CVE-2024-1"


# ── vulnerabilities-Format (alternatives Feed-Schema) ────────────────────────

def test_fetch_finds_cve_in_vulnerabilities_feed(tmp_path):
    _write_feed(tmp_path / "feed.json", [_item("CVE-2024-2")], key="vulnerabilities")
    client = LocalNvdClient(cache_dir=str(tmp_path))
    assert client.fetch_cve_json("CVE-2024-2") is not None


# ── id-Feld auf Item-Ebene (neueres Feed-Format) ──────────────────────────────

def test_fetch_finds_cve_via_top_level_id(tmp_path):
    item = {"id": "CVE-2024-3", "severity": "HIGH"}
    _write_feed(tmp_path / "feed.json", [item])
    client = LocalNvdClient(cache_dir=str(tmp_path))
    assert client.fetch_cve_json("CVE-2024-3") is not None


# ── Korrupte JSON-Datei wird übersprungen ─────────────────────────────────────

def test_corrupted_json_file_skipped_others_loaded(tmp_path):
    (tmp_path / "bad.json").write_text("{ not valid json !!!", encoding="utf-8")
    _write_feed(tmp_path / "good.json", [_item("CVE-2024-4")])
    client = LocalNvdClient(cache_dir=str(tmp_path))
    assert client.fetch_cve_json("CVE-2024-4") is not None
    assert client.fetch_cve_json("CVE-DOESNT-EXIST") is None


# ── Whitespace in CVE-ID wird gestripped ──────────────────────────────────────

def test_whitespace_cve_id_is_stripped(tmp_path):
    item = {"cve": {"CVE_data_meta": {"ID": "  CVE-2024-5  "}}}
    _write_feed(tmp_path / "feed.json", [item])
    client = LocalNvdClient(cache_dir=str(tmp_path))
    assert client.fetch_cve_json("CVE-2024-5") is not None


def test_empty_cve_id_after_strip_not_indexed(tmp_path):
    item = {"cve": {"CVE_data_meta": {"ID": "   "}}}
    _write_feed(tmp_path / "feed.json", [item])
    client = LocalNvdClient(cache_dir=str(tmp_path))
    client._ensure_loaded()
    assert "" not in client._index
    assert "   " not in client._index


# ── Doppelte CVE-IDs: letzte Datei gewinnt ───────────────────────────────────

def test_duplicate_cve_id_last_file_wins(tmp_path):
    item_a = {"cve": {"CVE_data_meta": {"ID": "CVE-2024-6"}}, "source": "a"}
    item_b = {"cve": {"CVE_data_meta": {"ID": "CVE-2024-6"}}, "source": "b"}
    _write_feed(tmp_path / "a_feed.json", [item_a])
    _write_feed(tmp_path / "b_feed.json", [item_b])
    client = LocalNvdClient(cache_dir=str(tmp_path))
    result = client.fetch_cve_json("CVE-2024-6")
    assert result is not None
    assert result.get("source") == "b"


# ── _loaded verhindert doppeltes Einlesen ─────────────────────────────────────

def test_ensure_loaded_called_only_once(tmp_path):
    _write_feed(tmp_path / "feed.json", [_item("CVE-2024-7")])
    client = LocalNvdClient(cache_dir=str(tmp_path))
    client._ensure_loaded()
    # Leere den Index nach dem ersten Laden → zweiter Aufruf darf nicht neu laden
    client._index.clear()
    client._ensure_loaded()
    assert client.fetch_cve_json("CVE-2024-7") is None  # Index bleibt leer


# ── items-Level als Dict (nicht Liste) → wird ignoriert ──────────────────────

def test_items_as_dict_not_list_is_ignored(tmp_path):
    (tmp_path / "feed.json").write_text(
        json.dumps({"CVE_Items": {"CVE-X": "bad_format"}}), encoding="utf-8"
    )
    client = LocalNvdClient(cache_dir=str(tmp_path))
    client._ensure_loaded()
    assert client._index == {}
