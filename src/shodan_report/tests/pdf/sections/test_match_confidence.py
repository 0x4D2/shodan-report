"""Unit Tests — Drei-Stufen-Confidence-System (MatchConfidence).

Prüft:
- _version_in_range: alle vier NVD-Grenzen
- _extract_cpe_matches_for_service: Vendor/Product-Matching aus NVD-Konfigurationen
- match_cve_to_service: VERIFIED / INFERRED / UNMATCHED-Logik
- match_cve_to_service: CPE-direkt-Pfad (service_cpe statt VENDOR_MAP)
- build_cve_port_map: versions-Feld und primary_cpe korrekt befüllt
- enrich_cves_with_local: confidence gesetzt nach lokalem Snapshot
- _vendor_product_from_cpe: CPE-Parsing
"""
import pytest
from shodan_report.pdf.sections.data.cve_enricher import (
    MatchConfidence,
    VENDOR_MAP,
    _parse_version_tuple,
    _version_in_range,
    _extract_cpe_matches_for_service,
    _vendor_product_from_cpe,
    match_cve_to_service,
    build_cve_port_map,
    enrich_cves_with_local,
)


# ──────────────────────────────────────────────────────────────────────────────
# _parse_version_tuple
# ──────────────────────────────────────────────────────────────────────────────

class TestParseVersionTuple:
    def test_simple(self):
        assert _parse_version_tuple("2.4.54") == (2, 4, 54)

    def test_two_parts(self):
        assert _parse_version_tuple("9.0") == (9, 0)

    def test_with_suffix(self):
        # "9.0p1" → only numeric parts
        result = _parse_version_tuple("9.0p1")
        assert result[0] == 9 and result[1] == 0

    def test_dash_separator(self):
        assert _parse_version_tuple("1-2-3") == (1, 2, 3)

    def test_empty_returns_empty(self):
        assert _parse_version_tuple("") == ()
        assert _parse_version_tuple(None) == ()

    def test_non_numeric_returns_empty(self):
        assert _parse_version_tuple("abc") == ()


# ──────────────────────────────────────────────────────────────────────────────
# _version_in_range
# ──────────────────────────────────────────────────────────────────────────────

class TestVersionInRange:
    def test_start_including_in_range(self):
        assert _version_in_range("2.4.51", start_including="2.4.0") is True

    def test_start_including_exact(self):
        assert _version_in_range("2.4.0", start_including="2.4.0") is True

    def test_start_including_below(self):
        assert _version_in_range("2.3.99", start_including="2.4.0") is False

    def test_end_excluding_below(self):
        assert _version_in_range("2.4.51", end_excluding="2.4.58") is True

    def test_end_excluding_exact(self):
        # versionEndExcluding means the end version itself is NOT included
        assert _version_in_range("2.4.58", end_excluding="2.4.58") is False

    def test_end_excluding_above(self):
        assert _version_in_range("2.4.60", end_excluding="2.4.58") is False

    def test_end_including_exact(self):
        assert _version_in_range("2.4.57", end_including="2.4.57") is True

    def test_end_including_above(self):
        assert _version_in_range("2.4.58", end_including="2.4.57") is False

    def test_start_excluding_exact(self):
        # versionStartExcluding: start itself NOT included
        assert _version_in_range("2.4.0", start_excluding="2.4.0") is False

    def test_start_excluding_above(self):
        assert _version_in_range("2.4.1", start_excluding="2.4.0") is True

    def test_combined_range(self):
        # typical NVD range: >= 2.4.0 AND < 2.4.58
        assert _version_in_range("2.4.51", start_including="2.4.0", end_excluding="2.4.58") is True
        assert _version_in_range("2.4.58", start_including="2.4.0", end_excluding="2.4.58") is False
        assert _version_in_range("2.3.99", start_including="2.4.0", end_excluding="2.4.58") is False

    def test_unparseable_version_returns_false(self):
        assert _version_in_range("unknown", start_including="2.4.0") is False

    def test_no_bounds_returns_true(self):
        # no bounds = all versions match (wildcard CPE)
        assert _version_in_range("2.4.51") is True


# ──────────────────────────────────────────────────────────────────────────────
# _extract_cpe_matches_for_service
# ──────────────────────────────────────────────────────────────────────────────

def _make_nvd_with_ranges(vendor, product, version_start, version_end):
    return {
        "vulnerabilities": [{
            "cve": {
                "configurations": [{
                    "nodes": [{
                        "cpeMatch": [{
                            "criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
                            "vulnerable": True,
                            "versionStartIncluding": version_start,
                            "versionEndExcluding":   version_end,
                        }]
                    }]
                }]
            }
        }]
    }


class TestExtractCpeMatchesForService:
    def test_matching_vendor_and_product(self):
        nvd = _make_nvd_with_ranges("apache", "http_server", "2.4.0", "2.4.58")
        matches = _extract_cpe_matches_for_service(nvd, "apache", "http_server")
        assert len(matches) == 1
        assert matches[0]["versionStartIncluding"] == "2.4.0"

    def test_partial_product_match(self):
        nvd = _make_nvd_with_ranges("apache", "http_server", "2.4.0", "2.4.58")
        # "http" partial match against "http_server"
        matches = _extract_cpe_matches_for_service(nvd, "apache", "http")
        assert len(matches) == 1

    def test_no_match_wrong_vendor(self):
        nvd = _make_nvd_with_ranges("apache", "http_server", "2.4.0", "2.4.58")
        matches = _extract_cpe_matches_for_service(nvd, "nginx", "nginx")
        assert len(matches) == 0

    def test_vulnerable_false_excluded(self):
        nvd = {
            "vulnerabilities": [{
                "cve": {
                    "configurations": [{
                        "nodes": [{
                            "cpeMatch": [{
                                "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                                "vulnerable": False,  # platform-only → excluded
                            }]
                        }]
                    }]
                }
            }]
        }
        matches = _extract_cpe_matches_for_service(nvd, "apache", "http_server")
        assert len(matches) == 0

    def test_empty_nvd_returns_empty(self):
        assert _extract_cpe_matches_for_service({}, "apache", "http_server") == []


# ──────────────────────────────────────────────────────────────────────────────
# match_cve_to_service
# ──────────────────────────────────────────────────────────────────────────────

class TestMatchCveToService:
    def _base_entry(self, label=None, version=None):
        entry = {"id": "CVE-TEST-1", "cvss": 7.5}
        if label:
            entry["service_indicator"] = {"label": label, "matched_by": "cpe", "confidence": "low"}
        if version:
            entry["service_version"] = version
        return entry

    # ── UNMATCHED ──────────────────────────────────────────────────────────────

    def test_no_service_label_is_unmatched(self):
        entry = self._base_entry()
        result = match_cve_to_service(entry)
        assert result["confidence"] == MatchConfidence.UNMATCHED
        assert "match_note" in result

    def test_unknown_service_not_in_vendor_map_is_unmatched(self):
        entry = self._base_entry(label="SomeObscureDaemon 3.0")
        result = match_cve_to_service(entry)
        assert result["confidence"] == MatchConfidence.UNMATCHED

    # ── INFERRED ──────────────────────────────────────────────────────────────

    def test_known_service_no_version_is_inferred(self):
        entry = self._base_entry(label="Apache HTTP Server")
        result = match_cve_to_service(entry)
        assert result["confidence"] == MatchConfidence.INFERRED
        assert "Version nicht verfügbar" in result["match_note"]

    def test_known_service_version_no_nvd_is_inferred(self):
        entry = self._base_entry(label="Apache HTTP Server", version="2.4.51")
        result = match_cve_to_service(entry, nvd_json=None)
        assert result["confidence"] == MatchConfidence.INFERRED

    def test_version_outside_range_is_inferred(self):
        """Version bekannt, Ranges gefunden, aber Version bereits gepatcht → INFERRED."""
        entry = self._base_entry(label="Apache HTTP Server", version="2.4.60")
        nvd = _make_nvd_with_ranges("apache", "http_server", "2.4.0", "2.4.58")
        result = match_cve_to_service(entry, nvd_json=nvd)
        assert result["confidence"] == MatchConfidence.INFERRED
        assert "außerhalb" in result["match_note"]

    def test_nvd_no_ranges_for_service_is_inferred(self):
        """NVD-Daten vorhanden, aber kein passender cpeMatch → INFERRED."""
        entry = self._base_entry(label="Apache HTTP Server", version="2.4.51")
        nvd = _make_nvd_with_ranges("nginx", "nginx", "1.0.0", "1.24.0")
        result = match_cve_to_service(entry, nvd_json=nvd)
        assert result["confidence"] == MatchConfidence.INFERRED

    # ── VERIFIED ──────────────────────────────────────────────────────────────

    def test_version_in_range_is_verified(self):
        """Kernfall VERIFIED: Version liegt in bekannter NVD-Range."""
        entry = self._base_entry(label="Apache HTTP Server", version="2.4.51")
        nvd = _make_nvd_with_ranges("apache", "http_server", "2.4.0", "2.4.58")
        result = match_cve_to_service(entry, nvd_json=nvd)
        assert result["confidence"] == MatchConfidence.VERIFIED
        assert "2.4.51" in result["match_note"]

    def test_openssh_verified(self):
        entry = self._base_entry(label="OpenSSH", version="8.9")
        nvd = _make_nvd_with_ranges("openssh", "openssh", "7.0", "9.0")
        result = match_cve_to_service(entry, nvd_json=nvd)
        assert result["confidence"] == MatchConfidence.VERIFIED

    def test_nginx_verified(self):
        entry = self._base_entry(label="Nginx", version="1.22.0")
        nvd = _make_nvd_with_ranges("nginx", "nginx", "1.0.0", "1.24.0")
        result = match_cve_to_service(entry, nvd_json=nvd)
        assert result["confidence"] == MatchConfidence.VERIFIED

    # ── Sonderfälle ──────────────────────────────────────────────────────────

    def test_match_note_always_set(self):
        for label, version in [
            (None, None),
            ("Apache HTTP Server", None),
            ("Apache HTTP Server", "2.4.51"),
        ]:
            entry = self._base_entry(label=label, version=version)
            result = match_cve_to_service(entry)
            assert "match_note" in result and result["match_note"]

    def test_confidence_field_is_enum_instance(self):
        entry = self._base_entry(label="Apache HTTP Server")
        result = match_cve_to_service(entry)
        assert isinstance(result["confidence"], MatchConfidence)


# ──────────────────────────────────────────────────────────────────────────────
# build_cve_port_map: versions-Feld
# ──────────────────────────────────────────────────────────────────────────────

class TestBuildCvePortMapVersions:
    def test_version_stored_from_service(self):
        technical = {
            "services": [{
                "port": 80,
                "product": "Apache HTTP Server",
                "version": "2.4.54",
                "vulnerabilities": [{"id": "CVE-TEST-1", "cvss": 9.8}],
            }]
        }
        pm = build_cve_port_map(technical)
        assert "CVE-TEST-1" in pm
        assert "2.4.54" in pm["CVE-TEST-1"]["versions"]

    def test_no_version_empty_list(self):
        technical = {
            "services": [{
                "port": 22,
                "vulnerabilities": ["CVE-TEST-2"],
            }]
        }
        pm = build_cve_port_map(technical)
        assert pm["CVE-TEST-2"]["versions"] == []

    def test_version_deduplication(self):
        """Dieselbe Version wird nicht doppelt gespeichert."""
        technical = {
            "services": [
                {"port": 80, "version": "2.4.54",
                 "vulnerabilities": [{"id": "CVE-TEST-3", "cvss": 7.0}]},
                {"port": 443, "version": "2.4.54",
                 "vulnerabilities": [{"id": "CVE-TEST-3", "cvss": 7.0}]},
            ]
        }
        pm = build_cve_port_map(technical)
        assert pm["CVE-TEST-3"]["versions"].count("2.4.54") == 1

    def test_nested_service_version(self):
        """Version unter 'service'-Sub-Dict wird erkannt."""
        technical = {
            "services": [{
                "port": 80,
                "service": {"product": "Apache", "version": "2.4.62"},
                "vulnerabilities": ["CVE-TEST-4"],
            }]
        }
        pm = build_cve_port_map(technical)
        assert "2.4.62" in pm["CVE-TEST-4"]["versions"]


# ──────────────────────────────────────────────────────────────────────────────
# enrich_cves_with_local: initiale Confidence
# ──────────────────────────────────────────────────────────────────────────────

class TestEnrichCvesWithLocalConfidence:
    def test_known_service_no_version_is_inferred(self):
        technical = {
            "services": [{
                "port": 80,
                "cpes": ["cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"],
                "vulnerabilities": [{"id": "CVE-TEST-10", "cvss": 7.5}],
            }]
        }
        enriched = enrich_cves_with_local(technical, ["CVE-TEST-10"])
        assert len(enriched) == 1
        assert enriched[0]["confidence"] == MatchConfidence.INFERRED

    def test_known_service_with_version_is_inferred_locally(self):
        """Lokal ist max. INFERRED (kein NVD) — erst nach NVD-Lookup VERIFIED."""
        technical = {
            "services": [{
                "port": 80,
                "version": "2.4.51",
                "cpes": ["cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"],
                "vulnerabilities": [{"id": "CVE-TEST-11", "cvss": 9.8}],
            }]
        }
        enriched = enrich_cves_with_local(technical, ["CVE-TEST-11"])
        assert enriched[0]["confidence"] == MatchConfidence.INFERRED
        assert enriched[0].get("service_version") == "2.4.51"

    def test_no_cpe_no_service_is_unmatched(self):
        """CVE ohne CPE und ohne Service-Mapping → UNMATCHED."""
        technical = {
            "services": [{
                "port": 9999,
                "vulnerabilities": ["CVE-TEST-12"],
                # keine cpes, kein bekanntes product
            }]
        }
        enriched = enrich_cves_with_local(technical, ["CVE-TEST-12"])
        assert enriched[0]["confidence"] == MatchConfidence.UNMATCHED

    def test_confidence_field_present_for_all_entries(self):
        technical = {
            "services": [{
                "port": 22,
                "cpes": ["cpe:2.3:a:openssh:openssh:9.3:*:*:*:*:*:*:*"],
                "version": "9.3",
                "vulnerabilities": [{"id": "CVE-SSH-1", "cvss": 5.0}],
            }]
        }
        enriched = enrich_cves_with_local(technical, ["CVE-SSH-1", "CVE-UNKNOWN-99"])
        for e in enriched:
            assert "confidence" in e
            assert isinstance(e["confidence"], MatchConfidence)


# ──────────────────────────────────────────────────────────────────────────────
# _vendor_product_from_cpe
# ──────────────────────────────────────────────────────────────────────────────

class TestVendorProductFromCpe:
    def test_apache_http_server(self):
        r = _vendor_product_from_cpe("cpe:2.3:a:apache:http_server:2.4.66:*:*:*:*:*:*:*")
        assert r == {"vendor": "apache", "product": "http_server"}

    def test_openssh(self):
        r = _vendor_product_from_cpe("cpe:2.3:a:openssh:openssh:9.3:*:*:*:*:*:*:*")
        assert r == {"vendor": "openssh", "product": "openssh"}

    def test_wildcard_version_ok(self):
        """Wildcard-Version (*) ist erlaubt — nur Vendor/Product müssen konkret sein."""
        r = _vendor_product_from_cpe("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")
        assert r == {"vendor": "nginx", "product": "nginx"}

    def test_wildcard_product_returns_none(self):
        r = _vendor_product_from_cpe("cpe:2.3:a:apache:*:2.4.0:*:*:*:*:*:*:*")
        assert r is None

    def test_wildcard_vendor_returns_none(self):
        r = _vendor_product_from_cpe("cpe:2.3:a:*:http_server:2.4.0:*:*:*:*:*:*")
        assert r is None

    def test_empty_returns_none(self):
        assert _vendor_product_from_cpe("") is None
        assert _vendor_product_from_cpe(None) is None

    def test_too_short_returns_none(self):
        assert _vendor_product_from_cpe("cpe:2.3:a:apache") is None

    def test_mod_fcgid(self):
        """mod_fcgid ist ein eigenes Produkt — nicht http_server."""
        r = _vendor_product_from_cpe("cpe:2.3:a:apache:mod_fcgid:2.3.9:*:*:*:*:*:*:*")
        assert r == {"vendor": "apache", "product": "mod_fcgid"}


# ──────────────────────────────────────────────────────────────────────────────
# match_cve_to_service: CPE-direkt-Pfad
# ──────────────────────────────────────────────────────────────────────────────

class TestMatchCveToServiceCpeDirect:
    def test_service_cpe_overrides_vendor_map(self):
        """Wenn service_cpe gesetzt ist, wird VENDOR_MAP nicht benötigt."""
        entry = {
            "id": "CVE-TEST-CPE-1",
            "cvss": 7.5,
            "service_cpe": "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*",
            "service_version": "2.4.51",
        }
        nvd = _make_nvd_with_ranges("apache", "http_server", "2.4.0", "2.4.58")
        result = match_cve_to_service(entry, nvd_json=nvd)
        assert result["confidence"] == MatchConfidence.VERIFIED

    def test_mod_fcgid_cpe_does_not_match_http_server_nvd(self):
        """CVE für mod_fcgid: service_cpe=http_server → kein NVD-Match → INFERRED (nicht VERIFIED).
        Kernfall: apache:http_server sucht in NVD nach http_server-Ranges,
        findet nur mod_fcgid → kein Range-Match → INFERRED statt falsches VERIFIED."""
        entry = {
            "id": "CVE-2013-4365",
            "cvss": 7.5,
            # Shodan meldet http_server auf Port 80
            "service_cpe": "cpe:2.3:a:apache:http_server:2.4.66:*:*:*:*:*:*:*",
            "service_version": "2.4.66",
        }
        # NVD enthält nur mod_fcgid-Ranges, NICHT http_server
        nvd_mod_fcgid = {
            "vulnerabilities": [{
                "cve": {
                    "configurations": [{
                        "nodes": [{
                            "cpeMatch": [{
                                "criteria": "cpe:2.3:a:apache:mod_fcgid:*:*:*:*:*:*:*:*",
                                "vulnerable": True,
                                "versionStartIncluding": "0.0.1",
                                "versionEndExcluding": "2.3.9",
                            }]
                        }]
                    }]
                }
            }]
        }
        result = match_cve_to_service(entry, nvd_json=nvd_mod_fcgid)
        # mod_fcgid passt nicht zu http_server → kein VERIFIED, sondern INFERRED
        assert result["confidence"] != MatchConfidence.VERIFIED

    def test_unknown_service_with_cpe_not_in_vendor_map_gets_inferred(self):
        """Dienst ohne VENDOR_MAP-Eintrag, aber mit konkretem service_cpe → INFERRED (nicht UNMATCHED)."""
        entry = {
            "id": "CVE-TEST-FTP-1",
            "cvss": 6.5,
            # ftpd ist nicht im VENDOR_MAP, aber Shodan liefert den CPE
            "service_cpe": "cpe:2.3:a:ftpd:ftpd:3.4.0:*:*:*:*:*:*:*",
            "service_version": "3.4.0",
        }
        result = match_cve_to_service(entry, nvd_json=None)
        # Kein NVD-Lookup, aber vendor_entry aus CPE bekannt → INFERRED
        assert result["confidence"] == MatchConfidence.INFERRED

    def test_no_cpe_no_label_is_unmatched(self):
        """Weder service_cpe noch service_indicator → UNMATCHED."""
        entry = {"id": "CVE-TEST-BARE-1", "cvss": 5.0}
        result = match_cve_to_service(entry)
        assert result["confidence"] == MatchConfidence.UNMATCHED


# ──────────────────────────────────────────────────────────────────────────────
# build_cve_port_map: primary_cpe
# ──────────────────────────────────────────────────────────────────────────────

class TestBuildCvePortMapPrimaryCpe:
    def test_primary_cpe_stored(self):
        technical = {
            "services": [{
                "port": 80,
                "cpes": ["cpe:2.3:a:apache:http_server:2.4.66:*:*:*:*:*:*:*"],
                "vulnerabilities": [{"id": "CVE-PC-1", "cvss": 7.5}],
            }]
        }
        pm = build_cve_port_map(technical)
        assert pm["CVE-PC-1"]["primary_cpe"] == "cpe:2.3:a:apache:http_server:2.4.66:*:*:*:*:*:*:*"

    def test_wildcard_only_cpe_not_stored_as_primary(self):
        """CPE mit Wildcard-Vendor/Product wird nicht als primary_cpe übernommen."""
        technical = {
            "services": [{
                "port": 80,
                "cpes": ["cpe:2.3:a:*:*:2.4.66:*:*:*:*:*:*:*"],
                "vulnerabilities": [{"id": "CVE-PC-2", "cvss": 5.0}],
            }]
        }
        pm = build_cve_port_map(technical)
        assert pm["CVE-PC-2"]["primary_cpe"] is None

    def test_primary_cpe_not_overwritten_by_second_port(self):
        """primary_cpe des ersten gemeldeten Ports wird beibehalten."""
        technical = {
            "services": [
                {"port": 80,  "cpes": ["cpe:2.3:a:apache:http_server:2.4.66:*:*:*:*:*:*:*"],
                 "vulnerabilities": [{"id": "CVE-PC-3", "cvss": 7.5}]},
                {"port": 443, "cpes": ["cpe:2.3:a:apache:http_server:2.4.66:*:*:*:*:*:*:*"],
                 "vulnerabilities": [{"id": "CVE-PC-3", "cvss": 7.5}]},
            ]
        }
        pm = build_cve_port_map(technical)
        assert pm["CVE-PC-3"]["primary_cpe"] == "cpe:2.3:a:apache:http_server:2.4.66:*:*:*:*:*:*:*"
        assert sorted(pm["CVE-PC-3"]["ports"]) == [80, 443]


# ──────────────────────────────────────────────────────────────────────────────
# enrich_cves_with_local: service_cpe wird gesetzt
# ──────────────────────────────────────────────────────────────────────────────

class TestEnrichCvesWithLocalServiceCpe:
    def test_service_cpe_set_from_snapshot(self):
        technical = {
            "services": [{
                "port": 80,
                "cpes": ["cpe:2.3:a:apache:http_server:2.4.66:*:*:*:*:*:*:*"],
                "version": "2.4.66",
                "vulnerabilities": [{"id": "CVE-SC-1", "cvss": 7.5}],
            }]
        }
        enriched = enrich_cves_with_local(technical, ["CVE-SC-1"])
        assert enriched[0].get("service_cpe") == "cpe:2.3:a:apache:http_server:2.4.66:*:*:*:*:*:*:*"

    def test_no_cpe_in_snapshot_no_service_cpe(self):
        technical = {
            "services": [{
                "port": 80,
                "vulnerabilities": [{"id": "CVE-SC-2", "cvss": 5.0}],
            }]
        }
        enriched = enrich_cves_with_local(technical, ["CVE-SC-2"])
        assert enriched[0].get("service_cpe") is None
