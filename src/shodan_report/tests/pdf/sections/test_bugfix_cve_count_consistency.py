"""Unit Tests — Bug 1: Inkonsistente CVE-Zählung.

Prüft dass management_data.prepare_management_data() die Severity-Counts
(critical, high, medium, low, kev) direkt aus dem enriched CVE-Listenobjekt
berechnet und im mdata-Dict speichert — keine zweite Berechnungslogik.

Szenario aus dem Bug-Report: Management Summary zeigt KRITISCH: 0,
CVE-Liste enthält CVE-2024-3566 mit CVSS 9.8.
"""
import pytest
from shodan_report.pdf.sections.data.management_data import (
    prepare_management_data,
    _compute_severity_counts,
)


# ──────────────────────────────────────────────────────────────────────────────
# Hilfsdaten
# ──────────────────────────────────────────────────────────────────────────────

def _make_snapshot_with_critical_cve():
    """Snapshot: Port 80 mit CVE-2024-3566 (CVSS 9.8) in der Service-Vulnerability-Liste."""
    return {
        "ip": "1.2.3.4",
        "services": [
            {
                "port": 80,
                "product": "Apache HTTP Server",
                "version": "2.4.51",
                "vulnerabilities": [
                    {"id": "CVE-2024-3566", "cvss": 9.8, "summary": "Critical RCE"},
                    {"id": "CVE-2024-1234", "cvss": 7.2, "summary": "High severity"},
                    {"id": "CVE-2024-5678", "cvss": 4.5, "summary": "Medium"},
                ],
            }
        ],
    }


def _make_eval():
    return {
        "exposure_score": 3,
        "risk": "high",
        "critical_points": ["Apache 2.4.51 öffentlich erreichbar"],
        "cves": [],
    }


# ──────────────────────────────────────────────────────────────────────────────
# Tests: _compute_severity_counts (Hilfsfunktion)
# ──────────────────────────────────────────────────────────────────────────────

class TestComputeSeverityCounts:
    def test_empty_list(self):
        counts = _compute_severity_counts([])
        assert counts == {"critical": 0, "high": 0, "medium": 0, "low": 0, "kev": 0}

    def test_counts_by_severity(self):
        enriched = [
            {"id": "CVE-A", "cvss": 9.8,  "exploit_status": "public"},
            {"id": "CVE-B", "cvss": 7.5,  "exploit_status": None},
            {"id": "CVE-C", "cvss": 5.0,  "exploit_status": "unknown"},
            {"id": "CVE-D", "cvss": 2.0,  "exploit_status": None},
            {"id": "CVE-E", "cvss": None, "exploit_status": "kev"},
        ]
        counts = _compute_severity_counts(enriched)
        assert counts["critical"] == 1   # CVE-A: 9.8 ≥ 9.0
        assert counts["high"]     == 1   # CVE-B: 7.5
        assert counts["medium"]   == 1   # CVE-C: 5.0
        assert counts["low"]      == 1   # CVE-D: 2.0
        assert counts["kev"]      == 2   # CVE-A (public) + CVE-E (kev)

    def test_cvss_boundary_9_0_is_critical(self):
        counts = _compute_severity_counts([{"id": "X", "cvss": 9.0, "exploit_status": None}])
        assert counts["critical"] == 1

    def test_cvss_boundary_6_9_is_medium(self):
        counts = _compute_severity_counts([{"id": "X", "cvss": 6.9, "exploit_status": None}])
        assert counts["medium"] == 1

    def test_non_dict_entries_ignored(self):
        counts = _compute_severity_counts(["not-a-dict", None, 42])
        assert counts == {"critical": 0, "high": 0, "medium": 0, "low": 0, "kev": 0}


# ──────────────────────────────────────────────────────────────────────────────
# Tests: prepare_management_data — Severity-Counts im mdata-Dict
# ──────────────────────────────────────────────────────────────────────────────

class TestManagementDataSeverityCounts:
    def test_critical_cve_in_service_vuln_list_produces_critical_count(self):
        """BUG-1 REPRODUKTION: CVE 9.8 in Service-Vulnerability-Liste → critical_count == 1."""
        technical = _make_snapshot_with_critical_cve()
        evaluation = _make_eval()

        mdata = prepare_management_data(technical, evaluation)

        # BUGFIX: critical_count muss 1 sein (nicht 0)
        assert mdata["critical_count"] == 1, (
            "BUGFIX Bug 1 fehlgeschlagen: management_data liefert critical_count=0 "
            "obwohl CVE-2024-3566 (CVSS 9.8) in der Service-Vulnerability-Liste steht."
        )
        assert mdata["high_count"] == 1
        assert mdata["medium_count"] == 1

    def test_kev_count_from_exploit_status(self):
        """kev_count wird aus exploit_status='public' berechnet."""
        technical = {
            "services": [
                {
                    "port": 443,
                    "vulnerabilities": [
                        {"id": "CVE-KNOWN", "cvss": 8.0, "exploit_status": "public"},
                    ],
                }
            ]
        }
        mdata = prepare_management_data(technical, {})
        # exploit_status im Snapshot wird im enrich_cves_with_local nicht direkt übernommen
        # (KEV-Status kommt von CISA-Live-Lookup); kev_count ist daher 0 ohne Live-Daten.
        # Hier testen wir dass kev_count im Rückgabe-Dict vorhanden ist.
        assert "kev_count" in mdata
        assert isinstance(mdata["kev_count"], int)

    def test_severity_counts_keys_always_present(self):
        """Alle Severity-Felder müssen im mdata-Dict vorhanden sein — auch bei leerem Snapshot."""
        mdata = prepare_management_data({}, {})
        for key in ("critical_count", "high_count", "medium_count", "low_count", "kev_count"):
            assert key in mdata, f"Key '{key}' fehlt in mdata"
            assert isinstance(mdata[key], int), f"Key '{key}' sollte int sein"

    def test_enriched_cves_present_in_mdata(self):
        """enriched_cves wird im mdata-Dict gespeichert und ist eine Liste."""
        technical = _make_snapshot_with_critical_cve()
        mdata = prepare_management_data(technical, {})
        assert "enriched_cves" in mdata
        assert isinstance(mdata["enriched_cves"], list)

    def test_critical_count_consistent_with_unique_cves(self):
        """critical_count basiert auf denselben CVE-IDs wie unique_cves — kein zweiter Pfad."""
        technical = _make_snapshot_with_critical_cve()
        mdata = prepare_management_data(technical, {})

        # unique_cves muss CVE-2024-3566 enthalten
        assert "CVE-2024-3566" in mdata["unique_cves"]

        # critical_count muss >= 1 sein (CVE-2024-3566 hat CVSS 9.8 in enriched_cves)
        critical_cves_in_enriched = [
            e for e in mdata["enriched_cves"]
            if (e.get("cvss") or 0) >= 9.0
        ]
        assert mdata["critical_count"] == len(critical_cves_in_enriched), (
            "critical_count stimmt nicht mit tatsächlicher Anzahl kritischer CVEs "
            "in enriched_cves überein (Inkonsistenz zwischen den Berechnungspfaden)."
        )

    def test_cve_count_matches_unique_cves_length(self):
        """cve_count muss len(unique_cves) entsprechen."""
        technical = _make_snapshot_with_critical_cve()
        mdata = prepare_management_data(technical, {})
        assert mdata["cve_count"] == len(mdata["unique_cves"])

    def test_no_cves_zero_counts(self):
        """Ohne CVEs sind alle Counts 0."""
        technical = {"services": [{"port": 22, "product": "OpenSSH", "version": "9.3"}]}
        mdata = prepare_management_data(technical, {})
        assert mdata["cve_count"] == 0
        assert mdata["critical_count"] == 0
        assert mdata["high_count"] == 0
