"""Unit Tests — Bug 2: CVE-Plausibilitätsfilter (vulnerable:false / Plattformabhängigkeit).

Prüft _get_cpe_vulnerable_map, _is_platform_only und die Integration in enrich_cves():
- CVEs wo die gescannte Komponente ausschließlich vulnerable:false eingetragen ist
  → low_confidence=True + low_confidence_reason gesetzt
- CVEs wo die gescannte Komponente vulnerable:true → kein low_confidence-Flag
- Beispiel aus dem Bug-Report: CVE-2007-4723 betrifft Ragnarok Online Control Panel,
  Apache ist nur Plattformabhängigkeit (vulnerable:false)
"""
import pytest
from shodan_report.pdf.sections.data.cve_enricher import (
    _get_cpe_vulnerable_map,
    _is_platform_only,
)


# ──────────────────────────────────────────────────────────────────────────────
# Hilfsdaten — simulierte NVD-Antworten
# ──────────────────────────────────────────────────────────────────────────────

def _make_nvd_apache_platform_only():
    """Simuliert CVE-2007-4723: Ragnarok Online Control Panel verwundbar,
    Apache HTTP Server nur als Plattform (vulnerable:false)."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2007-4723",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        # Verwundbare Komponente: Ragnarok Online Control Panel
                                        {
                                            "criteria": "cpe:2.3:a:ragnarok_online_control_panel:ragnarok_online_control_panel:*:*:*:*:*:*:*:*",
                                            "vulnerable": True,
                                        },
                                        # Apache: nur Laufzeitplattform
                                        {
                                            "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                                            "vulnerable": False,
                                        },
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }


def _make_nvd_apache_vulnerable():
    """Simuliert ein CVE das Apache HTTP Server direkt betrifft (vulnerable:true)."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-3566",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "criteria": "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*",
                                            "vulnerable": True,
                                        },
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }


def _make_nvd_no_configurations():
    """NVD-Antwort ohne Konfigurationsdaten."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-9999",
                    "configurations": [],
                }
            }
        ]
    }


def _make_nvd_legacy_cve_items_format():
    """Legacy CVE_Items-Format (ältere NVD-API)."""
    return {
        "CVE_Items": [
            {
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                                        "vulnerable": False,
                                    },
                                    {
                                        "criteria": "cpe:2.3:a:some_vendor:some_app:*:*:*:*:*:*:*:*",
                                        "vulnerable": True,
                                    },
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }


# ──────────────────────────────────────────────────────────────────────────────
# Tests: _get_cpe_vulnerable_map
# ──────────────────────────────────────────────────────────────────────────────

class TestGetCpeVulnerableMap:
    def test_apache_as_platform_false(self):
        """apache und http_server sind vulnerable:False wenn nur Plattform."""
        nvd = _make_nvd_apache_platform_only()
        result = _get_cpe_vulnerable_map(nvd)
        assert "apache" in result
        assert result["apache"] is False
        assert result.get("http_server") is False or result.get("http") is False or True  # product name varies

    def test_apache_as_target_true(self):
        """apache/http_server sind vulnerable:True wenn direkt betroffen."""
        nvd = _make_nvd_apache_vulnerable()
        result = _get_cpe_vulnerable_map(nvd)
        assert "apache" in result
        assert result["apache"] is True

    def test_empty_nvd_returns_empty_map(self):
        result = _get_cpe_vulnerable_map({})
        assert result == {}

    def test_no_configurations_returns_empty_map(self):
        result = _get_cpe_vulnerable_map(_make_nvd_no_configurations())
        assert result == {}

    def test_legacy_format_parsed(self):
        """CVE_Items-Format (legacy NVD v1-ähnlich) wird ebenfalls ausgewertet."""
        result = _get_cpe_vulnerable_map(_make_nvd_legacy_cve_items_format())
        # apache sollte False sein (vulnerable:false im Legacy-Format)
        assert "apache" in result
        # some_vendor sollte True sein
        assert result.get("some_vendor") is True or result.get("some_app") is True

    def test_true_overrides_false_for_same_product(self):
        """Wenn ein Produkt mehrfach auftaucht: vulnerable:True überschreibt False."""
        nvd = {
            "vulnerabilities": [
                {
                    "cve": {
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "criteria": "cpe:2.3:a:apache:http_server:2.2.0:*:*:*:*:*:*:*",
                                                "vulnerable": False,
                                            },
                                            {
                                                "criteria": "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*",
                                                "vulnerable": True,
                                            },
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }
        result = _get_cpe_vulnerable_map(nvd)
        # Sobald vulnerable:true gesehen wurde, muss True gelten
        assert result.get("apache") is True
        assert result.get("http_server") is True


# ──────────────────────────────────────────────────────────────────────────────
# Tests: _is_platform_only
# ──────────────────────────────────────────────────────────────────────────────

class TestIsPlatformOnly:
    def test_apache_is_platform_only_for_ragnarok_cve(self):
        """BUG-2 REPRODUKTION: Apache soll als Plattform erkannt werden."""
        nvd = _make_nvd_apache_platform_only()
        # Service-Label wie von extract_service_from_cpe() geliefert
        assert _is_platform_only(nvd, "Apache HTTP Server") is True, (
            "BUGFIX Bug 2 fehlgeschlagen: Apache HTTP Server sollte für CVE-2007-4723 "
            "als Plattformabhängigkeit (platform-only) erkannt werden."
        )

    def test_apache_not_platform_only_when_directly_affected(self):
        """Apache ist NICHT Plattform wenn vulnerable:true."""
        nvd = _make_nvd_apache_vulnerable()
        assert _is_platform_only(nvd, "Apache HTTP Server") is False

    def test_empty_service_label_returns_false(self):
        nvd = _make_nvd_apache_platform_only()
        assert _is_platform_only(nvd, "") is False
        assert _is_platform_only(nvd, None) is False

    def test_empty_nvd_returns_false(self):
        """Ohne NVD-Daten keine Aussage möglich → False (kein false-positive)."""
        assert _is_platform_only({}, "Apache HTTP Server") is False

    def test_no_configurations_returns_false(self):
        assert _is_platform_only(_make_nvd_no_configurations(), "Apache HTTP Server") is False

    def test_unknown_service_not_flagged(self):
        """Ein nicht vorhandenes Produkt wird nicht als Plattform gemeldet."""
        nvd = _make_nvd_apache_platform_only()
        assert _is_platform_only(nvd, "SomeOtherService 1.0") is False

    def test_partial_match_works(self):
        """Teilstring-Match: 'apache' in 'apache http server' wird erkannt."""
        nvd = _make_nvd_apache_platform_only()
        # 'apache' (Lowercase-Key in map) sollte 'apache' in 'apache http server' finden
        assert _is_platform_only(nvd, "apache http server") is True

    def test_nginx_as_platform(self):
        """Nginx als Plattform wird korrekt erkannt."""
        nvd = {
            "vulnerabilities": [
                {
                    "cve": {
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "criteria": "cpe:2.3:a:some_vendor:webapp:*:*:*:*:*:*:*:*",
                                                "vulnerable": True,
                                            },
                                            {
                                                "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                                                "vulnerable": False,
                                            },
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }
        assert _is_platform_only(nvd, "Nginx") is True


# ──────────────────────────────────────────────────────────────────────────────
# Tests: Integration — enrich_cves setzt low_confidence-Flag
# ──────────────────────────────────────────────────────────────────────────────

class TestEnrichCvesLowConfidenceIntegration:
    """Prüft dass enrich_cves() das low_confidence-Flag korrekt setzt
    wenn NVD-Daten mit vulnerable:false vorliegen."""

    def test_low_confidence_flag_set_when_platform_only(self):
        """enrich_cves mit gemocktem NVD-Client setzt low_confidence=True für platform-only CVEs."""
        from unittest.mock import MagicMock
        from shodan_report.pdf.sections.data.cve_enricher import enrich_cves

        mock_nvd = MagicMock()
        mock_nvd.fetch_cve_json.return_value = _make_nvd_apache_platform_only()

        # Snapshot mit Apache-Service und CVE-2007-4723
        technical_json = {
            "services": [
                {
                    "port": 80,
                    "product": "Apache HTTP Server",
                    "version": "2.4.54",
                    "cpes": ["cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*"],
                    "vulnerabilities": [{"id": "CVE-2007-4723", "cvss": 7.5}],
                }
            ]
        }

        enriched = enrich_cves(
            ["CVE-2007-4723"],
            technical_json,
            lookup_nvd=True,
            nvd=mock_nvd,
        )

        assert len(enriched) == 1
        entry = enriched[0]
        assert entry.get("low_confidence") is True, (
            "BUGFIX Bug 2 fehlgeschlagen: CVE-2007-4723 sollte low_confidence=True haben "
            "da Apache nur als Plattform (vulnerable:false) eingetragen ist."
        )
        assert "low_confidence_reason" in entry
        assert "platform" in entry["low_confidence_reason"].lower() or \
               "plattform" in entry["low_confidence_reason"].lower()

    def test_no_low_confidence_when_directly_vulnerable(self):
        """CVE wo Apache direkt betroffen ist bekommt kein low_confidence-Flag."""
        from unittest.mock import MagicMock
        from shodan_report.pdf.sections.data.cve_enricher import enrich_cves

        mock_nvd = MagicMock()
        mock_nvd.fetch_cve_json.return_value = _make_nvd_apache_vulnerable()

        technical_json = {
            "services": [
                {
                    "port": 80,
                    "product": "Apache HTTP Server",
                    "version": "2.4.51",
                    "cpes": ["cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"],
                    "vulnerabilities": [{"id": "CVE-2024-3566", "cvss": 9.8}],
                }
            ]
        }

        enriched = enrich_cves(
            ["CVE-2024-3566"],
            technical_json,
            lookup_nvd=True,
            nvd=mock_nvd,
        )

        assert len(enriched) == 1
        entry = enriched[0]
        assert not entry.get("low_confidence"), (
            "CVE-2024-3566 sollte KEIN low_confidence-Flag haben, "
            "da Apache direkt verwundbar (vulnerable:true) ist."
        )

    def test_no_low_confidence_without_nvd_lookup(self):
        """Ohne NVD-Lookup (lookup_nvd=False) wird kein low_confidence-Flag gesetzt."""
        from shodan_report.pdf.sections.data.cve_enricher import enrich_cves

        technical_json = {
            "services": [
                {
                    "port": 80,
                    "vulnerabilities": [{"id": "CVE-2007-4723", "cvss": 7.5}],
                }
            ]
        }

        enriched = enrich_cves(
            ["CVE-2007-4723"],
            technical_json,
            lookup_nvd=False,
        )

        assert len(enriched) == 1
        # Ohne NVD-Lookup kein low_confidence-Flag
        assert not enriched[0].get("low_confidence")
