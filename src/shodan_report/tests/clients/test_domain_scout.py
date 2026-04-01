"""
Tests für domain_scout.py — ohne Netzwerk-Calls.

Alle externen Funktionen (_resolve_a, _resolve_mx, _resolve_ns, _reverse_dns,
_fetch_crtsh, _fetch_hackertarget) werden gemockt, damit die Tests offline
und deterministisch laufen.
"""

import pytest
from unittest.mock import patch

from shodan_report.clients.domain_scout import (
    AttackSurface,
    ScoutedIP,
    _check_cdn,
    scout_domain,
)


# ─── Unit: _check_cdn ─────────────────────────────────────────────────────────

class TestCheckCdn:
    def test_cloudflare_ip_detected(self):
        # 104.16.x.x liegt in Cloudflare 104.16.0.0/13
        assert _check_cdn("104.16.1.1") == "Cloudflare"

    def test_akamai_ip_detected(self):
        # 23.32.x.x liegt in Akamai 23.32.0.0/11
        assert _check_cdn("23.32.0.1") == "Akamai"

    def test_fastly_ip_detected(self):
        # 151.101.x.x liegt in Fastly 151.101.0.0/16
        assert _check_cdn("151.101.1.1") == "Fastly"

    def test_aws_cloudfront_detected(self):
        # 13.32.x.x liegt in AWS CloudFront
        assert _check_cdn("13.32.0.1") == "AWS CloudFront"

    def test_non_cdn_ip_returns_none(self):
        assert _check_cdn("185.146.238.111") is None
        assert _check_cdn("8.8.8.8") is None
        assert _check_cdn("1.1.1.1") is None

    def test_invalid_ip_returns_none(self):
        assert _check_cdn("not-an-ip") is None
        assert _check_cdn("") is None


# ─── Unit: ScoutedIP ──────────────────────────────────────────────────────────

class TestScoutedIP:
    def test_is_cdn_true(self):
        sip = ScoutedIP(ip="104.16.1.1", sources=["A-Record (example.com)"], cdn="Cloudflare")
        assert sip.is_cdn is True

    def test_is_cdn_false(self):
        sip = ScoutedIP(ip="1.2.3.4", sources=["A-Record (example.com)"])
        assert sip.is_cdn is False

    def test_is_mail_true(self):
        sip = ScoutedIP(ip="1.2.3.4", sources=["MX (mail.example.com)"])
        assert sip.is_mail is True

    def test_is_mail_false(self):
        sip = ScoutedIP(ip="1.2.3.4", sources=["A-Record (example.com)"])
        assert sip.is_mail is False

    def test_is_nameserver_true(self):
        sip = ScoutedIP(ip="1.2.3.4", sources=["NS (ns1.example.com)"])
        assert sip.is_nameserver is True

    def test_is_nameserver_false(self):
        sip = ScoutedIP(ip="1.2.3.4", sources=["A-Record (example.com)"])
        assert sip.is_nameserver is False


# ─── Unit: AttackSurface.primary_ip ──────────────────────────────────────────

class TestAttackSurfacePrimaryIp:
    def _make(self, relevant=None, cdn=None):
        return AttackSurface(
            domain="example.com",
            relevant_ips=relevant or [],
            cdn_ips=cdn or [],
        )

    def test_prefers_a_record_over_mx(self):
        a_rec = ScoutedIP(ip="1.1.1.1", sources=["A-Record (example.com)"])
        mx_rec = ScoutedIP(ip="2.2.2.2", sources=["MX (mail.example.com)"])
        surface = self._make(relevant=[mx_rec, a_rec])
        assert surface.primary_ip == "1.1.1.1"

    def test_prefers_non_www_a_record(self):
        www = ScoutedIP(ip="2.2.2.2", sources=["A-Record (www.example.com)"])
        apex = ScoutedIP(ip="1.1.1.1", sources=["A-Record (example.com)"])
        surface = self._make(relevant=[www, apex])
        assert surface.primary_ip == "1.1.1.1"

    def test_falls_back_to_www_a_record(self):
        www = ScoutedIP(ip="2.2.2.2", sources=["A-Record (www.example.com)"])
        surface = self._make(relevant=[www])
        assert surface.primary_ip == "2.2.2.2"

    def test_falls_back_to_mx(self):
        mx_rec = ScoutedIP(ip="3.3.3.3", sources=["MX (mail.example.com)"])
        surface = self._make(relevant=[mx_rec])
        assert surface.primary_ip == "3.3.3.3"

    def test_falls_back_to_first(self):
        ip = ScoutedIP(ip="4.4.4.4", sources=["NS (ns1.example.com)"])
        surface = self._make(relevant=[ip])
        assert surface.primary_ip == "4.4.4.4"

    def test_returns_none_when_no_relevant_ips(self):
        surface = self._make(relevant=[])
        assert surface.primary_ip is None

    def test_total_found(self):
        r = ScoutedIP(ip="1.1.1.1", sources=["A-Record (example.com)"])
        c = ScoutedIP(ip="104.16.1.1", sources=["A-Record (example.com)"], cdn="Cloudflare")
        surface = self._make(relevant=[r], cdn=[c])
        assert surface.total_found == 2


# ─── Integration: scout_domain mit gemockten Netzwerk-Calls ──────────────────

_MOCK_PATCH_BASE = "shodan_report.clients.domain_scout"


class TestScoutDomain:
    """Testet scout_domain mit vollständig gemockten I/O-Funktionen."""

    def _run(self, a_records=None, www_a_records=None, mx_ips=None, ns_ips=None,
             crtsh=None, hackertarget=None, reverse=None):
        """Hilfsmethode: scout_domain mit kontrollierten Mocks ausführen."""

        def fake_resolve_a(domain):
            if domain.startswith("www."):
                return www_a_records or []
            return a_records or []

        with patch(f"{_MOCK_PATCH_BASE}._resolve_a", side_effect=fake_resolve_a), \
             patch(f"{_MOCK_PATCH_BASE}._resolve_mx", return_value=mx_ips or []), \
             patch(f"{_MOCK_PATCH_BASE}._resolve_ns", return_value=ns_ips or []), \
             patch(f"{_MOCK_PATCH_BASE}._reverse_dns", return_value=reverse), \
             patch(f"{_MOCK_PATCH_BASE}._fetch_crtsh", return_value=crtsh or []), \
             patch(f"{_MOCK_PATCH_BASE}._fetch_hackertarget", return_value=hackertarget or []):
            return scout_domain("example.com")

    def test_single_a_record_non_cdn(self):
        surface = self._run(a_records=["1.2.3.4"])
        assert len(surface.relevant_ips) == 1
        assert surface.relevant_ips[0].ip == "1.2.3.4"
        assert len(surface.cdn_ips) == 0

    def test_cloudflare_ip_goes_to_cdn_ips(self):
        surface = self._run(a_records=["104.16.1.1"])
        assert len(surface.cdn_ips) == 1
        assert surface.cdn_ips[0].cdn == "Cloudflare"
        assert len(surface.relevant_ips) == 0

    def test_domain_normalized_from_url(self):
        with patch(f"{_MOCK_PATCH_BASE}._resolve_a", return_value=[]), \
             patch(f"{_MOCK_PATCH_BASE}._resolve_mx", return_value=[]), \
             patch(f"{_MOCK_PATCH_BASE}._resolve_ns", return_value=[]), \
             patch(f"{_MOCK_PATCH_BASE}._reverse_dns", return_value=None), \
             patch(f"{_MOCK_PATCH_BASE}._fetch_crtsh", return_value=[]), \
             patch(f"{_MOCK_PATCH_BASE}._fetch_hackertarget", return_value=[]):
            surface = scout_domain("https://example.com/some/path")
        assert surface.domain == "example.com"

    def test_duplicate_ips_merged(self):
        """Gleiche IP aus A-Record und MX darf nur einmal erscheinen."""
        surface = self._run(a_records=["5.5.5.5"], mx_ips=["5.5.5.5"])
        ips = [s.ip for s in surface.relevant_ips]
        assert ips.count("5.5.5.5") == 1

    def test_mx_source_tagged(self):
        surface = self._run(mx_ips=["9.9.9.9"])
        assert any("MX" in src for src in surface.relevant_ips[0].sources)

    def test_primary_ip_is_a_record(self):
        surface = self._run(a_records=["1.2.3.4"], mx_ips=["9.9.9.9"])
        assert surface.primary_ip == "1.2.3.4"

    def test_primary_ip_fallback_to_mx_when_no_a(self):
        surface = self._run(mx_ips=["9.9.9.9"])
        assert surface.primary_ip == "9.9.9.9"

    def test_subdomains_from_crtsh(self):
        surface = self._run(crtsh=["mail.example.com", "dev.example.com"])
        assert "mail.example.com" in surface.subdomains

    def test_hackertarget_ips_added(self):
        surface = self._run(hackertarget=[("sub.example.com", "7.7.7.7")])
        ips = [s.ip for s in surface.relevant_ips]
        assert "7.7.7.7" in ips

    def test_primary_ip_none_when_all_cdn(self):
        """Alle IPs sind CDN → relevant_ips leer → primary_ip None."""
        surface = self._run(a_records=["104.16.1.1"])
        assert surface.primary_ip is None

    def test_total_found_combines_relevant_and_cdn(self):
        surface = self._run(a_records=["1.2.3.4"], www_a_records=["104.16.1.1"])
        assert surface.total_found == len(surface.relevant_ips) + len(surface.cdn_ips)

    def test_empty_domain_returns_empty_surface(self):
        surface = self._run()
        assert surface.relevant_ips == []
        assert surface.cdn_ips == []
        assert surface.subdomains == []
        assert surface.primary_ip is None
