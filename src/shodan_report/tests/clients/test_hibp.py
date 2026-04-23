"""Tests für shodan_report.clients.hibp"""
from unittest.mock import MagicMock, patch

import pytest

from shodan_report.clients.hibp import (
    check_breaches,
    _build_email_list,
    _hibp_url,
)


class TestBuildEmailList:
    def test_standard_prefixes_from_domain(self):
        emails = _build_email_list("example.de")
        assert any("info@example.de" in e for e in emails)
        assert any("admin@example.de" in e for e in emails)

    def test_extra_emails_appended(self):
        emails = _build_email_list("example.de", extra_emails=["ceo@example.de"])
        assert "ceo@example.de" in emails

    def test_no_duplicates(self):
        emails = _build_email_list("example.de", extra_emails=["info@example.de"])
        assert emails.count("info@example.de") == 1

    def test_empty_domain_returns_only_extras(self):
        emails = _build_email_list("", extra_emails=["custom@test.de"])
        assert "custom@test.de" in emails

    def test_extra_none_safe(self):
        emails = _build_email_list("example.de", extra_emails=None)
        assert isinstance(emails, list)
        assert len(emails) > 0


class TestHibpUrl:
    def test_at_sign_encoded(self):
        url = _hibp_url("info@example.de")
        assert "%40" in url
        assert "@" not in url.split("haveibeenpwned.com/account/")[1]

    def test_url_structure(self):
        url = _hibp_url("test@test.de")
        assert url.startswith("https://haveibeenpwned.com/account/")


class TestCheckBreachesManualMode:
    def test_no_api_key_returns_manual_mode(self):
        with patch.dict("os.environ", {}, clear=True):
            result = check_breaches("example.de")
        assert result["mode"] == "manual"

    def test_manual_mode_has_emails(self):
        with patch.dict("os.environ", {}, clear=True):
            result = check_breaches("example.de")
        assert len(result["emails"]) > 0

    def test_manual_mode_total_breached_none(self):
        with patch.dict("os.environ", {}, clear=True):
            result = check_breaches("example.de")
        assert result["total_breached"] is None

    def test_manual_mode_all_entries_have_check_url(self):
        with patch.dict("os.environ", {}, clear=True):
            result = check_breaches("example.de")
        for e in result["emails"]:
            assert "check_url" in e
            assert e["check_url"].startswith("https://")

    def test_manual_mode_breached_is_none(self):
        with patch.dict("os.environ", {}, clear=True):
            result = check_breaches("example.de")
        for e in result["emails"]:
            assert e["breached"] is None

    def test_empty_domain_no_crash(self):
        result = check_breaches("")
        assert "mode" in result
        assert "emails" in result

    def test_extra_emails_in_result(self):
        with patch.dict("os.environ", {}, clear=True):
            result = check_breaches("example.de", extra_emails=["boss@example.de"])
        addrs = [e["email"] for e in result["emails"]]
        assert "boss@example.de" in addrs


class TestCheckBreachesApiMode:
    def _make_response(self, status_code, data=None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.json.return_value = data or []
        return resp

    def test_api_mode_breached_email(self):
        breaches = [{"Name": "LinkedIn"}, {"Name": "Dropbox"}]
        with patch("shodan_report.clients.hibp._requests") as m, \
             patch("shodan_report.clients.hibp.time") as t:
            m.get.return_value = self._make_response(200, breaches)
            result = check_breaches("example.de", api_key="testkey")
        assert result["mode"] == "api"
        first_breached = next(e for e in result["emails"] if e.get("breached"))
        assert first_breached["breach_count"] == 2
        assert "LinkedIn" in first_breached["breach_names"]

    def test_api_mode_clean_email(self):
        with patch("shodan_report.clients.hibp._requests") as m, \
             patch("shodan_report.clients.hibp.time"):
            m.get.return_value = self._make_response(404)
            result = check_breaches("example.de", api_key="testkey")
        for e in result["emails"]:
            assert e["breached"] is False

    def test_api_mode_total_breached_count(self):
        def side_effect(url, **kwargs):
            if "info@" in url:
                return self._make_response(200, [{"Name": "Test"}])
            return self._make_response(404)

        with patch("shodan_report.clients.hibp._requests") as m, \
             patch("shodan_report.clients.hibp.time"):
            m.get.side_effect = side_effect
            result = check_breaches("example.de", api_key="testkey")
        assert result["total_breached"] >= 1

    def test_api_mode_network_error_falls_back_to_manual_entry(self):
        with patch("shodan_report.clients.hibp._requests") as m, \
             patch("shodan_report.clients.hibp.time"):
            m.get.side_effect = Exception("Timeout")
            result = check_breaches("example.de", api_key="testkey")
        assert result["mode"] == "api"
        for e in result["emails"]:
            assert e["breached"] is None

    def test_api_key_from_env(self):
        with patch("shodan_report.clients.hibp._requests") as m, \
             patch("shodan_report.clients.hibp.time"), \
             patch.dict("os.environ", {"HIBP_API_KEY": "envkey"}):
            m.get.return_value = self._make_response(404)
            result = check_breaches("example.de")
        assert result["mode"] == "api"
