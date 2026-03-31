"""Tests for the EOL detection engine (evaluation.eol)."""

from datetime import date

import pytest

from shodan_report.evaluation.eol.eol_detector import (
    detect_eol,
    scan_services_for_eol,
)

TODAY = date(2026, 3, 31)


# ── detect_eol: Windows Server ────────────────────────────────────────────────

def test_windows_server_2016_detected_as_eol():
    """RDP banner with Windows Server 2016 in version string → eol."""
    result = detect_eol(
        "Remote Desktop Protocol",
        "Windows Server 2016 (version 1607) OS Build: 10.0.14393",
        today=TODAY,
    )
    assert result["eol_status"] == "eol"
    assert result["product_id"] == "windows_server_2016"
    assert result["confidence"] in ("high", "medium")


def test_windows_server_2019_is_eol():
    result = detect_eol(
        "Remote Desktop Protocol",
        "Windows Server 2019 OS Build: 17763",
        today=TODAY,
    )
    assert result["eol_status"] == "eol"
    assert result["product_id"] == "windows_server_2019"


def test_windows_server_2022_is_near_eol():
    """Mainstream support ends 2026-10-14 — 197 days away, within NEAR_EOL_DAYS=365."""
    result = detect_eol(
        "Remote Desktop Protocol",
        "Windows Server 2022 OS Build: 20348",
        today=TODAY,
    )
    assert result["eol_status"] == "near_eol"
    assert result["product_id"] == "windows_server_2022"


def test_windows_server_2022_is_supported_far_future():
    """When today is well before near-EOL window, status should be supported."""
    result = detect_eol(
        "Remote Desktop Protocol",
        "Windows Server 2022 OS Build: 20348",
        today=date(2024, 1, 1),
    )
    assert result["eol_status"] == "supported"


# ── detect_eol: Apache HTTP Server ───────────────────────────────────────────

def test_apache_22_is_eol():
    result = detect_eol("Apache httpd", "2.2.34", today=TODAY)
    assert result["eol_status"] == "eol"
    assert result["product_id"] == "apache_httpd_2_2"
    assert result["confidence"] == "high"


def test_apache_24_is_unknown():
    """Apache 2.4.x is still actively maintained — must NOT be flagged as EOL."""
    result = detect_eol("Apache httpd", "2.4.38", today=TODAY)
    assert result["eol_status"] == "unknown"
    assert result["product_id"] is None


# ── detect_eol: PHP ──────────────────────────────────────────────────────────

def test_php_74_is_eol():
    result = detect_eol("PHP", "7.4.33", today=TODAY)
    assert result["eol_status"] == "eol"
    assert result["product_id"] == "php_7_4"


def test_php_81_is_eol():
    """PHP 8.1 EOL was 2025-12-31 — past that date."""
    result = detect_eol("PHP", "8.1.25", today=TODAY)
    assert result["eol_status"] == "eol"
    assert result["product_id"] == "php_8_1"


def test_php_82_is_unknown():
    """PHP 8.2 is still supported — should return unknown (no entry in table)."""
    result = detect_eol("PHP", "8.2.5", today=TODAY)
    assert result["eol_status"] == "unknown"


# ── detect_eol: MySQL ────────────────────────────────────────────────────────

def test_mysql_57_is_eol():
    result = detect_eol("MySQL", "5.7.42", today=TODAY)
    assert result["eol_status"] == "eol"
    assert result["product_id"] == "mysql_5_7"


# ── detect_eol: OpenSSL ──────────────────────────────────────────────────────

def test_openssl_111_is_eol():
    result = detect_eol("OpenSSL", "1.1.1t", today=TODAY)
    assert result["eol_status"] == "eol"
    assert result["product_id"] == "openssl_1_1_1"


# ── detect_eol: unknown products ─────────────────────────────────────────────

def test_unknown_product_returns_unknown():
    result = detect_eol("SomeRandomVendorProduct", "3.7.2", today=TODAY)
    assert result["eol_status"] == "unknown"
    assert result["product_id"] is None
    assert result["eol_date"] is None


def test_empty_product_returns_unknown():
    result = detect_eol("", "1.0.0", today=TODAY)
    assert result["eol_status"] == "unknown"


# ── scan_services_for_eol ────────────────────────────────────────────────────

def test_scan_services_returns_only_eol_findings():
    services = [
        {"port": 80,   "product": "Apache httpd",           "version": "2.4.38"},
        {"port": 3389, "product": "Remote Desktop Protocol", "version": "Windows Server 2016 OS Build: 10.0.14393"},
        {"port": 3306, "product": "MySQL",                   "version": "5.7.41"},
    ]
    findings = scan_services_for_eol(services, today=TODAY)
    product_ids = {f["product_id"] for f in findings}
    assert "windows_server_2016" in product_ids
    assert "mysql_5_7" in product_ids
    # Apache 2.4.x must NOT appear
    assert not any(
        (f.get("product_id") or "").startswith("apache_httpd")
        for f in findings
    )


def test_scan_deduplicates_same_product_on_multiple_ports():
    """Same EOL product detected on two ports → exactly one finding."""
    services = [
        {"port": 80,  "product": "Apache httpd", "version": "2.2.15"},
        {"port": 443, "product": "Apache httpd", "version": "2.2.15"},
    ]
    findings = scan_services_for_eol(services, today=TODAY)
    assert len(findings) == 1
    assert findings[0]["product_id"] == "apache_httpd_2_2"


def test_scan_empty_services_returns_empty():
    assert scan_services_for_eol([], today=TODAY) == []


def test_scan_services_near_eol_included():
    """near_eol findings must be included in the result."""
    services = [
        {"port": 3389, "product": "Remote Desktop Protocol", "version": "Windows Server 2022 OS Build: 20348"},
    ]
    findings = scan_services_for_eol(services, today=TODAY)
    assert len(findings) == 1
    assert findings[0]["eol_status"] == "near_eol"
    assert findings[0]["port"] == 3389


def test_scan_result_includes_port():
    services = [
        {"port": 3306, "product": "MySQL", "version": "5.7.28"},
    ]
    findings = scan_services_for_eol(services, today=TODAY)
    assert findings[0]["port"] == 3306


# ── support_model field ───────────────────────────────────────────────────────

def test_windows_server_result_has_mainstream_end_model():
    result = detect_eol(
        "Remote Desktop Protocol",
        "Windows Server 2016 OS Build: 10.0.14393",
        today=TODAY,
    )
    assert result["support_model"] == "mainstream_end"


def test_apache_result_has_official_model():
    result = detect_eol("Apache httpd", "2.2.34", today=TODAY)
    assert result["support_model"] == "official"


def test_php_result_has_official_model():
    result = detect_eol("PHP", "7.4.1", today=TODAY)
    assert result["support_model"] == "official"
