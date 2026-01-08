# tests/utils/test_slug.py
import pytest
from shodan_report.utils.slug import create_slug


def test_create_slug_basic():
    assert create_slug("MG Solutions GmbH") == "mg_solutions_gmbh"
    assert create_slug("CHINANET HUBEI PROVINCE NETWORK") == "chinanet_hubei_province_network"
    assert create_slug("Test & More Test!") == "test_more_test"
    assert create_slug("Test-Company Name") == "test_company_name"


def test_create_slug_special_characters():
    assert create_slug("Company & Co. KG") == "company_co_kg"
    assert create_slug("Test@Email.com") == "testemailcom"
    assert create_slug("Über-Änderung Österreich") == "uber_anderung_osterreich"  # Umlaute
    assert create_slug("Café René") == "cafe_rene"  # Akzente


def test_create_slug_empty_input():
    assert create_slug("") == "unknown"
    assert create_slug(None) == "unknown"  # None wird zu ""


def test_create_slug_max_length():
    text = "very_long_company_name_with_many_parts"
    result = create_slug(text, max_length=20)
    assert len(result) <= 20
    assert result == "very_long_company"  # Das ist korrekt!

def test_create_slug_whitespace():
    assert create_slug("  Spaces  Around  ") == "spaces_around"
    assert create_slug("Multiple   Spaces") == "multiple_spaces"
    assert create_slug("Tab\tSeparated") == "tab_separated"


def test_create_slug_consistent():
    slug1 = create_slug("Test Company")
    slug2 = create_slug("Test Company")
    slug3 = create_slug("test company")
    slug4 = create_slug("TEST COMPANY")
    
    assert slug1 == slug2 == slug3 == slug4 == "test_company"


def test_create_slug_edge_cases():
    """Testet Edge Cases."""
    # Nur Sonderzeichen
    assert create_slug("!@#$%^&*()") == "unknown"
    
    # Nur Zahlen
    assert create_slug("123 456") == "123_456"
    
    # Mixed
    assert create_slug("Company-123_Test") == "company_123_test"
    
    # Sehr lange mit Sonderzeichen
    long_mixed = "A" * 60 + "!@#" + "B" * 60
    result = create_slug(long_mixed, max_length=50)
    assert len(result) <= 50
    assert "_" not in result or result.endswith("_") == False


def test_create_slug_examples():
    """Testet konkrete Beispiele aus dem echten Code."""
    # Beispiele aus deinem Archiv
    assert create_slug("MG Solutions") == "mg_solutions"
    assert create_slug("CHINANET HUBEI PROVINCE NETWORK") == "chinanet_hubei_province_network"
    
    # Mögliche Kunden-Namen
    assert create_slug("Deutsche Bahn AG") == "deutsche_bahn_ag"
    assert create_slug("BMW Group München") == "bmw_group_munchen"
    assert create_slug("Siemens Healthineers") == "siemens_healthineers"