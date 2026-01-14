# tests/archiver/test_report_archiver.py
import pytest
from pathlib import Path
import tempfile
import shutil
from shodan_report.archiver.report_archiver import ReportArchiver
from shodan_report.utils.slug import create_slug


def test_create_slug():
    assert create_slug("MG Solutions GmbH") == "mg_solutions_gmbh"
    assert (
        create_slug("CHINANET HUBEI PROVINCE NETWORK")
        == "chinanet_hubei_province_network"
    )
    assert create_slug("Test & More!") == "test_more"
    assert create_slug("") == "unknown"


def test_report_archiver_initialization():
    with tempfile.TemporaryDirectory() as tmpdir:
        archiver = ReportArchiver(Path(tmpdir) / "archive")
        assert archiver.archive_root.exists()
        assert archiver.version_manager is not None


def test_archive_report_basic(tmp_path):

    # Test-PDF erstellen
    pdf_path = tmp_path / "test.pdf"
    pdf_path.write_text("PDF Content")

    # Archivierung testen
    archiver = ReportArchiver(tmp_path / "archive")
    metadata = archiver.archive_report(
        pdf_path=pdf_path, customer_name="Test Company", month="2025-01", ip="1.2.3.4"
    )

    # Prüfungen
    assert metadata["customer_slug"] == "test_company"
    assert metadata["version"] == 1
    assert metadata["month"] == "2025-01"
    assert metadata["ip"] == "1.2.3.4"
    assert "sha256" in metadata
    assert metadata["size_bytes"] == len("PDF Content")

    # Dateien existieren
    expected_pdf = (
        tmp_path / "archive" / "test_company" / "2025-01" / "2025-01_1.2.3.4_v1.pdf"
    )
    expected_meta = (
        tmp_path / "archive" / "test_company" / "2025-01" / "2025-01_1.2.3.4.meta.json"
    )

    assert expected_pdf.exists()
    assert expected_meta.exists()


def test_archive_report_versioning(tmp_path):
    pdf_path = tmp_path / "test.pdf"
    pdf_path.write_text("PDF Content")

    archiver = ReportArchiver(tmp_path / "archive")

    # Erste Version
    metadata1 = archiver.archive_report(pdf_path, "Test", "2025-01", "1.2.3.4")
    assert metadata1["version"] == 1

    # Zweite Version (gleicher Monat/IP)
    metadata2 = archiver.archive_report(pdf_path, "Test", "2025-01", "1.2.3.4")
    assert metadata2["version"] == 2

    # Dritte Version (anderer Monat)
    metadata3 = archiver.archive_report(pdf_path, "Test", "2025-02", "1.2.3.4")
    assert metadata3["version"] == 1  # Neuer Monat, beginnt bei 1


def test_find_previous_report(tmp_path):
    """Testet das Finden vorheriger Reports."""
    pdf_path = tmp_path / "test.pdf"
    pdf_path.write_text("PDF Content")

    archiver = ReportArchiver(tmp_path / "archive")

    # Report für Januar archivieren
    archiver.archive_report(pdf_path, "Test", "2025-01", "1.2.3.4")

    # Report für Februar archivieren
    archiver.archive_report(pdf_path, "Test", "2025-02", "1.2.3.4")

    # Vorherigen Report für Februar suchen (sollte Januar finden)
    prev_report = archiver.find_previous_report("Test", "2025-02", "1.2.3.4")
    assert prev_report is not None
    assert prev_report["month"] == "2025-01"
    assert prev_report["ip"] == "1.2.3.4"


def test_invalid_month_format(tmp_path):
    pdf_path = tmp_path / "test.pdf"
    pdf_path.write_text("PDF Content")

    archiver = ReportArchiver(tmp_path / "archive")

    with pytest.raises(ValueError):
        archiver.archive_report(
            pdf_path, "Test", "2025-13", "1.2.3.4"
        )  # Ungültiger Monat

    with pytest.raises(ValueError):
        archiver.archive_report(pdf_path, "Test", "invalid", "1.2.3.4")  # Kein Datum


def test_list_customer_reports(tmp_path):
    """Testet das Auflisten von Kunden-Reports."""
    pdf_path = tmp_path / "test.pdf"
    pdf_path.write_text("PDF Content")

    archiver = ReportArchiver(tmp_path / "archive")

    # Mehrere Reports erstellen
    archiver.archive_report(pdf_path, "Customer A", "2025-01", "1.2.3.4")
    archiver.archive_report(pdf_path, "Customer A", "2025-02", "1.2.3.4")
    archiver.archive_report(pdf_path, "Customer B", "2025-01", "5.6.7.8")

    # Kunden-Reports auflisten
    reports_a = archiver.list_customer_reports("Customer A")
    assert reports_a["customer"] == "Customer A"
    assert reports_a["total_reports"] == 2
    assert len(reports_a["months"]) == 2

    reports_b = archiver.list_customer_reports("Customer B")
    assert reports_b["total_reports"] == 1
    assert len(reports_b["months"]) == 1

    reports_c = archiver.list_customer_reports("Non Existent")
    assert reports_c["total_reports"] == 0


def test_archive_report_slug_consistency(tmp_path):
    """Testet dass Slugs konsistent in der Archivierung verwendet werden."""
    pdf_path = tmp_path / "test.pdf"
    pdf_path.write_text("PDF Content")

    archiver = ReportArchiver(tmp_path / "archive")

    # Teste verschiedene Kunden-Namen
    test_cases = [
        ("MG Solutions GmbH", "mg_solutions_gmbh"),
        ("Test & More!", "test_more"),
        ("CHINANET-HUBEI", "chinanet_hubei"),
        ("  Trimmed  Name  ", "trimmed_name"),
    ]

    for customer_name, expected_slug in test_cases:
        metadata = archiver.archive_report(
            pdf_path=pdf_path,
            customer_name=customer_name,
            month="2025-01",
            ip="1.2.3.4",
        )

        # Prüfe dass der Slug korrekt ist
        assert metadata["customer_slug"] == expected_slug

        # Prüfe dass das Verzeichnis mit korrektem Slug existiert
        expected_dir = tmp_path / "archive" / expected_slug / "2025-01"
        assert (
            expected_dir.exists()
        ), f"Verzeichnis für {customer_name} sollte existieren"

        print(f"✅ {customer_name} -> {expected_slug}")
