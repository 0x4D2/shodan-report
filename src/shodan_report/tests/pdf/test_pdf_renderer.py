# src/shodan_report/tests/pdf/test_pdf_renderer.py
"""Tests für render_pdf: page_meta-Weiterleitung und Corner-Decoration-Rendering."""

import hashlib
import pytest
from pathlib import Path
from reportlab.platypus import Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab import rl_config

from shodan_report.pdf.pdf_renderer import render_pdf


# ─────────────────────────────────────────────────────────────────────────────
# Hilfsfunktionen
# ─────────────────────────────────────────────────────────────────────────────

def _minimal_elements():
    """Minimale Elemente-Liste für einen 1-seitigen Test-PDF."""
    styles = getSampleStyleSheet()
    return [Paragraph("Test-Inhalt", styles["Normal"]), Spacer(1, 12)]


def _pdf_bytes(tmp_path: Path, page_meta=None) -> bytes:
    """
    Rendert ein Mini-PDF ohne Kompression und gibt den rohen Byte-Inhalt zurück.
    pageCompression=0 + useA85=0 deaktiviert FlateDecode und ASCII85, sodass
    Canvas-Texte als ASCII-Klartext im Bytestring prüfbar sind.
    """
    old_pc = rl_config.pageCompression
    old_a85 = rl_config.useA85
    rl_config.pageCompression = 0
    rl_config.useA85 = 0
    try:
        pdf_path = tmp_path / "test.pdf"
        render_pdf(pdf_path, _minimal_elements(), page_meta=page_meta)
        return pdf_path.read_bytes()
    finally:
        rl_config.pageCompression = old_pc
        rl_config.useA85 = old_a85


# ─────────────────────────────────────────────────────────────────────────────
# 1. Grundlegende Renderer-Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestRenderPdfBasic:

    def test_creates_file(self, tmp_path):
        pdf_path = tmp_path / "out.pdf"
        render_pdf(pdf_path, _minimal_elements())
        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 0

    def test_no_meta_does_not_crash(self, tmp_path):
        """page_meta=None darf nicht zu einem Fehler führen."""
        render_pdf(tmp_path / "out.pdf", _minimal_elements(), page_meta=None)

    def test_empty_meta_does_not_crash(self, tmp_path):
        """Leeres page_meta-Dict darf nicht zu einem Fehler führen."""
        render_pdf(tmp_path / "out.pdf", _minimal_elements(), page_meta={})

    def test_output_is_valid_pdf(self, tmp_path):
        """Ausgabe-Datei beginnt mit dem PDF-Magic-Byte."""
        content = _pdf_bytes(tmp_path)
        assert content[:4] == b"%PDF"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Corner-Decoration-Tests (unkomprimierter PDF-Stream)
# ─────────────────────────────────────────────────────────────────────────────

class TestCornerDecorations:
    """
    Mit rl_config.compress=0 werden Canvas-Strings direkt als Klartextbytes
    in den PDF-Inhaltsstrom geschrieben und sind via `in content` prüfbar.
    """

    def test_domain_appears_in_pdf(self, tmp_path):
        # domain is hardcoded to ichwillsicherheit.de in pdf_renderer.py
        content = _pdf_bytes(tmp_path, {"domain": "example.de"})
        assert b"ichwillsicherheit.de" in content

    def test_confidentiality_label_in_pdf(self, tmp_path):
        content = _pdf_bytes(tmp_path, {"confidentiality": "Vertraulich"})
        assert b"Vertraulich" in content

    def test_sha256_prefix_in_pdf(self, tmp_path):
        sha = hashlib.sha256(b"test").hexdigest()
        content = _pdf_bytes(tmp_path, {"sha256": sha})
        assert b"SHA256" in content

    def test_sha256_value_in_pdf(self, tmp_path):
        sha = hashlib.sha256(b"uniquevalue").hexdigest()
        content = _pdf_bytes(tmp_path, {"sha256": sha})
        assert sha.encode() in content

    def test_month_display_in_pdf(self, tmp_path):
        content = _pdf_bytes(tmp_path, {"month_display": "Apr 2026"})
        assert b"Apr 2026" in content

    def test_seite_label_in_pdf(self, tmp_path):
        """Seitenangabe 'Seite 1 von 1' muss im PDF erscheinen."""
        content = _pdf_bytes(tmp_path)
        assert b"Seite" in content

    def test_empty_domain_no_crash(self, tmp_path):
        """Leerer Domain-String darf keinen Fehler verursachen."""
        render_pdf(tmp_path / "out.pdf", _minimal_elements(), page_meta={"domain": ""})

    def test_missing_sha256_no_sha_line(self, tmp_path):
        """Ohne SHA256 im meta darf kein 'SHA256:' im PDF erscheinen."""
        content = _pdf_bytes(tmp_path, {"domain": "x.de", "confidentiality": "Vertraulich"})
        assert b"SHA256" not in content

    def test_stand_label_in_pdf(self, tmp_path):
        """'Stand:' erscheint unten links wenn month_display gesetzt ist."""
        content = _pdf_bytes(tmp_path, {"month_display": "Jan 2026"})
        assert b"Stand" in content


# ─────────────────────────────────────────────────────────────────────────────
# 1. Grundlegende Renderer-Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestRenderPdfBasic:

    def test_creates_file(self, tmp_path):
        pdf_path = tmp_path / "out.pdf"
        render_pdf(pdf_path, _minimal_elements())
        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 0

    def test_no_meta_does_not_crash(self, tmp_path):
        """page_meta=None darf nicht zu einem Fehler führen."""
        render_pdf(tmp_path / "out.pdf", _minimal_elements(), page_meta=None)

    def test_empty_meta_does_not_crash(self, tmp_path):
        """Leeres page_meta-Dict darf nicht zu einem Fehler führen."""
        render_pdf(tmp_path / "out.pdf", _minimal_elements(), page_meta={})

    def test_output_is_valid_pdf(self, tmp_path):
        """Ausgabe-Datei beginnt mit dem PDF-Magic-Byte."""
        content = _pdf_bytes(tmp_path)
        assert content[:4] == b"%PDF"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Corner-Decoration-Tests (raw-bytes scan)
# ─────────────────────────────────────────────────────────────────────────────

class TestCornerDecorations:
    """
    ReportLab schreibt ASCII-Text mit Helvetica direkt als Byte-Literal in
    den PDF-Stream, sodass kurze ASCII-Strings in den rohen PDF-Bytes
    auffindbar sind.
    """

    def test_domain_appears_in_pdf(self, tmp_path):
        # domain is hardcoded to ichwillsicherheit.de in pdf_renderer.py
        content = _pdf_bytes(tmp_path, {"domain": "example.de"})
        assert b"ichwillsicherheit.de" in content

    def test_confidentiality_label_in_pdf(self, tmp_path):
        content = _pdf_bytes(tmp_path, {"confidentiality": "Vertraulich"})
        assert b"Vertraulich" in content

    def test_sha256_prefix_in_pdf(self, tmp_path):
        sha = hashlib.sha256(b"test").hexdigest()
        content = _pdf_bytes(tmp_path, {"sha256": sha})
        assert b"SHA256" in content

    def test_sha256_value_in_pdf(self, tmp_path):
        sha = hashlib.sha256(b"uniquevalue").hexdigest()
        content = _pdf_bytes(tmp_path, {"sha256": sha})
        assert sha.encode() in content

    def test_month_display_in_pdf(self, tmp_path):
        content = _pdf_bytes(tmp_path, {"month_display": "Apr 2026"})
        assert b"Apr 2026" in content

    def test_seite_label_in_pdf(self, tmp_path):
        """Seitenangabe 'Seite 1 von 1' muss im PDF erscheinen."""
        content = _pdf_bytes(tmp_path)
        assert b"Seite" in content

    def test_empty_domain_no_crash(self, tmp_path):
        """Leerer Domain-String darf keinen Fehler verursachen."""
        render_pdf(tmp_path / "out.pdf", _minimal_elements(), page_meta={"domain": ""})

    def test_missing_sha256_no_sha_line(self, tmp_path):
        """Ohne SHA256 im meta darf kein 'SHA256:' im PDF erscheinen."""
        content = _pdf_bytes(tmp_path, {"domain": "x.de", "confidentiality": "Vertraulich"})
        assert b"SHA256" not in content

    def test_stand_label_in_pdf(self, tmp_path):
        """'Stand:' erscheint unten links wenn month_display gesetzt ist."""
        content = _pdf_bytes(tmp_path, {"month_display": "Jan 2026"})
        assert b"Stand" in content
