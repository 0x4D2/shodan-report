import hashlib
import pytest
from pathlib import Path
from unittest.mock import MagicMock, call
from shodan_report.pdf import pdf_generator
from shodan_report.pdf.pdf_generator import generate_pdf
from shodan_report.evaluation.evaluation import Evaluation, RiskLevel


def test_generate_pdf_calls_renderer_and_returns_path(tmp_path, monkeypatch):
    customer = "Acme Inc"
    month = "2026-01"
    ip = "1.2.3.4"
    mgmt = "management text"
    trend = "trend text"
    technical = {"open_ports": []}

    mock_evaluation = Evaluation(ip=ip, risk=RiskLevel.MEDIUM, critical_points=[])
    mock_business_risk = "medium"

    elements = [{"type": "header", "text": "Acme"}]
    prepare_mock = MagicMock(return_value=elements)
    render_mock = MagicMock()

    monkeypatch.setattr(pdf_generator, "prepare_pdf_elements", prepare_mock)
    monkeypatch.setattr(pdf_generator, "render_pdf", render_mock)

    result_path = generate_pdf(
        customer_name=customer,
        month=month,
        ip=ip,
        management_text=mgmt,
        trend_text=trend,
        technical_json=technical,
        evaluation=mock_evaluation,
        business_risk=mock_business_risk,
        output_dir=tmp_path / "reports",
    )

    expected_dir = tmp_path / "reports" / customer.replace(" ", "_")
    expected_file = f"{month}_{ip}.pdf"
    expected_path = expected_dir / expected_file

    assert isinstance(result_path, Path)
    assert result_path == expected_path

    prepare_mock.assert_called_once_with(
        customer,
        month,
        ip,
        mgmt,
        trend,
        technical,
        mock_evaluation,
        mock_business_risk,
        {},
    )


# ─────────────────────────────────────────────────────────────────────────────
# page_meta-Weiterleitung an render_pdf
# ─────────────────────────────────────────────────────────────────────────────

def _run_generate(tmp_path, monkeypatch, *, customer="Acme", month="2026-03",
                  ip="1.2.3.4", technical_json=None, config=None):
    """Hilfsfunktion: führt generate_pdf mit gemocktem render_pdf aus."""
    render_mock = MagicMock()
    monkeypatch.setattr(pdf_generator, "prepare_pdf_elements", MagicMock(return_value=[]))
    monkeypatch.setattr(pdf_generator, "render_pdf", render_mock)
    generate_pdf(
        customer_name=customer,
        month=month,
        ip=ip,
        management_text="",
        trend_text="",
        technical_json=technical_json or {},
        evaluation=Evaluation(ip=ip, risk=RiskLevel.LOW, critical_points=[]),
        business_risk="low",
        output_dir=tmp_path / "reports",
        config=config or {},
    )
    return render_mock


class TestGeneratePdfPageMeta:

    def test_render_pdf_called_with_page_meta(self, tmp_path, monkeypatch):
        mock = _run_generate(tmp_path, monkeypatch)
        _, kwargs = mock.call_args
        assert "page_meta" in kwargs

    def test_page_meta_has_required_keys(self, tmp_path, monkeypatch):
        mock = _run_generate(tmp_path, monkeypatch)
        meta = mock.call_args[1]["page_meta"]
        for key in ("domain", "month_display", "sha256", "confidentiality"):
            assert key in meta, f"page_meta fehlt Schlüssel: {key}"

    def test_sha256_is_64_hex_chars(self, tmp_path, monkeypatch):
        mock = _run_generate(tmp_path, monkeypatch)
        sha = mock.call_args[1]["page_meta"]["sha256"]
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)

    def test_month_display_format(self, tmp_path, monkeypatch):
        mock = _run_generate(tmp_path, monkeypatch, month="2026-01")
        disp = mock.call_args[1]["page_meta"]["month_display"]
        assert disp == "Jan 2026"

    def test_month_display_format_april(self, tmp_path, monkeypatch):
        mock = _run_generate(tmp_path, monkeypatch, month="2026-04")
        disp = mock.call_args[1]["page_meta"]["month_display"]
        assert disp == "Apr 2026"

    def test_confidentiality_label(self, tmp_path, monkeypatch):
        mock = _run_generate(tmp_path, monkeypatch)
        label = mock.call_args[1]["page_meta"]["confidentiality"]
        assert label == "Vertraulich"

    def test_domain_from_hostnames_fallback(self, tmp_path, monkeypatch):
        mock = _run_generate(tmp_path, monkeypatch,
                             technical_json={"hostnames": ["test.example.de"]})
        domain = mock.call_args[1]["page_meta"]["domain"]
        assert domain == "test.example.de"


# ─────────────────────────────────────────────────────────────────────────────
# SHA256 Eindeutigkeit
# ─────────────────────────────────────────────────────────────────────────────

class TestPageMetaSha256:
    """
    SHA256 = SHA256(customer_name:ip:month) — deterministisch und eindeutig
    pro Kombination aus Kunde + IP + Monat.
    """

    def _sha(self, customer, ip, month):
        return hashlib.sha256(f"{customer}:{ip}:{month}".encode()).hexdigest()

    def test_deterministic_same_inputs(self):
        """Gleiche Eingaben → gleicher Hash (Reproduzierbarkeit)."""
        assert self._sha("Acme", "1.2.3.4", "2026-03") == self._sha("Acme", "1.2.3.4", "2026-03")

    def test_different_customer(self):
        """Unterschiedlicher Kundenname → unterschiedlicher Hash."""
        assert self._sha("Acme", "1.2.3.4", "2026-03") != self._sha("Omega", "1.2.3.4", "2026-03")

    def test_different_ip(self):
        """Unterschiedliche IP → unterschiedlicher Hash."""
        assert self._sha("Acme", "1.2.3.4", "2026-03") != self._sha("Acme", "9.9.9.9", "2026-03")

    def test_different_month(self):
        """Unterschiedlicher Monat → unterschiedlicher Hash."""
        assert self._sha("Acme", "1.2.3.4", "2026-03") != self._sha("Acme", "1.2.3.4", "2025-12")

    def test_is_hex_string(self):
        sha = self._sha("X", "0.0.0.0", "2026-01")
        assert len(sha) == 64
        int(sha, 16)  # muss als Hex parsebar sein

    def test_matches_generator_output(self, tmp_path, monkeypatch):
        """Hash im page_meta muss identisch mit dem erwarteten SHA256 sein."""
        customer, ip, month = "TestCo", "5.5.5.5", "2026-02"
        expected = hashlib.sha256(f"{customer}:{ip}:{month}".encode()).hexdigest()
        mock = _run_generate(tmp_path, monkeypatch, customer=customer, ip=ip, month=month)
        actual = mock.call_args[1]["page_meta"]["sha256"]
        assert actual == expected
