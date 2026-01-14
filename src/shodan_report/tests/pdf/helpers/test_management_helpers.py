# src/shodan_report/tests/pdf/helpers/test_management_helpers.py
import pytest
from unittest.mock import Mock, patch
from shodan_report.pdf.helpers.management_helpers import (
    extract_first_sentence,
    generate_priority_insights,
    generate_priority_recommendations,
    _sanitize_critical_point,
)
from shodan_report.models import Service
from shodan_report.evaluation import Evaluation


class TestExtractFirstSentence:
    """Tests für extract_first_sentence Funktion."""

    def test_extract_complete_sentence(self):
        """Extrahiert ersten vollständigen Satz."""
        text = "Dies ist der erste Satz. Und hier kommt der zweite."
        result = extract_first_sentence(text)
        assert result == "Dies ist der erste Satz."

    def test_extract_with_exclamation(self):
        """Extrahiert Satz mit Ausrufezeichen."""
        text = "Achtung! Das ist wichtig. Bitte beachten."
        result = extract_first_sentence(text)
        assert result == "Achtung!"

    def test_extract_with_question_mark(self):
        """Extrahiert Satz mit Fragezeichen."""
        text = "Ist das sicher? Wir sollten prüfen."
        result = extract_first_sentence(text)
        assert result == "Ist das sicher?"

    def test_no_sentence_endings(self):
        """Text ohne Satzzeichen -> gibt ersten 100 Zeichen zurück."""
        text = "Dies ist ein sehr langer Text ohne Punkt oder Komma " * 5
        result = extract_first_sentence(text)
        assert len(result) <= 103  # 100 Zeichen + "..."
        assert "..." in result

    def test_empty_text(self):
        """Leerer Text sollte leeren String zurückgeben."""
        result = extract_first_sentence("")
        assert result == ""

    def test_short_text_without_ending(self):
        """Kurzer Text ohne Satzzeichen."""
        text = "Kurzer Text"
        result = extract_first_sentence(text)
        assert result == "Kurzer Text"


class TestGeneratePriorityInsights:
    """Tests für generate_priority_insights Funktion."""

    @pytest.fixture
    def mock_evaluation(self):
        """Mock Evaluation Objekt."""
        evaluation = Mock(spec=Evaluation)
        evaluation.critical_points = []
        return evaluation

    @pytest.fixture
    def sample_service(self):
        """Erstellt ein Sample Service Objekt."""
        return Service(port=80, transport="tcp", product="nginx", ssl_info=None)

    def test_empty_technical_json(self, mock_evaluation):
        """Test mit leeren technischen Daten."""
        technical_json = {}
        insights = generate_priority_insights(technical_json, mock_evaluation, "MEDIUM")

        # Erwartete Ausgabe:
        # ['Keine kritischen Schwachstellen', '0 kritische Risikopunkte']

        assert insights == [
            "Keine kritischen Schwachstellen",
            "0 kritische Risikopunkte",
        ]

    def test_with_open_ports(self, mock_evaluation, sample_service):
        """Test mit offenen Ports."""
        technical_json = {"open_ports": [sample_service, sample_service]}  # 2 Dienste

        insights = generate_priority_insights(technical_json, mock_evaluation, "MEDIUM")

        assert any("2 öffentliche Dienste" in insight for insight in insights)

    @patch("shodan_report.pdf.helpers.management_helpers.is_service_secure")
    def test_with_vulnerabilities(self, mock_is_secure, mock_evaluation):
        """Test mit Schwachstellen."""
        mock_is_secure.return_value = True

        technical_json = {
            "open_ports": [Mock(spec=Service)],
            "vulnerabilities": [
                {"cvss": 9.5, "id": "CVE-2021-12345"},
                {"cvss": 7.0, "id": "CVE-2021-67890"},
                {"cvss": 9.8, "id": "CVE-2021-11111"},
            ],
        }

        insights = generate_priority_insights(technical_json, mock_evaluation, "MEDIUM")

        # Sollte 2 kritische CVEs finden (>= 9.0)
        assert any("2 kritische Schwachstellen" in insight for insight in insights)

    @patch("shodan_report.pdf.helpers.management_helpers.is_service_secure")
    def test_with_insecure_services(self, mock_is_secure, mock_evaluation):
        """Test mit unsicheren Diensten."""
        # Simuliere einige sichere, einige unsichere Dienste
        mock_is_secure.side_effect = [False, True, False]  # 2 unsicher, 1 sicher

        services = [Mock(spec=Service) for _ in range(3)]
        technical_json = {"open_ports": services}

        insights = generate_priority_insights(technical_json, mock_evaluation, "MEDIUM")

        # Sollte "2 kritische Risikopunkte" enthalten (2 unsichere Dienste + 0 critical points)
        assert any("2 kritische Risikopunkte" in insight for insight in insights)

    def test_with_critical_points(self, mock_evaluation):
        """Test mit kritischen Punkten in Evaluation."""
        mock_evaluation.critical_points = ["SSH exposed", "Weak TLS"]

        technical_json = {"open_ports": []}

        insights = generate_priority_insights(technical_json, mock_evaluation, "MEDIUM")

        assert any("2 kritische Risikopunkte" in insight for insight in insights)

    def test_business_risk_high(self, mock_evaluation):
        """Test mit HIGH Business Risk."""
        technical_json = {"open_ports": []}

        insights = generate_priority_insights(technical_json, mock_evaluation, "HIGH")

        assert any("Erhöhter Handlungsbedarf" in insight for insight in insights)

    def test_max_4_insights(self, mock_evaluation):
        """Testet, dass maximal 4 Insights zurückgegeben werden."""
        technical_json = {
            "open_ports": [Mock(spec=Service) for _ in range(10)],
            "vulnerabilities": [{"cvss": 9.5} for _ in range(5)],
        }
        mock_evaluation.critical_points = ["Point1", "Point2", "Point3"]

        insights = generate_priority_insights(technical_json, mock_evaluation, "HIGH")

        assert len(insights) <= 4

    def test_insight_ordering(self, mock_evaluation):
        """Testet die Reihenfolge der Insights."""
        technical_json = {
            "open_ports": [Mock(spec=Service)],
            "vulnerabilities": [{"cvss": 9.5}],
        }

        insights = generate_priority_insights(technical_json, mock_evaluation, "HIGH")

        # Erste Insight sollte über Dienste sein
        assert "öffentliche Dienste" in insights[0]
        # Zweite über Schwachstellen
        assert "kritische Schwachstellen" in insights[1]


def test_sanitize_preserves_full_port_number():
    text = "MySQL 8.0.33 öffentlich erreichbar auf Port 3306"
    out = _sanitize_critical_point(text)
    assert "Port 3306" in out


class TestGeneratePriorityRecommendations:
    """Tests für generate_priority_recommendations Funktion."""

    @pytest.fixture
    def sample_service(self):
        """Erstellt ein Sample Service Objekt."""
        return Service(port=80, transport="tcp", product="nginx")

    def test_base_recommendations_critical(self):
        """Testet Basis-Empfehlungen für CRITICAL Risk."""
        technical_json = {"open_ports": []}

        recommendations = generate_priority_recommendations("CRITICAL", technical_json)

        assert len(recommendations) <= 3
        assert "Sofortige Notfallmaßnahmen" in recommendations[0]
        assert "Kritische Dienste temporär isolieren" in recommendations[1]

    def test_base_recommendations_high(self):
        """Testet Basis-Empfehlungen für HIGH Risk."""
        technical_json = {"open_ports": []}

        recommendations = generate_priority_recommendations("HIGH", technical_json)

        assert "7 Tagen" in recommendations[0]
        assert "Härtung" in recommendations[0]

    def test_base_recommendations_medium(self):
        """Testet Basis-Empfehlungen für MEDIUM Risk."""
        technical_json = {"open_ports": []}

        recommendations = generate_priority_recommendations("MEDIUM", technical_json)

        assert "Kurzfristig" in recommendations[0]

    def test_base_recommendations_low(self):
        """Testet Basis-Empfehlungen für LOW Risk."""
        technical_json = {"open_ports": []}

        recommendations = generate_priority_recommendations("LOW", technical_json)

        assert "Keine sofortigen Notfallmaßnahmen" in recommendations[0]

    def test_unknown_risk_level(self):
        """Testet unbekanntes Risk Level."""
        technical_json = {"open_ports": []}

        recommendations = generate_priority_recommendations("UNKNOWN", technical_json)

        # Sollte default Empfehlungen geben
        assert len(recommendations) > 0
        assert any("Überprüfung" in rec or "Scans" in rec for rec in recommendations)

    def test_ssh_service_recommendation(self):
        """Testet spezifische SSH Empfehlung."""
        ssh_service = Service(port=22, transport="tcp", product="OpenSSH")
        technical_json = {"open_ports": [ssh_service]}

        recommendations = generate_priority_recommendations("MEDIUM", technical_json)

        assert any(
            "SSH" in rec and "Schlüsselbasierte" in rec for rec in recommendations
        )

    def test_rdp_service_recommendation(self):
        """Testet spezifische RDP Empfehlung."""
        rdp_service = Service(port=3389, transport="tcp", product="Windows RDP")
        technical_json = {"open_ports": [rdp_service]}

        recommendations = generate_priority_recommendations("MEDIUM", technical_json)

        assert any(
            "RDP" in rec and "Netzwerk-Level-Authentifizierung" in rec
            for rec in recommendations
        )

    def test_max_3_recommendations(self):
        """Testet, dass maximal 3 Empfehlungen zurückgegeben werden."""
        # Erstelle viele Services um viele Empfehlungen zu trigger
        services = [
            Service(port=22, transport="tcp", product="OpenSSH"),
            Service(port=3389, transport="tcp", product="Windows RDP"),
            Service(port=443, transport="tcp", product="nginx"),
            Service(port=80, transport="tcp", product="apache"),
        ]
        technical_json = {"open_ports": services}

        recommendations = generate_priority_recommendations("HIGH", technical_json)

        assert len(recommendations) <= 3

    def test_mixed_services(self):
        """Testet gemischte Services."""
        services = [
            Service(port=22, transport="tcp", product="ssh server"),
            Service(port=443, transport="tcp", product="https server"),
            Service(port=8080, transport="tcp", product="custom app"),
        ]
        technical_json = {"open_ports": services}

        recommendations = generate_priority_recommendations("MEDIUM", technical_json)

        # Mindestens Basis-Empfehlungen + SSH Empfehlung
        assert len(recommendations) >= 2
        assert any("SSH" in rec for rec in recommendations)

    def test_case_insensitive_risk_level(self):
        """Testet case-insensitive Risk Level."""
        technical_json = {"open_ports": []}

        # Teste verschiedene Schreibweisen
        for risk in ["high", "HIGH", "High", "hIgH"]:
            recommendations = generate_priority_recommendations(risk, technical_json)
            assert len(recommendations) > 0
            assert "7 Tagen" in recommendations[0] or "Kurzfristig" in recommendations[0]


# Integration Tests
class TestManagementHelpersIntegration:
    """Integrationstests für Management-Helpers."""

    def test_complete_workflow(self):
        """Testet den kompletten Workflow mit echten Daten."""
        # Echte Services erstellen
        services = [
            Service(port=22, transport="tcp", product="OpenSSH", ssl_info=None),
            Service(
                port=443,
                transport="tcp",
                product="nginx",
                ssl_info={"protocol": "TLSv1.3"},
            ),
        ]

        technical_json = {
            "open_ports": services,
            "vulnerabilities": [{"cvss": 9.5, "id": "CVE-2021-12345"}],
        }

        evaluation = Evaluation(
            ip="192.168.1.1", risk="MEDIUM", critical_points=["SSH exposed without VPN"]
        )

        # Insights generieren
        insights = generate_priority_insights(technical_json, evaluation, "HIGH")

        # Recommendations generieren
        recommendations = generate_priority_recommendations("HIGH", technical_json)

        # Validierung
        assert len(insights) > 0
        assert len(recommendations) > 0

        # Spezifische Checks
        assert any("2 öffentliche Dienste" in insight for insight in insights)
        assert any("kritische Schwachstellen" in insight for insight in insights)
        assert any("SSH" in rec for rec in recommendations)
