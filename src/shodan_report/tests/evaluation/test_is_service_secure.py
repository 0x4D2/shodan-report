# src/shodan_report/tests/evaluation/test_is_service_secure.py
import pytest
from shodan_report.models import Service
from shodan_report.pdf.helpers.evaluation_helpers import is_service_secure


class TestIsServiceSecure:

    @pytest.fixture
    def default_secure_indicators(self):
        """Default secure indicators für die Tests."""
        return ["ssh", "rdp", "https", "tls", "vpn"]

    def test_service_with_secure_flags(self, default_secure_indicators):
        service = Service(
            port=443,
            transport="tcp",
            product="nginx",
            ssl_info={"protocol": "TLSv1.3"},
            vpn_protected=True,
            tunneled=True,
            cert_required=True,
            raw={},
        )
        # Service mit SSL sollte IMMER sicher sein, egal was in secure_indicators steht
        assert is_service_secure(service, default_secure_indicators) is True

    def test_service_without_ssl(self, default_secure_indicators):
        service = Service(
            port=80,
            transport="tcp",
            product="nginx",
            ssl_info=None,
            vpn_protected=False,
            tunneled=False,
            cert_required=False,
            raw={},
        )
        # HTTP ohne SSL ist unsicher
        assert is_service_secure(service, default_secure_indicators) is False

    def test_service_partial_security(self, default_secure_indicators):
        service = Service(
            port=443,
            transport="tcp",
            product="nginx",
            ssl_info={"protocol": "TLSv1.2"},
            vpn_protected=False,
            tunneled=False,
            cert_required=False,
            raw={},
        )
        # Service MIT SSL sollte sicher sein (Zeile 1 in is_service_secure prüft ssl_info)
        # Also: SSL vorhanden → sollte True zurückgeben
        assert is_service_secure(service, default_secure_indicators) is True

    def test_ssh_without_vpn(self, default_secure_indicators):
        """SSH ohne VPN sollte unsicher sein."""
        service = Service(
            port=22,
            transport="tcp",
            product="OpenSSH",
            ssl_info=None,
            vpn_protected=False,
            tunneled=False,
            cert_required=False,
            raw={},
        )
        # SSH ist in secure_indicators enthalten, aber wird in der Admin-Dienste-Logik separat behandelt
        # Admin-Dienste brauchen VPN/Tunnel/Cert
        assert is_service_secure(service, default_secure_indicators) is False

    def test_ssh_with_vpn(self, default_secure_indicators):
        """SSH mit VPN sollte sicher sein."""
        service = Service(
            port=22,
            transport="tcp",
            product="OpenSSH",
            ssl_info=None,
            vpn_protected=True,
            tunneled=False,
            cert_required=False,
            raw={},
        )
        assert is_service_secure(service, default_secure_indicators) is True

    def test_rdp_without_security(self, default_secure_indicators):
        """RDP ohne Sicherheitsmaßnahmen sollte unsicher sein."""
        service = Service(
            port=3389,
            transport="tcp",
            product="Windows RDP",
            ssl_info=None,
            vpn_protected=False,
            tunneled=False,
            cert_required=False,
            raw={},
        )
        assert is_service_secure(service, default_secure_indicators) is False

    def test_service_with_secure_product_indicator(self, default_secure_indicators):
        """Service mit secure_indicators im Produktnamen sollte sicher sein."""
        service = Service(
            port=8443,
            transport="tcp",
            product="Apache with TLS",
            ssl_info=None,
            vpn_protected=False,
            tunneled=False,
            cert_required=False,
            raw={},
        )
        # "tls" ist in default_secure_indicators enthalten
        assert is_service_secure(service, default_secure_indicators) is True

    def test_version_risk_makes_service_insecure(self, default_secure_indicators):
        """Service mit version_risk > 0 sollte unsicher sein (auch ohne SSL)."""
        service = Service(
            port=80,  # Kein SSL Port
            transport="tcp",
            product="nginx",
            ssl_info=None,  # KEIN SSL!
            vpn_protected=False,
            tunneled=False,
            cert_required=False,
            raw={},
        )
        service._version_risk = 1

        assert is_service_secure(service, default_secure_indicators) is False

    def test_encrypted_service(self, default_secure_indicators):
        """Service mit is_encrypted=True sollte sicher sein."""
        service = Service(
            port=993,
            transport="tcp",
            product="IMAPS",
            ssl_info=None,
            vpn_protected=False,
            tunneled=False,
            cert_required=False,
            raw={},
        )
        service.is_encrypted = True  # Setze das Attribut

        assert is_service_secure(service, default_secure_indicators) is True
