# src/shodan_report/tests/models/test_service.py
import pytest
from shodan_report.models import Service


class TestService:

    def test_basic_service_creation(self):
        """Testet die grundlegende Erstellung eines Service-Objekts."""
        service = Service(
            port=80,
            transport="tcp",
            product="nginx",
            version="1.18.0",
            raw={"port": 80, "product": "nginx"},
        )

        assert service.port == 80
        assert service.transport == "tcp"
        assert service.product == "nginx"
        assert service.version == "1.18.0"
        assert service.raw == {"port": 80, "product": "nginx"}

    def test_service_with_optional_fields_none(self):
        """Testet Service-Erstellung mit optionalen None-Feldern."""
        service = Service(
            port=443,
            transport="tcp",
            # Keine optionalen Felder
        )

        assert service.port == 443
        assert service.transport == "tcp"
        assert service.product is None
        assert service.version is None
        assert service.ssl_info is None
        assert service.ssh_info is None
        assert service.raw is None

    def test_security_flags_default_false(self):
        """Testet, dass Sicherheits-Flags standardmäßig False sind."""
        service = Service(port=22, transport="tcp")

        assert service.is_encrypted is False
        assert service.requires_auth is False
        assert service.vpn_protected is False
        assert service.tunneled is False
        assert service.cert_required is False

    def test_service_with_ssl_info(self):
        """Testet Service mit SSL-Informationen."""
        ssl_info = {
            "protocol": "TLSv1.3",
            "cipher": "AES256-GCM-SHA384",
            "cert": {"issuer": "Let's Encrypt"},
        }

        service = Service(
            port=443,
            transport="tcp",
            product="Apache",
            ssl_info=ssl_info,
            is_encrypted=True,
        )

        assert service.ssl_info == ssl_info
        assert service.is_encrypted is True

    def test_service_with_ssh_info(self):
        """Testet Service mit SSH-Informationen."""
        ssh_info = {"version": "OpenSSH_8.2p1", "key_type": "ssh-rsa", "key_bits": 2048}

        service = Service(
            port=22,
            transport="tcp",
            product="OpenSSH",
            ssh_info=ssh_info,
            requires_auth=True,
        )

        assert service.ssh_info == ssh_info
        assert service.requires_auth is True

    def test_service_with_security_flags_enabled(self):
        """Testet Service mit aktivierten Sicherheits-Flags."""
        service = Service(
            port=3389,
            transport="tcp",
            product="Windows RDP",
            vpn_protected=True,
            tunneled=True,
            cert_required=True,
        )

        assert service.vpn_protected is True
        assert service.tunneled is True
        assert service.cert_required is True

    def test_service_immutability_of_raw_data(self):
        """Testet, dass raw-Daten als Referenz gespeichert werden (Python-Standard)."""
        raw_data = {
            "port": 8080,
            "product": "Tomcat",
            "version": "9.0.50",
            "extra": {"java": "11.0.12"},
        }

        service = Service(port=8080, transport="tcp", raw=raw_data)

        # Ändere das originale dict
        raw_data["modified"] = True

        # In Python wird das dict per Referenz gespeichert
        # Das ist das erwartete Verhalten für mutable objects
        assert "modified" in service.raw
        assert service.raw["modified"] is True

    def test_service_equality(self):
        """Testet Gleichheit von Service-Objekten."""
        service1 = Service(port=80, transport="tcp", product="nginx")
        service2 = Service(port=80, transport="tcp", product="nginx")
        service3 = Service(port=443, transport="tcp", product="nginx")

        # Dataclasses implementieren __eq__ basierend auf Attributen
        assert service1 == service2
        assert service1 != service3

    def test_service_string_representation(self):
        """Testet die String-Repräsentation."""
        service = Service(port=3306, transport="tcp", product="MySQL", version="8.0.26")

        str_repr = str(service)
        assert "3306" in str_repr
        assert "tcp" in str_repr
        assert "MySQL" in str_repr
        assert "8.0.26" in str_repr

    def test_service_accepts_all_values_no_validation(self):
        """Testet, dass Service ALLE Werte akzeptiert (keine eingebaute Validierung)."""
        # Da Service-Klasse keine Validierung hat, sollten ALLE Werte funktionieren
        test_cases = [
            (80, "tcp"),
            (443, "tcp"),
            (22, "tcp"),
            (53, "udp"),
            (-1, "tcp"),  # Ungültiger Port, wird aber akzeptiert
            (65536, "tcp"),  # Port zu hoch, wird aber akzeptiert
            (80, "icmp"),  # Ungültiges Protokoll, wird aber akzeptiert
            (None, "tcp"),  # Port None, wird aber akzeptiert
            (80, None),  # Transport None, wird aber akzeptiert
        ]

        for port, transport in test_cases:
            service = Service(port=port, transport=transport)
            assert service.port == port
            assert service.transport == transport

    def test_service_with_complete_data(self):
        """Testet Service mit allen möglichen Feldern."""
        service = Service(
            port=8443,
            transport="tcp",
            product="Apache Tomcat",
            version="9.0.50",
            ssl_info={"protocol": "TLSv1.2"},
            ssh_info=None,
            is_encrypted=True,
            requires_auth=True,
            vpn_protected=False,
            tunneled=True,
            cert_required=False,
            raw={
                "port": 8443,
                "transport": "tcp",
                "service": "https",
                "product": "Apache Tomcat",
                "version": "9.0.50",
                "ssl": {"protocol": "TLSv1.2"},
            },
        )

        # Teste alle Attribute
        assert service.port == 8443
        assert service.transport == "tcp"
        assert service.product == "Apache Tomcat"
        assert service.version == "9.0.50"
        assert service.ssl_info == {"protocol": "TLSv1.2"}
        assert service.ssh_info is None
        assert service.is_encrypted is True
        assert service.requires_auth is True
        assert service.vpn_protected is False
        assert service.tunneled is True
        assert service.cert_required is False
        assert "service" in service.raw
