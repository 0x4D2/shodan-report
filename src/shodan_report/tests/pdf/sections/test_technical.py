import pytest
from reportlab.platypus import Paragraph
from shodan_report.pdf.sections.technical import (
    create_technical_section,
    _build_port_text,
    _extract_metadata_items
)
from shodan_report.pdf.styles import _create_styles


class TestTechnicalSection:
    
    def test_build_port_text_basic(self):
        text = _build_port_text(
            port=80,
            transport="TCP",
            product="HTTP",
            version="",
            banner="",
            extra_info=""
        )
        
        assert "Port 80/TCP" in text
        assert "HTTP" in text
    
    def test_build_port_text_with_version(self):
        text = _build_port_text(
            port=22,
            transport="TCP", 
            product="OpenSSH",
            version="8.9p1",
            banner="",
            extra_info=""
        )
        
        assert "Port 22/TCP" in text
        assert "OpenSSH" in text
        assert "(8.9p1)" in text
    
    def test_build_port_text_with_extra_info(self):
        text = _build_port_text(
            port=53,
            transport="TCP",
            product="DNS Service",
            version="",
            banner="",
            extra_info="DNS Recursion aktiv"
        )
        
        assert "Port 53/TCP" in text
        assert "DNS Service" in text
        assert "DNS Recursion aktiv" in text
    
    def test_extract_metadata_items_complete(self):
        technical_json = {
            "hostnames": ["server1.example.com", "server2.example.com"],
            "org": "Example Corp",
            "country": "Germany",
            "city": "Berlin",
            "asn": "AS12345",
            "vulnerabilities": [{"cve": "CVE-2021-1234"}],
            "critical_services": [
                {"port": 22, "reason": "SSH öffentlich", "severity": "high"}
            ]
        }
        
        items = _extract_metadata_items(technical_json)
        
        assert len(items) >= 5
        assert any("Hostname(s):" in item for item in items)
        assert any("Example Corp" in item for item in items)
        assert any("Berlin, Germany" in item for item in items)
        assert any("AS12345" in item for item in items)
        assert any("Kritische Konfigurationen: 1" in item for item in items)
    
    def test_create_technical_section_empty(self):
        elements = []
        styles = _create_styles("#1a365d", "#2d3748")
        
        create_technical_section(
            elements=elements,
            styles=styles,
            technical_json={"open_ports": []},
            config={}
        )
        
        # Sollte mindestens Überschrift enthalten
        assert len(elements) > 0
        assert any("Technischer Anhang" in str(elem) for elem in elements)
    
    def test_create_technical_section_with_ports(self):
        elements = []
        styles = _create_styles("#1a365d", "#2d3748")
        
        technical_json = {
            "open_ports": [
                {
                    "port": 22,
                    "transport": "tcp",
                    "service": {
                        "product": "OpenSSH",
                        "version": "8.9p1",
                        "banner": "SSH-2.0-OpenSSH"
                    },
                    "extra_info": "SSH Service"
                },
                {
                    "port": 80,
                    "transport": "tcp",
                    "service": {
                        "product": "nginx",
                        "version": "1.18.0",
                        "banner": "Welcome to nginx"
                    },
                    "extra_info": ""
                }
            ],
            "hostnames": ["test.example.com"],
            "org": "Test Corp",
            "country": "DE",
            "city": "Teststadt"
        }
        
        create_technical_section(
            elements=elements,
            styles=styles,
            technical_json=technical_json,
            config={}
        )
        
        assert len(elements) > 0
        
        # Überprüfe ob Ports angezeigt werden
        port_texts = [str(elem) for elem in elements]
        port_text = ' '.join(port_texts)
        
        assert "Port 22/TCP" in port_text
        assert "OpenSSH" in port_text
        assert "Port 80/TCP" in port_text
        assert "nginx" in port_text
        assert "Test Corp" in port_text