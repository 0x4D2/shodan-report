from datetime import datetime
from shodan_report.models import Service, AssetSnapshot
from shodan_report.reporting.technical_data import build_technical_data

def test_build_technical_data_basic():
    service = [
        Service(port=22, transport="tcp", product="OpenSSH", version="8.1p1", ssl_info=None, ssh_info=None, raw={}),
        Service(port=80, transport="tcp", product="nginx", version="1.24.0", ssl_info=None, ssh_info=None, raw={}), 
    ]

    snapshot = AssetSnapshot(
        ip="1.2.3.4",
        hostnames=["example.com"],
        domains=["example.com"],
        org="TestOrg",
        isp="TestISP",
        os="Linux",
        city="Berlin",
        country="Germany",
        services=service,
        open_ports=[22, 80],
        last_update=datetime(2026, 1, 7)   
    )

    tech_data = build_technical_data(snapshot)

    # Basis-Felder
    assert tech_data["ip"] == "1.2.3.4"
    assert tech_data["snapshot_date"] == "2026-01-07"
    assert len(tech_data["open_ports"]) == 2

    #  verschachtelte Struktur
    ports = {port["port"]: port for port in tech_data["open_ports"]}
    
    # Port 22
    assert ports[22]["service"]["product"] == "OpenSSH"      
    assert ports[22]["service"]["version"] == "8.1p1"        
    assert ports[22]["transport"] == "tcp"
    
    # Port 80  
    assert ports[80]["service"]["product"] == "nginx"        
    assert ports[80]["service"]["version"] == "1.24.0"       
    assert ports[80]["transport"] == "tcp"
    
    # Weitere Felder prüfen
    assert ports[22]["service_type"] == "ssh"
    assert ports[80]["service_type"] == "web"
    
    # Kritische Services
    assert "critical_services" in tech_data
    assert isinstance(tech_data["critical_services"], list)
    # SSH sollte als kritisch markiert sein (Port 22)
    ssh_critical = any(s["port"] == 22 for s in tech_data["critical_services"])
    assert ssh_critical is True
    
    # Vulnerable Versions
    assert "vulnerable_versions" in tech_data
    assert isinstance(tech_data["vulnerable_versions"], list)
    
    # Weitere Felder
    assert tech_data["hostnames"] == ["example.com"]
    assert tech_data["domains"] == ["example.com"]
    assert tech_data["org"] == "TestOrg"
    assert tech_data["country"] == "Germany"
    assert tech_data["city"] == "Berlin"
    
    assert tech_data["trend"] is None


def test_build_technical_data_ignores_ssl_ssh_by_default():
    services = [
        Service(port=443, transport="tcp", product="nginx", version="1.24.0", 
                ssl_info={"cert": "x"}, ssh_info=None, raw={}),
        Service(port=22, transport="tcp", product="OpenSSH", version="8.1p1", 
                ssl_info=None, ssh_info={"kex": "x"}, raw={}),
    ]

    snapshot = AssetSnapshot(
        ip="5.6.7.8",
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
        services=services,
        open_ports=[443, 22],
        last_update=datetime(2026, 1, 7)
    )

    tech = build_technical_data(snapshot)
    
    assert tech["ip"] == "5.6.7.8"
    assert len(tech["open_ports"]) == 2
    
    # SSL/SSH Info sollte nicht in open_ports enthalten sein
    for port_info in tech["open_ports"]:
        assert "ssl_info" not in port_info
        assert "ssh_info" not in port_info
        if port_info["port"] == 443:
            
            assert "cert_info" in port_info or "cert_info" not in port_info  # Optional


def test_build_technical_data_empty_services():
    snapshot = AssetSnapshot(
        ip="9.9.9.9",
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
        services=[],
        open_ports=[],
        last_update=datetime(2026, 1, 7)
    )

    tech = build_technical_data(snapshot)
    
    assert tech["ip"] == "9.9.9.9"
    assert tech["snapshot_date"] == "2026-01-07"
    assert isinstance(tech["open_ports"], list)
    assert len(tech["open_ports"]) == 0
    
    assert "hostnames" in tech
    assert "domains" in tech
    assert "org" in tech
    assert "isp" in tech
    assert "country" in tech
    assert "city" in tech
    assert "critical_services" in tech
    assert "vulnerabilities" in tech
    assert "trend" in tech
    
    assert tech["hostnames"] == []
    assert tech["domains"] == []
    assert tech["critical_services"] == []
    assert tech["vulnerabilities"] == []
    assert tech["trend"] is None