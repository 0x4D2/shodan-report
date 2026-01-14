# test_full_integration.py
from shodan_report.core.runner import generate_report
import json

print("=== FINALER SYSTEMTEST ===")

# Option A: Mit Test-Daten
test_data = {
    "ip_str": "93.184.216.34",  # Beispiel-IP
    "data": [
        {
            "port": 3306,
            "transport": "tcp",
            "product": "MySQL",
            "version": "5.7.33",
            "vulns": [
                {"id": "CVE-2023-12345", "cvss": 9.8},
                {"id": "CVE-2023-56789", "cvss": 8.5},
            ],
        },
        {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "7.6p1"},
    ],
    "open_ports": [3306, 22],
}

print("1. Test mit MySQL 5.7.33 (kritische CVEs + EOL):")
# ... Code zum Testen

print("\n2. Test mit OpenSSH 7.6p1 (veraltet):")
# ... Code zum Testen
