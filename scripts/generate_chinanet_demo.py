import sys
from pathlib import Path

# ensure package import works when running script from repo root
root = Path(__file__).resolve().parents[1]
src_dir = root / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from shodan_report.pdf.pdf_generator import generate_pdf

customer='CHINANET'
month='2026-01'
ip='111.170.152.60'
management_text='''Gesamtbewertung der externen Angriffsfläche\nExposure-Level: 5 von 5 (sehr hoch)\nAuf Basis passiver OSINT-Daten wurden 7 öffentlich erreichbare Dienste identifiziert.\nIdentifizierte Sicherheitslücken: 107. Weitere Details im Anhang.\nKritische Sicherheitsprobleme identifiziert. Sofortige Priorisierung empfohlen.\n'''
trend_text='Keine historischen Daten für Trendanalyse vorhanden.'
technical_json={
    "open_ports":[
        {"port":22, "service":{"product":"OpenSSH"}},
        {"port":3306, "service":{"product":"MySQL", "version":"8.0.33"}},
        {"port":80, "service":{"product":"HTTP"}},
        {"port":8080, "service":{"product":"HTTP"}},
        {"port":8123, "service":{"product":"ClickHouse"}},
        {"port":8443, "service":{"product":"HTTPS"}},
        {"port":9000, "service":{"product":"ClickHouse"}},
    ],
    "hostnames":["example.chinanet"],
    "org":"CHINANET HUBEI PROVINCE NETWORK",
    "asn":"AS151185",
    "vulnerabilities": [{"id":"CVE-2025-50079","cvss":6.0}],
}

eval_obj={"exposure_score":5,"risk":"high","cves":[{"id":"CVE-2025-50079","cvss":6.0}],"critical_points":["MySQL 8.0.33 öffentlich erreichbar"]}

out = generate_pdf(customer_name=customer, month=month, ip=ip, management_text=management_text, trend_text=trend_text, technical_json=technical_json, evaluation=eval_obj, business_risk='high', output_dir=Path('reports/demo/CHINANET'))
print('Wrote PDF:', out)
