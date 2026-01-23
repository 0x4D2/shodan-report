"""
Generiert viele Demo-PDF-Varianten unter `reports/demo/` zur manuellen Inspektion.

Aufruf:
    python scripts/generate_demo_pdfs.py

Das Script setzt `src` auf `sys.path` und verwendet `generate_pdf`.
"""

import sys
from pathlib import Path

# ensure package imports work
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from shodan_report.pdf.pdf_generator import generate_pdf

OUT_DIR = Path('reports') / 'demo'
OUT_DIR.mkdir(parents=True, exist_ok=True)


def _sparse():
    return {"open_ports": [], "vulnerabilities": [], "services": []}


def _dense(n_services=150, cves_each=5):
    services = []
    for i in range(n_services):
        services.append({
            "port": 1000 + i,
            "product": f"Service{i}",
            "version": "2.0.0",
            "banner": "B" * (800 if i % 10 == 0 else 60),
            "vulnerabilities": [{"id": f"CVE-2026-{i:04d}-{j}", "cvss": 7.0 + (j % 4)} for j in range(cves_each)],
            "ssl_info": {"has_weak_cipher": i % 17 == 0},
        })
    return {"open_ports": services, "services": services, "vulnerabilities": [{"id": f"CVE-TOP-{i}", "cvss": 9.0} for i in range(10)], "tls_weaknesses": ["weak-1", "weak-2"]}


def _multilingual():
    return {
        "open_ports": [
            {"port": 443, "product": "nginx", "version": "1.22.0", "banner": "Grüße 🌍 – Sonderzeichen: äöüß"},
            {"port": 22, "product": "OpenSSH", "version": "8.9", "banner": "שלום - שלום"},
        ],
        "vulnerabilities": [],
        "services": [],
    }


def _rtl():
    return {"open_ports": [{"port": 80, "product": "IIS", "banner": "مرحبا بالعالم - RTL نص"}], "vulnerabilities": [], "services": []}


def _longword():
    return {"open_ports": [{"port": 8080, "product": "weird", "banner": "A" * 10000}], "vulnerabilities": [], "services": []}


def _missing_fields():
    # services with missing optional fields to test robustness
    return {"open_ports": [{"port": 53}, {"product": "unknown"}, {"port": None}], "vulnerabilities": []}


def _html_banners():
    return {"open_ports": [{"port": 8000, "product": "webapp", "banner": "<h1>Title</h1><script>alert('x')</script>"}], "vulnerabilities": []}


def _many_small_services(n=500):
    services = [{"port": 2000 + i, "product": f"s{i}", "banner": "ok"} for i in range(n)]
    return {"open_ports": services, "services": services, "vulnerabilities": []}


variants = [
    ("DEMO_SPARSE", "2026-01", "1.2.3.4", "Kurz", "Keine Änderungen.", _sparse(), {}),
    ("DEMO_DENSE", "2026-01", "203.0.113.5", "Langer Managementtext\n" * 60, "Sehr viele Änderungen\n" * 40, _dense(), {"cves": []}),
    ("DEMO_MULTI", "2026-01", "198.51.100.7", "Mehrsprachig: Grüße", "Änderungen: 🌐🚀", _multilingual(), {}),
    ("DEMO_RTL", "2026-01", "198.51.100.8", "Management auf Arabisch", "تغييرات", _rtl(), {}),
    ("DEMO_LONGWORD", "2026-01", "192.0.2.9", "Banner Test", "Banner Trend", _longword(), {}),
    ("DEMO_MISSING", "2026-01", "192.0.2.10", "Fehlende Felder", "Test", _missing_fields(), {}),
    ("DEMO_HTML", "2026-01", "192.0.2.11", "HTML Banner", "Test", _html_banners(), {}),
    ("DEMO_MANY_SMALL", "2026-01", "198.51.100.99", "Viele kleine Dienste", "Test", _many_small_services(400), {}),
]

print(f"Generating {len(variants)} demo PDFs into {OUT_DIR}")
for cust, month, ip, mtext, ttext, tech, evalobj in variants:
    path = generate_pdf(
        customer_name=cust,
        month=month,
        ip=ip,
        management_text=mtext,
        trend_text=ttext,
        technical_json=tech,
        evaluation=evalobj,
        business_risk="medium",
        output_dir=OUT_DIR,
    )
    print("Wrote:", path)

print("Done.")
