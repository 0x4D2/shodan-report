
# Shodan Report — Monatliche Sicherheitsberichte aus externer Sicht

Kurzfassung:  
Dieses Projekt erstellt monatliche Sicherheitsreports auf Basis von Shodan-Snapshots. Ziel ist ein leichtgewichtiger, automatisierter Report-Generator, der für Kund:innen die öffentliche Angriffsfläche dokumentiert, bewertet, revisionssicher archiviert und als PDF ausliefert.

---

## Schnellstart

### Installation
```bash
# Entwicklungsumgebung
git clone <repository>
cd shodan-report
python -m venv .venv

# Windows (PowerShell)
.venv\Scripts\activate

# Linux / macOS
# source .venv/bin/activate

pip install -e .
````

### Ersten Report generieren

```bash
shodan-report --customer "Mein Kunde" --ip "8.8.8.8" --month "2025-01"
```

---

## CLI Usage

### Basis-Kommando

```bash
shodan-report --customer <NAME> --ip <IP> --month <YYYY-MM>
```

### Alle Parameter

| Parameter      | Kurzform | Beschreibung               | Beispiel                      |
| -------------- | -------- | -------------------------- | ----------------------------- |
| `--customer`   | `-c`     | Kundenname                 | `"CHINANET HUBEI"`            |
| `--ip`         | `-i`     | IP-Adresse                 | `"111.170.152.60"`            |
| `--month`      | `-m`     | Monat (YYYY-MM)            | `"2025-01"`                   |
| `--compare`    |          | Vergleichsmonat            | `"2024-12"`                   |
| `--config`     |          | Kundenkonfiguration (YAML) | `config/customers/kunde.yaml` |
| `--output-dir` | `-o`     | Ausgabeverzeichnis         | `./reports`                   |
| `--no-archive` |          | Archivierung deaktivieren  |                               |
| `--verbose`    | `-v`     | Ausführliche Ausgabe       |                               |
| `--quiet`      | `-q`     | Minimale Ausgabe           |                               |

---

## Beispiele

### Einfacher Report

```bash
shodan-report -c "MG Solutions" -i "217.154.224.104" -m "2025-01"
```

### Mit Trendanalyse (Vergleich mit Vormonat)

```bash
shodan-report -c "CHINANET" -i "111.170.152.60" -m "2025-01" --compare "2024-12"
```

### Mit Kundenkonfiguration

```bash
shodan-report -c "Enterprise AG" -i "192.168.1.1" -m "2025-01" \
  --config config/customers/enterprise.yaml
```

### Ohne Archivierung (nur lokale PDF-Erzeugung)

```bash
shodan-report -c "Test" -i "8.8.8.8" -m "2025-01" \
  --no-archive --output-dir /tmp
```

---

## ⚙️ Kundenkonfiguration (YAML)

### Struktur

```
config/
├── customers/
│   ├── example.yaml           # ✅ Template (im Git)
│   ├── chinanet-hubei.yaml    # ❌ Echte Kunden (gitignored)
│   └── mg-solutions.yaml      # ❌ Echte Kunden (gitignored)
└── templates/
    └── basic.yaml             # ✅ Generische Templates
```

### YAML-Schema

```yaml
customer:
  name: "Kundenname GmbH"
  slug: "kundenname"            # optional, wird aus dem Namen generiert
  contact: "security@kunde.de"
  language: "de"                # de / en

report:
  include_trend_analysis: true
  include_cve_check: false      # in Entwicklung
  severity_threshold: "medium"  # low / medium / high / critical
  sections:
    - executive_summary
    - technical_findings
    - risk_assessment
    - recommendations
    - appendix

delivery:
  email_enabled: false          # geplant
  archive_enabled: true
  local_copy: true

styling:
  primary_color: "#1a365d"
  secondary_color: "#2d3748"
  logo_path: null               # später: Pfad zum Kundenlogo

disclaimer:
  enabled: true
  text: |
    Dieser Bericht basiert auf öffentlich verfügbaren Informationen (OSINT).
    Keine Gewähr auf Vollständigkeit oder Richtigkeit.
    Dient ausschließlich zu Informationszwecken. Vertraulich.
```

---

## Automatisierung

### Batch-Verarbeitung (Beispiel PowerShell)

```powershell
foreach ($line in Get-Content jobs.txt) {
    $parts = $line -split " "
    shodan-report -c $parts[0] -i $parts[1] -m $parts[2] --quiet
}
```

### Cron-Job (Linux)

```bash
# Jeden 1. des Monats um 02:00 Uhr
0 2 1 * * /opt/shodan-report/run-monthly.sh
```

### n8n-Workflow

* Trigger: Cron / Monatswechsel
* Execute Command: `shodan-report ...`
* Versand: E-Mail mit PDF oder Notification (Slack / Teams)

---

## Projektstruktur

```
archive/                          # Revisionssichere Ablage
reports/                          # Temporäre PDFs
config/                           # Kunden- und Template-Konfiguration
src/shodan_report/
├── cli.py
├── core/
├── archiver/
├── pdf/
├── evaluation/
├── reporting/
└── tests/
```

---

## Rechtlicher Hinweis

Jeder Report enthält automatisch folgenden Disclaimer:

```
Dieser Bericht basiert auf öffentlich verfügbaren OSINT-Daten (Shodan).
Er ersetzt keinen Penetrationstest.
Keine Garantie auf Vollständigkeit oder Richtigkeit.
Vertraulich. Stand: {Datum}
```

---

## Umgebungsvariablen

```env
SHODAN_API_KEY=dein_api_key
SMTP_SERVER=smtp.example.com
SMTP_PORT=587
SMTP_USER=user@example.com
SMTP_PASS=passwort
```

---

## Tests

```bash
pytest -v
pytest --cov=src/shodan_report
```

Aktueller Status: **70/70 Tests erfolgreich**.

---

## Roadmap (Auszug)

* ✅ Revisionssichere Archivierung
* ✅ PDF-Design mit Corporate Colors
* 🔄 CVE- und SSL-Enrichment
* 🔄 Automatisierter Versand
* 🔄 Erweiterte Kundenkonfiguration

---

## 📄 Lizenz

MIT-Lizenz – siehe `LICENSE`.

---

**Status:**
Produktionsreifes MVP mit CLI, Automatisierung, rechtssicherem Disclaimer und revisionssicherer Archivierung.
