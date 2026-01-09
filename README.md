# Shodan Report — Automatisierte externe Sicherheitsanalyse (OSINT)

**Status: MVP FUNKTIONIERT - Interne Testversion mit professionellem Layout**

Kurzfassung:  
Automatisierter Security Report Generator für externe Angriffsflächenanalyse. Erstellt professionelle monatliche Berichte basierend auf Shodan-Snapshots mit vollständiger Pipeline von der Datenerfassung bis zur revisionssicheren Archivierung.

---

## WICHTIGER HINWEIS

**AKTUELLER STATUS:** Interne Testversion - Noch nicht kundenreif  
• PDF zeigt **hartcodierte Beispielinhalte** (Layout steht 100%)  
• Echte Datenanalyse funktioniert, muss nur noch im PDF sichtbar gemacht werden  
• 82/82 Tests bestanden - Alle Kernfunktionen laufen  

---

## SCHNELLSTART

### Installation
```bash
git clone <repository>
cd shodan-report
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -e .
```

### Ersten Report generieren
```bash
shodan-report --customer "Testkunde" --ip "8.8.8.8" --month "2025-01" --verbose
```

### Mit Trendanalyse
```bash
shodan-report --customer "Testkunde" --ip "8.8.8.8" --month "2025-01" --compare "2024-12"
```

---

## PROFESSIONELLER REPORT-AUFBAU (7 Abschnitte)

Jeder Report enthält automatisch:

1. **Header** - Professionelle Metadaten & Asset-Information
2. **Management-Zusammenfassung** - Executive Summary mit Exposure-Level
3. **Trend- & Vergleichsanalyse** - Historische Entwicklung (mit Tabelle bei `--compare`)
4. **Priorisierte Handlungsempfehlungen** - Konkrete Maßnahmen (Prio 1 + Prio 2)
5. **Technische Detailanalyse** - Ports, Dienste, Versionen, Risikobewertung
6. **CVE- & Exploit-Übersicht** - Schwachstellen mit CVSS Scores
7. **Methodik & Grenzen** - Transparente Dokumentation der Analyse
8. **Fazit** - Zusammenfassung & Ausblick
9. **Footer** - Professioneller Disclaimer

---

## 🛠️ CLI PARAMETER

| Parameter | Beschreibung | Beispiel |
|-----------|-------------|----------|
| `--customer`, `-c` | Kundenname | `"CHINANET HUBEI"` |
| `--ip`, `-i` | IP-Adresse | `"111.170.152.60"` |
| `--month`, `-m` | Monat (YYYY-MM) | `"2025-01"` |
| `--compare` | Vergleichsmonat für Trendanalyse | `"2024-12"` |
| `--config` | Kundenkonfiguration (YAML) | `config/customers/beispiel.yaml` |
| `--output-dir`, `-o` | Ausgabeverzeichnis für PDFs | `./reports` |
| `--no-archive` | Deaktiviert revisionssichere Archivierung | |
| `--verbose`, `-v` | Detaillierte Ausgabe | |
| `--quiet`, `-q` | Minimale Ausgabe | |

---

## KUNDENKONFIGURATION (YAML)

### Beispiel `config/customers/example.yaml`
```yaml
customer:
  name: "Beispiel GmbH"
  language: "de"

styling:
  primary_color: "#1a365d"    # Dunkelblau
  secondary_color: "#2d3748"  # Graublau

report:
  include_trend_analysis: true

disclaimer:
  enabled: true
  text: |
    Dieser Bericht basiert auf öffentlich verfügbaren OSINT-Daten.
    Dient ausschließlich zu Informationszwecken. Vertraulich.
```

---

## AUTOMATISIERUNG

### Batch-Verarbeitung mit `jobs.txt`
```
Kunde1 192.168.1.1 2025-01
Kunde2 10.0.0.1 2025-01 --compare 2024-12
Kunde3 172.16.0.1 2025-01 --config config/customers/kunde3.yaml
```

```bash
python scripts/run-jobs-direct.py
```

### PowerShell Script
```powershell
python -m shodan_report --customer "Enterprise AG" --ip "203.0.113.10" --month "2025-01" --quiet
```

---

## PROJEKTSTRUKTUR

```
shodan-report/
├── src/shodan_report/
│   ├── cli.py                    # CLI Entry Point
│   ├── core/runner.py           # Haupt-Pipeline
│   ├── pdf/                     # Professionelle PDF-Generierung
│   │   ├── pdf_manager.py       # Layout-Koordination (6703 Zeilen → WIRD REFACTORED)
│   │   ├── TODO_PDF_MANAGER_REFACTOR.py  # Vollständiger Code (33018 Zeilen)
│   │   └── sections/            # Modularisierung vorbereitet
│   ├── archiver/                # Revisionssichere Archivierung
│   │   ├── report_archiver.py   # SHA256, Versionierung
│   │   └── version_manager.py   # Versionsverwaltung
│   ├── evaluation/              # Risikobewertung
│   ├── reporting/               # Textgenerierung
│   └── tests/                   # 82/82 Tests bestanden ✓
├── config/customers/            # Kundenkonfigurationen
├── archive/                     # Revisionssichere Ablage
│   └── {kunde}/{YYYY-MM}/{IP}_v{N}.pdf
├── reports/                     # Temporäre PDFs
└── scripts/run-jobs-direct.py  # Batch-Verarbeitung
```

---

## ARCHIVIERUNGSSYSTEM

Jeder Report wird revisionssicher archiviert:
```
archive/
└── kundenname/
    └── 2025-01/
        ├── 192.168.1.1_v1.pdf
        ├── 192.168.1.1_v1.meta.json  # Metadaten mit SHA256
        └── 192.168.1.1_v2.pdf        # Bei Updates neue Version
```

**Features:**
- Automatische Versionierung (`_v1`, `_v2`, ...)
- SHA256 Checksummen
- JSON Metadaten (Erstellungsdatum, Generator, Version)
- Monatliche Ordnerstruktur

---

## TESTSTATUS

```bash
pytest  # 82/82 Tests erfolgreich ✅

src/shodan_report/tests/
├── integration/                 # Komplette Pipeline-Tests
├── pdf/                        # PDF-Generierung
├── archiver/                   # Archivierungslogik
├── cli/                        # CLI-Parsing
└── ...                         # Alle Module getestet
```

---

## TECHNISCHE DETAILS

### Datenfluss
```
Shodan API → AssetSnapshot → Evaluation → Reporting → PDF → Archiv
       ↓           ↓             ↓           ↓         ↓       ↓
    Rohdaten   Normalisiert   Risiko-    Management-  Layout  Versioniert
                           bewertung       texte          +SHA256
```

### Kernfunktionen
- **Shodan Integration** - Vollständige API-Anbindung
- **AssetSnapshot Model** - Datenmodell für konsistente Verarbeitung
- **Risikobewertung** - Regelbasierte Evaluation (niedrig/mittel/hoch)
- **Trendanalyse** - Automatischer Monatsvergleich
- **PDF-Generierung** - ReportLab mit Corporate Design
- **Archivierung** - Revisionssicher mit SHA256 & Versionierung

---

## 📈 ROADMAP

### ABGESCHLOSSEN (MVP)
- [x] Shodan API Integration & Daten-Parsing
- [x] AssetSnapshot Model & Daten-Normalisierung
- [x] Regelbasierte Evaluation & Risiko-Priorisierung
- [x] Management-Text Generierung
- [x] Professionelles PDF-Layout (7 Abschnitte)
- [x] Revisionssichere Archivierung (SHA256, Versionierung)
- [x] Vollständige CLI mit allen Parametern
- [x] Batch-Verarbeitung mit `jobs.txt`
- [x] 82/82 Tests bestanden

### IN ARBEIT
- [~] PDF-Inhalte dynamisieren (hartcodierte → echte Daten)
- [~] Kundenkonfiguration voll integrieren

### ⏳ NÄCHSTE SCHRITTE (Priorisiert)
1. **PDF-Inhalte dynamisieren** - Echte Daten statt Beispiele
2. **CVE-Integration** - Echte Vulnerability Daten
3. **TLS/SSL Analyse** - Zertifikatsprüfung
4. **E-Mail-Versand** - Automatischer Report-Versand
5. **Web-Dashboard** - Übersicht aller Kundenreports

---

## RECHTLICHER HINWEIS

Jeder Report enthält automatisch:
> **Vertraulich – nur für den genannten Empfänger**  
> Dieser Bericht basiert auf öffentlich verfügbaren OSINT-Daten von Shodan.  
> Er stellt keine vollständige Sicherheitsanalyse dar und ersetzt keinen Penetrationstest.  
> Keine Garantie auf Vollständigkeit oder Richtigkeit. Dient ausschließlich zu Informationszwecken.

---

## SOFORT LOSLEGEN

```bash
# 1. Installation
git clone <repo>
cd shodan-report
.venv\Scripts\activate
pip install -e .

# 2. API Key setzen (PowerShell)
$env:SHODAN_API_KEY = "dein_api_key"

# 3. Testlauf
shodan-report --customer "Test" --ip "1.1.1.1" --month "2025-01" --verbose

# 4. Mit Trendanalyse
shodan-report --customer "Test" --ip "1.1.1.1" --month "2025-01" --compare "2024-12"
```

---

**Kontakt & Support**  
Bei Fragen oder Problemen: Issues im Repository öffnen.

**Lizenz**  
MIT License - Siehe `LICENSE` Datei.

---
*Letzte Aktualisierung: 09.01.2024 - MVP funktional, PDF-Layout komplett, Inhalte werden dynamisiert*
