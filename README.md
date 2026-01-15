# Shodan Report — Automatisierte externe Sicherheitsanalyse (OSINT)
**Status: MVP FUNKTIONIERT - Interne Testversion mit professionellem Layout**
---
*Letzte Aktualisierung: 14.01.2026 — Teststatus: 145 passed, 6 failed. Bitte vor Release offene Tests beheben.*
Kurzfassung:  
Automatisierter Security Report Generator für externe Angriffsflächenanalyse. Erstellt professionelle monatliche Berichte basierend auf Shodan-Snapshots mit vollständiger Pipeline von der Datenerfassung bis zur revisionssicheren Archivierung.

---

## WICHTIGER HINWEIS

**AKTUELLER STATUS (14.01.2026):**
- Kernfunktionen und PDF-Layout sind implementiert. Einige PDF-Abschnitte nutzen noch hartkodierte Platzhalter (Dynamisierung in Arbeit).
- Teststatus: **145 passed, 6 failed** — Details zu den offenen Problemen weiter unten.


---

## Notes / Known issues

- Die Produkt-/Versionserkennung wurde verbessert, befindet sich aber noch in der Feinjustierung. Nicht alle Versionen werden in allen Bannern zuverlässig erkannt.
- In der Management‑Zusammenfassung werden bewusst nur Versionen mit mittlerer oder hoher Konfidenz angezeigt, um irreführende Angaben zu vermeiden. Das bedeutet, dass einige Versionsinformationen nicht im Executive‑Summary auftauchen, auch wenn sie technisch im Snapshot vorkommen.
- Die geplante `Top Vulnerability`‑Spalte im Management‑Table ist noch nicht aktiviert; diese wird nach weiterer CVE‑Zuordnung und Verifikation freigeschaltet.


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
│   ├── cli.py                   # CLI Entry Point
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
│   └── tests/                   # Tests (siehe Teststatus oben)
├── config/customers/            # Kundenkonfigurationen
├── archive/                     # Revisionssichere Ablage
│   └── {kunde}/{YYYY-MM}/{IP}_v{N}.pdf
├── reports/                     # Temporäre PDFs
└── scripts/run-jobs-direct.py  # Batch-Verarbeitung
```

## ARCHITEKTUR & WORKFLOW (Detaillierte Erklärung)

Zweck: `shodan-report` ist ein automatisierter Report-Generator für externe Sicherheitsanalysen (OSINT). Ziel ist es, monatlich reproduzierbare, revisionssichere Reports zu erzeugen, die Management und Technik klare Handlungsfelder liefern.

Pipeline (kurz und präzise, referenziert `src/shodan_report/core/runner.py`):

- 1) Kundenkonfiguration laden (`load_customer_config`) — YAML per `config/customers/*`.
- 2) Shodan API-Key aus Umgebung (`.env`) laden.
- 3) Shodan-Daten abrufen (`ShodanClient.get_host`) und in ein internes `Snapshot`-Modell parsen (`parse_shodan_host`).
- 4) Snapshot persistieren (`save_snapshot`) und optional historischen Snapshot laden (`load_snapshot`) für Trendanalyse.
- 5) Trendanalyse durchführen (`analyze_trend`) — liefert menschlich lesbare `trend_text`.
- 6) Evaluation mit `EvaluationEngine` (zentrale Komponente): aus dem `Snapshot` wird ein `EvaluationResult` erzeugt.
- 7) Business-Risiko ableiten (`prioritize_risk`) — wird im Management-Teil verwendet.
- 8) Management-Text generieren (`generate_management_text`) und HTML-Tags entfernen (Runner macht `re.sub`).
- 9) Technischen Anhang bauen (`build_technical_data`).
- 10) PDF erzeugen (`generate_pdf`) — `evaluation_result` wird vorher durch `evaluation_result_to_dict` in ein Template-kompatibles Dict umgewandelt.
- 11) Report revisionssicher archivieren (`ReportArchiver.archive_report`) inklusive SHA256 & Versionierung.

Wichtige Konzepte / Objekte:

- `EvaluationEngine` (Empfohlen):
  - Eingabe: `Snapshot` (von Shodan-parsing)
  - Ausgabe: `EvaluationResult` mit klaren Attributen:
    - `risk`: Enum `RiskLevel` (z.B. `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
    - `exposure_score`: Ganzzahl 1–5 (Exponiertheit)
    - `critical_points`: Liste von Strings (kurze Problembeschreibungen)
    - optional `messages`: zusätzliche Hinweise / Warnungen
  - Gründe: zentrale, testbare, erweiterbare Bewertungslogik; ersetzt ältere, verstreute Funktionen.

- `evaluation_result_to_dict(evaluation_result)` (Runner-Wrapper):
  - Zweck: Normiert `EvaluationResult` in ein Dictionary, das das PDF-Template erwartet.
  - Mapped Felder: `risk` → string (lowercase), `risk_score` (numerisch für Visualisierung), `exposure_score`, `exposure_level` (z.B. `5/5`), `critical_points_count`, `critical_services`, `has_ssh`/`has_rdp`/`has_mysql`, uvm.
  - Hinweis: Anpassungen hier sind normal, wenn PDF-Templates oder Sections neue Felder benötigen.

- Deprecation: `_calculate_exposure_level(critical_points: List[str])` ist im Runner als veraltet markiert — benutze stattdessen `evaluation_result.exposure_score` aus der `EvaluationEngine`.

Debugging / Entwicklungshinweise (aus `runner.py`):

- Der Runner enthält temporäre Debug-Prints (z.B. `Evaluation Dict nach Konvertierung`, `DEBUG: Evaluation Result vor PDF-Generierung`). Diese helfen beim Entwickeln, sollten vor Produktions-Run auf `verbose`/logging umgestellt oder entfernt werden.
- Wenn Tests ImportError melden (z.B. fehlende Module unter `shodan_report.pdf.helpers`), prüfen: relative vs. absolute Imports und Paketstruktur (`src` in `pyproject.toml` ist korrekt eingestellt).

Keine offenen Fragen (FAQ-basiert):

- Q: Was ist die primäre Eingabe?  
  A: Ein Shodan-Snapshot für eine IP (JSON → internal `Snapshot`).

- Q: Wer berechnet das Risiko?  
  A: `EvaluationEngine` liefert `EvaluationResult`; `prioritize_risk` wandelt das technischen Ergebnis in Business-Risk um.

- Q: Was verwendet das PDF?  
  A: `generate_pdf` erwartet die normalisierten Felder — `evaluation_result_to_dict` sorgt für Kompatibilität.

- Q: Warum `_calculate_exposure_level` noch im Repo?  
  A: Historischer Fallback; markiert als deprecated. Produktionscode soll `evaluation_result.exposure_score` nutzen.

- Q: Wie gehe ich mit fehlschlagenden Tests um?  
  A: `pytest -q` ausführen, Fehlermeldungen lesen (ImportErrors → Pfade/Init prüfen; AssertionErrors → Bewertungslogik/Defaultwerte prüfen). Siehe `TESTSTATUS` Abschnitt.

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

## TESTSTATUS (AKTUELL)

- Gesamt: **145 passed, 6 failed** (Stand: 14.01.2026)
- Bekannte Probleme (Kurzüberblick):
  - ImportError beim Laden einiger PDF-/Evaluation-Helper → Importpfade prüfen
  - Management-Text: Aufzählungen werden bei vielen Punkten abgeschnitten (nur 10 gelistet)
  - CVE-Konvertierung: Default-CVSS-Werte werden aktuell nicht wie erwartet gesetzt

Tipp: Tests lokal ausführen mit `pytest -q` oder `pytest tests/<file>`


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
- [~] PDF-Inhalte dynamisieren (einige Sections noch statisch)
- [~] CVE-Integration: Parsing & Normalisierung (teilweise umgesetzt)

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
