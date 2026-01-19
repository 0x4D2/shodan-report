""""markdown
# Shodan Report — Detaillierte Dokumentation

Automatisierter Report-Generator für externe Sicherheitsanalysen (OSINT).

Dieser Text erklärt Zweck, Architektur, Installation, typische Abläufe und wichtige Dateien.

## Kurzbeschreibung

`shodan-report` erstellt monatliche, reproduzierbare und revisionssichere PDF-Reports über die externe Angriffsfläche einer IP-Adresse basierend auf Shodan-Snapshots. Zielgruppen sind technische Teams (Details) und Management (Executive Summary).

## Hauptfunktionen

- Shodan-Daten abrufen und normalisieren
- Regelbasierte Risiko-Evaluation (zentral: `EvaluationEngine`)
- Trendanalyse (Monatsvergleiche)
- Professionelle PDF-Erzeugung mit Management- und Technik-Abschnitten
- Revisionssichere Archivierung mit Versionierung und SHA256
- CLI für Einzel- und Batchverarbeitung

## Schnellstart

1. Repository klonen

```powershell
git clone <repo-url>
cd shodan-report
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

2. API-Key (PowerShell)

```powershell
$env:SHODAN_API_KEY = "DEIN_API_KEY"
```

3. Einfache Nutzung

```powershell
shodan-report --customer "Testkunde" --ip "8.8.8.8" --month "2025-01"
```

4. Batch mit `jobs.txt`

```powershell
python scripts/run-jobs-direct.py
```

## CLI-Optionen (Auszug)

- `--customer`, `-c` : Kundenname
- `--ip`, `-i` : Ziel-IP
- `--month`, `-m` : Monat (YYYY-MM)
- `--compare` : Vergleichsmonat
- `--config` : Kundenkonfiguration (`config/customers/*.yaml`)
- `--output-dir`, `-o` : Ausgabeordner
- `--verbose`, `-v` / `--quiet`, `-q`

## Konfiguration

Kundenkonfigurationen liegen in `config/customers/`. Beispielstruktur:

```yaml
customer:
  name: "Beispiel GmbH"
  language: "de"

report:
  include_trend_analysis: true

styling:
  primary_color: "#1a365d"
```

## Architektur & Workflow (Kurz)

Ziel: Klar getrennte, testbare Schritte von Datenaufnahme bis Archiv.

Hauptkomponenten (Ort und Aufgabe):

- `src/shodan_report/cli.py` — CLI-Entrypoint
- `src/shodan_report/core/runner.py` — Orchestrierung der Pipeline
- `src/shodan_report/evaluation/` — Bewertungslogik (`EvaluationEngine`)
- `src/shodan_report/pdf/` — PDF-Generierung und Layout
- `src/shodan_report/archiver/` — Revisionssichere Archivierung
- `config/customers/` — Kunden-spezifische Einstellungen
- `scripts/` — Utility- und Batch-Skripte (z. B. `run-jobs-direct.py`)

Pipeline (vereinfacht):

1. Kundenkonfiguration laden
2. Shodan-Daten abrufen oder lokalen Snapshot verwenden
3. Snapshot normalisieren (Asset-Model)
4. Evaluation: Risiko-Level und Prioritäten bestimmen
5. Trendanalyse (optional)
6. Management- und Techniktexte generieren
7. PDF erzeugen
8. Archivierung (SHA256, Versionierung)

## Wichtige Konzepte

- `Snapshot` — internal Modell für Shodan-Hostdaten
- `EvaluationResult` — strukturierte Bewertung (risk, exposure_score, critical_points)
- `evaluation_result_to_dict()` — Normiert Ergebnis für PDF-Templates

## Tests

Tests befinden sich unter `src/shodan_report/tests/`. Lokal ausführen mit:

```powershell
pytest -q
```

## Wartung & Weiterentwicklung

- PDF-Layout soll schrittweise modularisiert werden (`src/shodan_report/pdf/sections/`).
- `EvaluationEngine` ist zentral: Änderungen sollen hier getestet werden.
- Bekannte Probleme und Teststatus sind im Repository-TODO bzw. CI dokumentiert.

## Lizenz

MIT — siehe `LICENSE`.

## Kontakt

Bei Fragen öffne ein Issue oder kontaktiere das Team über die Repository-Kanäle.

"""" # Detaillierte Dokumentation: Konfiguration, CVE‑Ermittlung & PDF‑Metadaten

Diese Datei beschreibt detailliert die Konfigurationsfelder, wie CVEs aus Shodan‑Snapshots ermittelt und angereichert werden, welche Metadaten beim Archivieren erzeugt werden und wie das PDF strukturiert ist — inklusive Gründen für Seitenumbrüche.

## 1) Konfiguration (Detailliert)

Pfad: `config/customers/{name}.yaml`

Wichtige Felder und Bedeutungen:

- `customer.name` (string): Anzeigename des Kunden, wird in PDF Header und Archiv‑Pfaden verwendet.
- `customer.language` (string): `de` oder `en` — wählt Sprache der generierten Texte.
- `report.include_trend_analysis` (bool): Bei `false` werden Trend‑Sektionen übersprungen.
- `report.nvd.enabled` (bool): Aktiviert Live‑NVD‑Lookups für CVE‑Anreicherung.
- `styling.primary_color`, `styling.secondary_color` (hex): Corporate Farben für Diagramme/Highlights.
- `pdf.include_toc` (bool): Fügt ein Inhaltsverzeichnis ein, nützlich für lange Reports.
- `disclaimer.enabled`, `disclaimer.text`: Footer‑Disclaimer aktivieren und anpassen.
- `archive.enabled`, `archive.root`: Archivierung aktivieren und alternativen Ort setzen.

Empfehlungen:
- Für Batch‑Runs `report.nvd.enabled` standardmäßig `false` und stattdessen die NVD‑Feeds vorab herunterladen.
- Stelle sicher, dass `customer.name` einzigartig ist, da daraus der `customer_slug` für Archivrechte abgeleitet wird.

## 2) PDF‑Metadaten & Archiv‑Meta (Format)

Archiv‑Metadatei: `archive/{customer_slug}/{YYYY-MM}/{YYYY-MM}_{ip}.meta.json`

Beispielfelder (aus `ReportArchiver._create_metadata`):

- `customer_slug`: slugifizierter Kundenname (z. B. `beispiel_gmbh`)
- `customer_name`: Originalname
- `ip`: Zieladresse
- `month`: YYYY‑MM
- `pdf_path`: Pfad relativ zum Archivverzeichnis
- `sha256`: SHA256 Hash des PDF (Integrität)
- `size_bytes`: Dateigröße in Bytes
- `version`: numerische Version (1,2,...)
- `generator`: z. B. "shodan-report"
- `created_at`: ISO Timestamp
- `extra`: optionales Freifeld

Hinweis: Für Revisionssicherheit nutze die `meta.json` zur Verifikation (SHA256 + Versionierung).

## 3) Wie CVEs ermittelt werden (Step‑by‑Step)

1) Rohdatenquelle: Shodan Host JSON
- Shodan liefert pro Service Einträge (`data[]`), oft mit `vulns` (Liste von CVE IDs oder Objekten).

2) Parsing
- `src/shodan_report/parsing/utils.py::parse_shodan_host` erzeugt ein `AssetSnapshot` mit `Service`‑Objekten.
- `parse_service` extrahiert `product`, `version`, `raw` Banner, `vulnerabilities` und strukturiert Zusatzinfos (`_extra_info`).

3) Lokale Aggregation
- `cve_enricher.build_cve_port_map(technical_json)` aggregiert für jede CVE: beobachtete Ports, max CVSS (wenn im Snapshot vorhanden) und CPEs.

4) Evaluierung
- `evaluation/evaluators/cve_evaluator.py` konvertiert Rohdaten über Helper (`convert_to_cve_objects`) in interne `CVE`–Objekte (id, cvss, description, etc.).
- `count_cves_by_severity` und `_calculate_cve_risk_score` führen zu einem numerischen CVE‑Score.
- `CVEEvaluator._generate_detailed_critical_points` erzeugt menschenlesbare `critical_points` (z. B. "3 kritische CVEs", "Kritischste CVE: CVE‑XXXX (CVSS 9.8)").

5) Optionales externes Enrichment
- NVD: `src/shodan_report/clients/nvd_client.py` (NVD v2 API) kann zusätzliche Felder liefern: `summary`, konsistente `cvss`, CPEs.
- CISA KEV: `src/shodan_report/clients/cisa_client.py` liefert KEV IDs; Treffer → `exploit_status = "public"`.
- `cve_enricher.enrich_cves(..., lookup_nvd=True)` führt Lookup + Cache (TTL, `.cache/shodan_report/cve_cache.json`) durch.

6) Aggregation in Report
- `EvaluationEngine` summiert Service‑Risiken inkl. CVE‑Contributions und produziert ein `EvaluationResult` (ip, risk enum, exposure_score, critical_points, recommendations).
- `evaluation_result_to_dict()` konvertiert für das PDF‑Template.

Konfigurierbar / ToDo:
- Scoring‑Schwellen sollten in `EvaluationConfig` liegende Parameter sein (anstatt hartkodiert).

## 4) PDF‑Aufbau & Seitenumbrüche — Warum so gestaltet?

Ziele des Layouts:
- Zielgruppentrennung: Management benötigt kompakte, nicht fragmentierte Kernaussagen. Techniker benötigt detaillierte Listen.
- Druckbarkeit & Signatur: Feste Abschnitte erleichtern das Ausdrucken und Unterzeichnen.
- Lesbarkeit: Tabellen und Diagramme sollen nicht über Seiten hinweg zerrissen werden.

Konkrete Sections (entsprechend dem Generator):
- Cover / Header: Metadaten, Generator‑Version
- Executive Summary: Kurzbewertung + Top‑Risiken
- Scorecards: Visualisierungen (Risk/Exposure/Trend)
- Trendvergleich: Tabellen/Charts
- Empfehlungen: Handlungsorientierte To‑Dos
- Technischer Anhang: Lange Tabellen, Services, Banners
- CVE Übersicht: Tabellarische CVE‑Liste, Links zu NVD
- Methodik & Grenzen: Transparenz über Datenquellen und Limitationen
- Footer / Disclaimer

Warum PageBreaks verwendet werden:
- ReportLab verwendet Flowables; `PageBreak` sorgt dafür, dass ein neuer Abschnitt sauber auf einer neuen Seite beginnt.
- Regeln wie "halte Tabelle zusammen" oder "Umbruch vor Tabelle" verhindern unschöne Layoutbrüche.
- Ein konsistenter Seitenaufbau erleichtert das Nachschlagen (TOC), die Archivierung und die Darstellung in Clients.

Technische Hinweise für Entwickler:
- Sections in `src/shodan_report/pdf/sections/` geben Flowable‑Listen zurück; `generate_pdf` fügt diese zusammen.
- Für Tests sind Sections als Callables injizierbar (Mock‑Sections), was Rendering ohne ReportLab erlaubt.

## 5) Empfehlungen für den produktiven Betrieb

- Batch‑Jobs: NVD‑Feeds vorab herunterladen (`scripts/fetch_nvd_feeds.py`) oder `NVD_API_KEY` verwenden.
- Cache: TTL anpassen, wenn Reports in kurzen Intervallen laufen.
- Konfiguration: Scoring‑Parameter in `EvaluationConfig` auslagern, um feingranulare Anpassung ohne Codeänderung zu ermöglichen.

---

Bei Fragen zur Datei oder wenn du möchtest, dass ich die Änderungen direkt in `config/customers/example.yaml` vornehme (z. B. `report.nvd.enabled: false`), sag kurz Bescheid.