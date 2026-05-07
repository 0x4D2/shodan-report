# Shodan Report — Detaillierte Dokumentation

Automatisierter Report-Generator für externe Sicherheitsanalysen auf Basis von OSINT- und Shodan-Daten.

Diese Datei ergänzt das Haupt-README um mehr Kontext zu Installation, Architektur, CVE-Enrichment, PDF-Aufbau und produktivem Betrieb.

## Kurzbeschreibung

`shodan-report` erstellt monatliche, reproduzierbare und revisionssichere PDF-Reports über die externe Angriffsfläche eines Assets. Zielgruppen sind sowohl Management als auch technische Teams: Management erhält verdichtete Kernaussagen und Prioritäten, technische Leser die zugrundeliegenden Dienste, Findings und Bewertungsdetails.

## Installation

Für die normale Nutzung:

```powershell
git clone <repo-url>
cd shodan-report
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

Für Entwicklung, Tests und CI:

```powershell
pip install -e .[dev]

# alternativ über den Dev-Shortcut
pip install -r requirements.txt
```

`pyproject.toml` ist die führende Quelle für Runtime- und Dev-Abhängigkeiten. `requirements.txt` dient nur als bequemer Einstiegspunkt für Dev-Umgebungen und installiert `-e .[dev]`.

## Schnellstart

API-Key in PowerShell setzen:

```powershell
$env:SHODAN_API_KEY = "DEIN_API_KEY"
```

Einfacher Reportlauf:

```powershell
shodan-report --customer "Testkunde" --ip "8.8.8.8" --month "2025-01"
```

Batch-Verarbeitung:

```powershell
python scripts/run-jobs-direct.py
```

## CLI-Optionen im Überblick

- `--customer`, `-c`: Kundenname
- `--ip`, `-i`: Ziel-IP
- `--domain`, `-d`: Ziel-Domain für Attack-Surface-Discovery
- `--month`, `-m`: Monat im Format `YYYY-MM`
- `--compare`: Vergleichsmonat
- `--config`: Kundenkonfiguration unter `config/customers/*.yaml`
- `--output-dir`, `-o`: Ausgabeordner
- `--from-snapshot`: PDF aus gespeichertem Snapshot neu rendern
- `--verbose`, `-v` und `--quiet`, `-q`: Ausgabesteuerung

## Konfiguration

Kundenkonfigurationen liegen unter `config/customers/`. Beispiel:

```yaml
customer:
  name: "Beispiel GmbH"
  ip: "1.2.3.4"
  domain: "beispiel.de"
  package: "professional"

report:
  include_trend_analysis: true
  cover_note: ""

styling:
  primary_color: "#1a365d"
  secondary_color: "#2d3748"

nvd:
  enabled: false
```

Wichtige Felder:

- `customer.name`: Anzeigename im Report und in Archivpfaden
- `customer.ip` oder `customer.ips`: explizite Zieladresse(n)
- `customer.domain`: aktiviert Domain-Discovery
- `customer.package`: steuert enthaltene Berichtsteile und NVD-Verhalten
- `report.include_trend_analysis`: schaltet Trendabschnitte ein oder aus
- `report.cover_note`: persönliche Analysten-Notiz auf Seite 1
- `styling.*`: Corporate-Farben für das PDF
- `nvd.enabled`: Live-NVD-Abfragen aktivieren

## Architektur und Workflow

Die Anwendung ist entlang klarer Verantwortungen geschnitten:

- `src/shodan_report/cli.py`: CLI-Entrypoint und Argumentvalidierung
- `src/shodan_report/core/runner.py`: Pipeline-Orchestrierung
- `src/shodan_report/clients/`: externe Datenquellen wie Shodan, NVD, CISA, EPSS, GreyNoise
- `src/shodan_report/parsing/`: Normalisierung der Rohdaten in interne Modelle
- `src/shodan_report/evaluation/`: Risikoermittlung und Priorisierung
- `src/shodan_report/reporting/`: Management- und Techniktexte
- `src/shodan_report/pdf/`: PDF-Komposition, Layout und Rendering
- `src/shodan_report/persistence/`: Snapshot-Speicherung
- `src/shodan_report/archiver/`: revisionssichere Archivierung mit Versionierung und Hashes

Vereinfachter Ablauf:

1. Kundenkonfiguration laden.
2. Daten per Shodan oder aus vorhandenem Snapshot beziehen.
3. Rohdaten in `AssetSnapshot` und `Service`-Objekte überführen.
4. Risiken, Exposure und Prioritäten berechnen.
5. Optional Trenddaten und Zusatzquellen anreichern.
6. Management- und Technikdaten vorbereiten.
7. PDF rendern.
8. Report archivieren und Metadaten schreiben.

## Wichtige Konzepte

- `AssetSnapshot`: internes Modell eines Host- oder Asset-Zustands
- `Service`: einzelner exponierter Dienst mit Port, Produkt, Version und Findings
- `EvaluationResult`: strukturierte Bewertung mit Risiko, Exposure und Empfehlungen
- `evaluation_result_to_dict()`: Übergabeformat für PDF-Rendering und Reporting

## CVE-Ermittlung und Enrichment

Die CVE-Aufbereitung läuft in mehreren Stufen:

1. Shodan-Snapshot lesen.
2. Im Parser CVEs, Banner, Produkte und Versionshinweise extrahieren.
3. CVEs lokal pro Port, CVSS und CPE aggregieren.
4. Optional zusätzliche Daten aus NVD, CISA KEV, EPSS oder ExploitDB anreichern.
5. Die Ergebnisse in die Risiko-Evaluierung und den PDF-Kontext übernehmen.

Wichtige Bausteine:

- `src/shodan_report/parsing/utils.py`: erstellt `AssetSnapshot`-Objekte aus Shodan-Rohdaten
- `src/shodan_report/evaluation/evaluators/cve_evaluator.py`: bewertet CVEs und erzeugt kritische Punkte
- `src/shodan_report/pdf/sections/data/cve_enricher.py`: reichert CVEs für den Bericht an
- `src/shodan_report/clients/nvd_client.py`: NVD-v2-Lookups
- `src/shodan_report/clients/cisa_client.py`: CISA-KEV-Abgleich

Hinweis: Ein Teil der Zuordnung bleibt OSINT-basiert. Im Report wird zwischen direkt beobachteten und hergeleiteten Findings unterschieden.

## PDF-Aufbau und Seitenlogik

Das PDF trennt Management- und Technikperspektive bewusst voneinander. Wichtige Ziele sind Lesbarkeit, Druckbarkeit und ein stabiler, wiederholbarer Aufbau.

Typische Abschnitte:

- Management-Zusammenfassung
- realistisches Angriffsszenario
- Handlungsempfehlungen
- Attack Surface bei Domain-Scans
- technischer Anhang
- CVE- und Exploit-Übersicht
- Trendanalyse
- Fazit
- Methodik und Grenzen

Warum explizite Seitenumbrüche und zusammengehaltene Blöcke genutzt werden:

- Tabellen und Kernabschnitte sollen nicht unkontrolliert zerrissen werden.
- Der Report bleibt beim Drucken und Archivieren konsistent.
- Der Seitenaufbau ist für wiederkehrende Monatsberichte leichter vergleichbar.

## Archivierung und Metadaten

Archivierte Reports liegen typischerweise unter `archive/{customer_slug}/{YYYY-MM}/`.

Die zugehörige `meta.json` enthält unter anderem:

- `customer_slug`
- `customer_name`
- `ip`
- `month`
- `pdf_path`
- `sha256`
- `size_bytes`
- `version`
- `generator`
- `created_at`

Die Kombination aus Versionierung und SHA256 dient der Nachvollziehbarkeit und Integritätsprüfung.

## Tests und Entwicklung

Tests liegen unter `src/shodan_report/tests/`.

```powershell
python -m pytest -q
```

Für fokussierte Läufe können Teilbereiche direkt ausgeführt werden, zum Beispiel:

```powershell
python -m pytest src/shodan_report/tests/pdf/ -q
python -m pytest src/shodan_report/tests/core/ -q
```

Die zuletzt verifizierte Suite lief am 2026-05-07 mit 913 grünen Tests.

## Empfehlungen für den produktiven Betrieb

- Für Batch-Jobs NVD-Feeds vorab mit `scripts/fetch_nvd_feeds.py` laden.
- Live-APIs nur gezielt aktivieren, um Rate-Limits zu vermeiden.
- Cache-Verhalten und TTLs für regelmäßige Reportläufe bewusst einstellen.
- Änderungen an der `EvaluationEngine` immer mit gezielten Tests absichern.
- Debug- und Demo-Ausgaben nicht als Produktionsartefakte übernehmen.

## Lizenz und Kontakt

Lizenz: MIT, siehe `LICENSE`.

Für Rückfragen oder Änderungen an Beispieldateien und Kundenkonfigurationen ist ein Repository-Issue der sinnvollste Einstiegspunkt.