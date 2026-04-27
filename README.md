# shodan-report

Automatisierter Generator für revisionssichere OSINT-Sicherheitsberichte auf Basis von Shodan-Daten. Erzeugt professionelle PDF-Reports mit Management-Zusammenfassung, CVE-Übersicht, Trendanalyse und technischem Anhang.

---

## Schnellstart

```powershell
# 1. Klonen & installieren
git clone <repo-url>
cd shodan-report
python -m venv .venv
.venv\Scripts\activate
pip install -e .

# 2. .env anlegen
copy .env.example .env
# SHODAN_API_KEY eintragen

# 3. Ersten Report generieren
shodan-report --customer "Beispiel GmbH" --ip "1.2.3.4" --month "2026-04"
```

---

## Umgebungsvariablen

Kopiere `.env.example` nach `.env` und passe die Werte an:

| Variable | Pflicht | Beschreibung |
|---|---|---|
| `SHODAN_API_KEY` | ✅ | Shodan API Key |
| `OUTPUT_BASE_DIR` | ❌ | Basisverzeichnis für Reports/Snapshots/Archiv (Standard: CWD) |
| `NVD_API_KEY` | ❌ | NVD API Key (erhöht Rate-Limit) |
| `NVD_LIVE` | ❌ | `1` = Live-NVD-Abfragen erzwingen |
| `NVD_PROGRESS` | ❌ | `1` = Fortschrittsanzeige bei NVD-Abfragen |
| `GREYNOISE_API_KEY` | ❌ | GreyNoise API Key (Community-Tier kostenlos) |
| `HIBP_API_KEY` | ❌ | HaveIBeenPwned API Key — ohne Key: manuelle Check-Links im Report |

---

## CLI

```
shodan-report --customer NAME --ip IP --month YYYY-MM [Optionen]
```

| Parameter | Pflicht | Beschreibung |
|---|---|---|
| `--customer`, `-c` | ✅ | Kundenname |
| `--ip`, `-i` | ⚠️ | IP-Adresse (oder `--domain`) |
| `--domain`, `-d` | ⚠️ | Domain für Attack-Surface-Discovery (oder `--ip`) |
| `--month`, `-m` | ✅ | Berichtsmonat `YYYY-MM` |
| `--compare` | ❌ | Vergleichsmonat für Trendanalyse |
| `--config` | ❌ | Pfad zur Kundenkonfiguration (YAML) |
| `--note`, `-n` | ❌ | Persönliche Ansprache auf Seite 1 (überschreibt `report.cover_note` aus YAML) |
| `--from-snapshot` | ❌ | PDF neu rendern ohne Shodan-Aufruf — nutzt gespeicherten Snapshot |
| `--output-dir`, `-o` | ❌ | Ausgabeverzeichnis |
| `--no-archive` | ❌ | Revisionssichere Archivierung deaktivieren |
| `--verbose`, `-v` | ❌ | Detaillierte Ausgabe |
| `--quiet`, `-q` | ❌ | Minimale Ausgabe |

**Beispiele:**

```powershell
# Report mit IP
shodan-report --customer "Acme GmbH" --ip "203.0.113.5" --month "2026-04"

# Mit Domain (Attack-Surface-Discovery automatisch)
shodan-report --customer "Acme GmbH" --domain "acme.de" --month "2026-04"

# Mit Trendvergleich
shodan-report --customer "Acme GmbH" --ip "203.0.113.5" --month "2026-04" --compare "2026-03"

# Mit Kundenkonfiguration
shodan-report --customer "Acme GmbH" --ip "203.0.113.5" --month "2026-04" --config config/customers/acme.yaml

# Persönliche Ansprache hinzufügen (kein neuer Shodan-Aufruf)
shodan-report --customer "Acme GmbH" --month "2026-04" --config config/customers/acme.yaml \
  --from-snapshot --note "Lage stabil, empfehle Überprüfung Port 8080."
```

---

## Report-Aufbau

Jeder Report enthält bis zu 9 Abschnitte:

| # | Abschnitt | Bedingung |
|---|---|---|
| 1 | **Management-Zusammenfassung** — KPI-Zeile (IP · Ports · CVEs · Kritisch · CISA KEV · Exploit), Exposure-Level, Kernaussagen, Empfehlung | immer |
| 2 | **Realistisches Angriffsszenario** — datengetriebene 4-stufige Angriffskette (Reconnaissance → Schwachstellen → Zugriff → Impact) mit Phasen-Balken und Schnell-Fakten | immer |
| 3 | **Handlungsempfehlungen** — Priorität 1–3 mit farbigen Badges; Credential Exposure (HIBP) direkt unter Priorität 3 integriert | immer |
| 4 | **Attack Surface / Domain-Discovery** — alle exponierten IPs, Subdomains, CDN-Filter | nur mit `--domain` |
| 5 | **Technischer Anhang** — Dienste, Versionen, TLS-Findings, EOL-Erkennung | immer |
| 6 | **CVE- & Exploit-Übersicht** — CVSS-Badges, ExploitDB-Status, EPSS-Score (30 Tage), CISA KEV | wenn CVEs vorhanden |
| 7 | **Trend- & Vergleichsanalyse** — Monatsvergleich mit Tabelle | wenn `--compare` oder Snapshot vorhanden |
| 8 | **Fazit** | immer |
| 9 | **Methodik & Grenzen** — Begriffe, Exposure-Level-Tabelle, Discovery-Quellen; Footer mit SHA256-Signatur | immer |

---

## Kundenkonfiguration (YAML)

Jeder Kunde bekommt eine Datei unter `config/customers/<name>.yaml`. IP, Domain, Vertragsbeginn und Paket werden dort zentral gepflegt.

```yaml
# config/customers/beispiel.yaml
customer:
  name: "Beispiel GmbH"
  ip: "1.2.3.4"                    # Primäre IP-Adresse
  domain: "beispiel.de"            # optional — aktiviert Attack-Surface-Discovery
  contract_start: "2026-01-01"     # Vertragsbeginn
  package: "professional"          # basic | professional | enterprise

styling:
  primary_color: "#1a365d"
  secondary_color: "#2d3748"

report:
  cover_note: ""                   # Persönliche Ansprache auf Seite 1 (oder via --note)
  debug_mdata: false               # false in Produktion (kein .mdata.json Sidecar)

nvd:
  enabled: false                   # bei package=enterprise automatisch true
```

**Pakete:**

| Paket | Enthaltene Abschnitte |
|---|---|
| `basic` | Management, Empfehlungen, Technischer Anhang, Attack Surface (wenn domain gesetzt) |
| `professional` | + CVE-Übersicht, Trendanalyse |
| `enterprise` | wie professional + NVD Live-Lookups automatisch aktiv |

---

## Batch-Verarbeitung

`jobs.txt` — eine Job-Definition pro Zeile. Zwei Formate werden unterstützt:

```
# Kurzformat: IP/Domain aus YAML (empfohlen)
Beispiel GmbH 2026-04
Beispiel GmbH 2026-04 --compare 2026-03

# Langformat: IP explizit (für Ausnahmen ohne YAML)
Kunde2 5.6.7.8 2026-04
Kunde3 9.10.11.12 2026-04 --config config/customers/kunde3.yaml
```

```powershell
python scripts/run-jobs-direct.py

# Lokale Entwicklungsversion verwenden (ohne pip install)
$env:USE_LOCAL_SRC=1; python scripts/run-jobs-direct.py
```

---

## NVD / CVE-Enrichment

CVE-Daten werden in drei Stufen angereichert:

1. **Lokal aus Snapshot** — CVEs direkt aus Shodan-Daten (Ports, CPEs, CVSS)
2. **NVD-Cache** — Offline aus vorgeladenen Jahresfeeds (`.cache/nvd/`)
3. **NVD-Live** — Direkte API-Abfrage (mit `NVD_LIVE=1` oder `nvd.enabled: true`)

Jahresfeeds vorladen (empfohlen für Batch-Betrieb):

```powershell
python scripts/fetch_nvd_feeds.py --years 2026,2025,2024
```

CVEs aus Versionszuordnungen werden im Report als **Inferred Findings** gekennzeichnet. TLS-Protokolldaten aus dem Shodan-Handshake als **Verified Findings**.

Zusätzliche OSINT-Quellen pro CVE (automatisch, kein API-Key nötig):

| Quelle | Beschreibung | Cache |
|---|---|---|
| **ExploitDB** | Öffentliche Exploit-Datenbank — bestätigt verfügbaren Angriffscode | 24 h (`~/.cache/shodan_report/exploitdb/`) |
| **EPSS** (FIRST.org) | Exploit Prediction Scoring System — Ausnutzungswahrscheinlichkeit in 30 Tagen (0–100 %) | kein lokaler Cache, Batch à 100 CVEs |
| **CISA KEV** | Known Exploited Vulnerabilities — aktiv in der Praxis ausgenutzte CVEs | im NVD-Feed enthalten |
| **GreyNoise** | IP-Reputationsdienst — RIOT/CLEAN/NOISE/MALICIOUS | Community-Tier: 25 Req./Woche |

---

## Archivierung

Jeder Report wird revisionssicher archiviert:

```
archive/
└── beispiel_gmbh/
    └── 2026-04/
        ├── 2026-04_1.2.3.4_v1.pdf
        ├── 2026-04_1.2.3.4_v2.pdf  # Bei Nachgenerierung automatisch neue Version
        └── 2026-04_1.2.3.4.meta.json
            # Enthält: SHA256, Erstellungsdatum, Generator-Version
            # + cover_note: persönliche Einschätzung des Analysten (gespeichert via --note)
```

Die `cover_note` wird beim nächsten Monats-Report automatisch im Terminal angezeigt — als Erinnerung was zuletzt geschrieben wurde.

---

## Projektstruktur

```
shodan-report/
├── src/shodan_report/
│   ├── cli.py                        # CLI Entry Point
│   ├── paths.py                      # Zentrale Pfad-Konfiguration (OUTPUT_BASE_DIR)
│   ├── core/runner.py                # Haupt-Pipeline
│   ├── pdf/
│   │   ├── pdf_generator.py          # Einstiegspunkt PDF-Generierung
│   │   ├── pdf_manager.py            # Element-Koordination
│   │   ├── pdf_renderer.py           # ReportLab-Rendering, SHA256-Footer
│   │   ├── styles.py                 # Farbpalette, Typografie
│   │   └── sections/
│   │       ├── management.py         # Management-Zusammenfassung, KPI-Zeile
│   │       ├── technical.py          # Technischer Anhang
│   │       ├── cve_overview.py       # CVE-Tabelle, CVSS-Badges
│   │       ├── trend.py              # Trendanalyse
│   │       ├── recommendations.py    # Handlungsempfehlungen
│   │       ├── attack_surface.py     # Domain-Discovery-Ergebnisse
│   │       ├── attack_scenario.py    # Realistisches Angriffsszenario
│   │       ├── credential_exposure.py # HIBP Credential Exposure (integriert in Empfehlungen)
│   │       ├── conclusion.py         # Fazit
│   │       ├── methodology.py        # Methodik & Grenzen
│   │       ├── header.py / footer.py
│   │       └── data/
│   │           ├── cve_enricher.py   # NVD/CISA-Enrichment
│   │           ├── cve_mapper.py     # CVE→Service-Zuordnung
│   │           ├── management_data.py
│   │           └── technical_data.py
│   ├── evaluation/                   # Risikobewertung (EvaluationEngine)
│   ├── reporting/                    # Textgenerierung
│   ├── archiver/                     # SHA256, Versionierung
│   ├── clients/                      # API-Clients (Shodan, NVD, CISA, ExploitDB, EPSS, GreyNoise)
│   ├── persistence/                  # Snapshot-Speicherung
│   └── tests/                        # 749 Tests, 9 skipped
├── config/
│   ├── customers/                    # Kundenkonfigurationen (YAML)
│   ├── evaluation.yaml               # Scoring-Konfiguration
│   └── example.yaml
├── scripts/                          # Hilfsskripte (Batch, NVD-Feeds, Demo-PDFs)
├── .env.example
└── jobs.txt                          # Batch-Job-Definitionen
```

---

## Tests

```powershell
# Alle Tests
python -m pytest -q

# Nur PDF-Tests
python -m pytest src/shodan_report/tests/pdf/ -q
```

Aktueller Stand: **768 passed, 9 skipped** (Stand 2026-04-27)

---

## Bekannte Einschränkungen

- EOL-Erkennung basiert auf einer statischen Tabelle; Extended-Support-Verträge (z.B. Windows ESU) werden nicht berücksichtigt — Hinweis `(lizenzabhängig)` ist im Report sichtbar
- CVE-Servicezuordnung ist OSINT-basiert (Versionszuordnung, nicht verifiziert) — im Report als "OSINT-Indiz" gekennzeichnet
- NVD Live-API unterliegt Rate-Limits; für Batch-Betrieb NVD-Feeds vorher laden
- `debug_mdata: true` erzeugt `.mdata.json` Sidecar neben der PDF — in Produktion deaktivieren
- GreyNoise Community-Tier ist auf 25 Anfragen/Woche limitiert; bei Überschreitung erscheint "–" im Exposure-Beitragsfaktor
- ExploitDB-CSV wird täglich aktualisiert; lokaler Cache läuft nach 24 h ab und wird automatisch erneuert

---

## Rechtlicher Hinweis

Jeder Report enthält automatisch:

> **Vertraulich – nur für den genannten Empfänger.**  
> Dieser Bericht basiert auf öffentlich verfügbaren OSINT-Daten (Shodan).  
> Er stellt keine vollständige Sicherheitsanalyse dar und ersetzt keinen Penetrationstest.  
> Dient ausschließlich zu Informationszwecken.

---

*Stand: 2026-04-27 — Branch `feature/data-enrichment`*
