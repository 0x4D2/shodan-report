
## Shodan Report — Kurzüberblick

`shodan-report` erzeugt aus Shodan‑Snapshots reproduzierbare PDF‑Reports mit Executive Summary und technischem Anhang.

**Kernfähigkeiten (Stand 2026-03):**
- **EOL-Erkennung** — identifiziert abgelaufene Betriebssysteme und Software aus Bannerversionen und priorisiert diese als Priorität-1-Risiko
- **TLS Verified Findings** — liest `ssl_info.versions` direkt aus Shodan-Daten; aktive unsichere Protokolle (SSLv2/3, TLSv1/1.1) erscheinen als farbige Warn-Boxen im Technischen Anhang
- **Risiko-Narrativ** — Management Summary nennt das höchste Risiko explizit, kombiniert RDP+EOL zum Ransomware-Einstiegspunkt und unterscheidet _Verified Findings_ (direkt beobachtet) von _Inferred Findings_ (Versionszuordnung)

Wichtige Links:

- Detaillierte Entwickler‑ und Architektur‑Dokumentation: [docs/DETAILED_README.md](docs/DETAILED_README.md)
- Beispiele & Demo: [examples/README.md](examples/README.md)

Schnellstart (Kurz):

1. Clone & install

```powershell
git clone <repo-url>
cd shodan-report
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

2. Set API key

```powershell
$env:SHODAN_API_KEY = "DEIN_API_KEY"
```

3. Run example

```powershell
# Mit bekannter IP:
shodan-report --customer "Testkunde" --ip "8.8.8.8" --month "2025-01"

# Mit Domain (Attack-Surface-Discovery automatisch):
shodan-report --customer "Testkunde" --domain "testkunde.de" --month "2026-04"
```

Konfiguration: siehe `config/example.yaml` für ein minimal Beispiel.

Bei tieferen Details zur Architektur, Evaluation, CVE‑Enrichment oder PDF‑Templates öffne bitte [docs/DETAILED_README.md](docs/DETAILED_README.md).

- `NVD_LIVE=1` (Env): Erzwingt Live‑NVD‑Lookups (alternativ per Kundenconfig `nvd.enabled`).
- `NVD_API_KEY` (optional): NVD API Key für höhere Raten/Limits; wird von `NvdClient` und `scripts/fetch_nvd_feeds.py` unterstützt.
- `fetch_nvd_feeds.py --years 2026,2025` lädt NVD JSON in `.cache/nvd/` zur Offline‑Nutzung.

Empfohlene Nutzung / Befehle:

```powershell
# Offline: NVD Jahresfeeds herunterladen (einmalig / regelmäßig)
python scripts/fetch_nvd_feeds.py --years 2026,2025

# Report mit NVD Lookup (Live‑API)
setx NVD_LIVE 1
setx NVD_API_KEY "DEIN_NVD_API_KEY"  # optional
shodan-report --customer "Kunde" --ip "1.2.3.4" --month "2026-01"
```

Hinweise & Empfehlungen:
- Performance & Ratenlimits: NVD Live‑API hat Rate‑Limits; für Batch‑Jobs empfiehlt sich das Vorladen der NVD‑Feeds oder Nutzung eines API‑Keys.
- Cache & TTL: Standard‑TTL ist 7 Tage; bei Bedarf TTL oder Cache‑Pfad per Aufruf an `enrich_cves(..., cache_ttl=..., cache_path=...)` anpassen.
- Konfigurierbarkeit: Scoring‑Schwellen (z. B. wann CVE→risk_score) sollten in `evaluation.config` ausgelagert werden — derzeit sind Schwellen in Code festcodiert (TODO).
- Testbarkeit: Unit‑Tests mocken `NvdClient` und `CisaClient` (siehe `src/shodan_report/tests/`), live NVD‑Tests sind per Env Flag (`NVD_LIVE_TESTS=1`) deaktiviert, es gibt Dummy‑Skripte zum Demo‑Generieren.

Sicherheits‑/Rechtsinfo:
- NVD und CISA sind öffentliche Datenquellen. CVEs aus Versionszuordnungen werden im Report explizit als **Inferred Findings** (Versionszuordnung, keine direkte Verifikation) ausgewiesen. TLS‑Protokolldaten aus dem Shodan‑Handshake werden als **Verified Findings** (direkt beobachtet) markiert.

---



---

## Notes / Known issues

- Die Produkt-/Versionserkennung befindet sich noch in der Feinjustierung. Nicht alle Versionen werden in allen Bannern zuverlässig erkannt.
- In der Management‑Zusammenfassung werden bewusst nur Versionen mit mittlerer oder hoher Konfidenz angezeigt, um irreführende Angaben zu vermeiden.
- EOL‑Erkennung basiert auf einer statischen Tabelle; produktspezifische Extended‑Support‑Verträge (z.B. Windows ESU) werden nicht berücksichtigt — Hinweis `(lizenzabhängig)` ist im Report sichtbar.


## SCHNELLSTART

### Installation
```bash
git clone <repository>
cd shodan-report
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -e .
```

### Ersten Report generieren (mit IP)
```bash
shodan-report --customer "Testkunde" --ip "8.8.8.8" --month "2025-01" --verbose
```

### Mit Domain (Attack-Surface-Discovery)
```bash
# Ermittelt automatisch alle exponierten IPs, wählt die beste für Shodan:
shodan-report --customer "Testkunde" --domain "testkunde.de" --month "2026-04" --verbose
```

### Mit Trendanalyse
```bash
shodan-report --customer "Testkunde" --ip "8.8.8.8" --month "2025-01" --compare "2024-12"
```

Hinweis: Wenn kein `--compare` angegeben ist, wird automatisch der vorherige Monat verwendet (falls Snapshot vorhanden).

---

## PROFESSIONELLER REPORT-AUFBAU (9 Abschnitte)

Jeder Report enthält automatisch:

1. **Management-Zusammenfassung** — Executive Summary mit Exposure-Level; benennt das höchste Risiko explizit; kombiniert RDP+EOL zum Ransomware-Narrativ; unterscheidet Verified vs. Inferred Findings
2. **Handlungsempfehlungen** — Konkrete Maßnahmen; EOL-Systeme automatisch als erstes Priorität-1-Element
3. **Attack Surface — Domain-Discovery** _(nur wenn `--domain` verwendet)_ — Alle passiv ermittelten IPs aus DNS, crt.sh und HackerTarget; CDN-Klassifizierung; Subdomains
4. **Technischer Anhang** — Ports, Dienste, Versionen, Risikobewertung; farbige Warn-Boxen für:
   - Shodan-Tags (doublepulsar, eol-product, …)
   - EOL/Near-EOL-Systeme aus Banneranalyse
   - TLS Verified Findings (aktive unsichere Protokolle direkt aus `ssl_info.versions`)
5. **CVE- & Exploit-Übersicht** — Schwachstellen mit CVSS Scores (als Inferred Findings gekennzeichnet)
6. **Trend- & Vergleichsanalyse** — Historische Entwicklung (mit Tabelle bei `--compare`)
7. **Fazit** — Zusammenfassung & Ausblick
8. **Methodik & Grenzen** — Transparente Dokumentation der Analyse inkl. Attack-Surface-Discovery-Quellen
9. **Footer** — Professioneller Disclaimer

> **Nummerierung:** Ohne `--domain` entfällt Abschnitt 3; die restlichen Abschnitte verschieben sich entsprechend.

---

## 🛠️ CLI PARAMETER

| Parameter | Beschreibung | Pflicht | Beispiel |
|-----------|-------------|---------|----------|
| `--customer`, `-c` | Kundenname | ✅ | `"CHINANET HUBEI"` |
| `--ip`, `-i` | IP-Adresse. Optional wenn `--domain` gesetzt. | ⚠️ (oder `--domain`) | `"111.170.152.60"` |
| `--domain`, `-d` | Kundendomain für Attack-Surface-Discovery. Ermittelt alle exponierten IPs passiv via OSINT und wählt automatisch die beste IP für die Shodan-Analyse. | ⚠️ (oder `--ip`) | `"example.com"` |
| `--month`, `-m` | Monat (YYYY-MM) | ✅ | `"2025-01"` |
| `--compare` | Vergleichsmonat für Trendanalyse | ❌ | `"2024-12"` |
| `--config` | Kundenkonfiguration (YAML) | ❌ | `config/customers/beispiel.yaml` |
| `--output-dir`, `-o` | Ausgabeverzeichnis für PDFs | ❌ | `./reports` |
| `--no-archive` | Deaktiviert revisionssichere Archivierung | ❌ | |
| `--verbose`, `-v` | Detaillierte Ausgabe | ❌ | |
| `--quiet`, `-q` | Minimale Ausgabe | ❌ | |

> **Hinweis:** Entweder `--ip` oder `--domain` muss angegeben werden. Werden beide angegeben, wird `--domain` für Attack-Surface-Discovery genutzt und `--ip` überschreibt die automatisch gewählte IP.

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

## WICHTIG: Hochprioritäre Konfiguration & Betriebshinweise

Diese Abschnitte sind für Betrieb und sichere Nutzung des Tools relevant — bitte lesen und in Produktionsumgebungen entsprechend anpassen.

- **Umgebungsvariablen (minimale Auswahl)**
  - **`SHODAN_API_KEY`**: Pflicht — API Key für Shodan (aus .env oder Umgebung).
  - **`NVD_API_KEY`**: Optional — API Key für NVD (höhere Raten/Quotas).
  - **`NVD_LIVE`**: Setze `1`, um Live‑NVD‑Lookups zu erzwingen (überschreibt Kundenconfig `nvd.enabled`).
  - **`NVD_LIVE_TESTS`** / **`NVD_LIVE`**: Wird in Tests/Debug‑Flows verwendet; nutze nur lokal/CI kontrolliert.

- **Wichtiges Kunden‑YAML (Ergänzung / Empfehlung)**
  - Ergänze in `config/customers/<name>.yaml` zumindest folgende Felder:

```yaml
report:
  include_trend_analysis: true   # true/false
  debug_mdata: false             # false in Prod: verhindert .mdata.json Sidecar

nvd:
  enabled: false                 # true für automatische NVD‑Lookups (oder setze NVD_LIVE=1)
```

- **Evaluation / Scoring (Kurzbeschreibung)**
  - Eingang: `AssetSnapshot` (IP, Services, Banners, vulns).
  - Engine: `EvaluationEngine.evaluate(snapshot)` → `EvaluationResult` mit Feldern:
    - `risk` (Enum `RiskLevel`: CRITICAL/HIGH/MEDIUM/LOW)
    - `exposure_score` (int 1–5)
    - `critical_points` (List[str])
    - `recommendations` (List[str])
  - Wichtige Heuristiken:
    - `_calculate_exposure_score` verwendet eine Kombination aus `risk_score` (Summen aus Service‑Evaluatoren) und Port‑Anzahl (Schwellen intern: 1–5).
    - `_determine_risk_level` prüft `critical_points` auf Schlüsselwörter (z.B. `rdp`, `cve`, `unverschlüsselt`) und kann `CRITICAL` direkt setzen.
  - Hinweis: Scoring‑Schwellen sind aktuell im Code festgelegt; für Anpassungen nutze `EvaluationConfig` bzw. wende Pull‑Request an.

- **`evaluation_result_to_dict` (PDF‑Mapping)**
  - Der Runner wandelt `EvaluationResult` in ein Dict mit folgenden erwarteten Feldern: `risk`, `risk_score`, `exposure_score`, `exposure_level` (z.B. `5/5`), `critical_points`, `critical_services`, `has_ssh/has_rdp/has_mysql`, Port‑Listen.
  - Achtung: Im Code gibt es doppelte Zuweisungen von `risk_str` — das ist dokumentiert und sollte bei Template‑Änderungen geprüft werden.

- **CVE / NVD / CISA (Betrieb & Cache)**
  - Ablauf: `generate_pdf` ruft intern `prepare_management_data()` und optional `enrich_cves()` auf. `enrich_cves` baut zuerst lokale Zuordnungen (CVE→Ports/CPEs/CVSS) und kann danach NVD/CISA ergänzen.
  - Konfig‑Priorität: `NVD_LIVE=1` (Env) überschreibt `nvd.enabled` in Kundenconfig.
  - Cache‑Pfad & Offline: Standardcache liegt unter `.cache/shodan_report/cve_cache.json` und NVD‑Feeds unter `.cache/nvd/`. Nutze `scripts/fetch_nvd_feeds.py` zum Vorladen für Offline‑Betrieb.
  - CISA KEV: Treffer werden markiert (`exploit_status = "public"`) und Quelle `cisa_kev` vermerkt.

- **Privacy / Sidecar‑Daten**
  - `generate_pdf` schreibt standardmäßig ein `.mdata.json` Sidecar neben dem PDF, wenn `debug_mdata` aktiv ist (default im Code war `True` — empfehlenswert: setze `report.debug_mdata: false` in Kundenconfig für Prod).
  - Sidecar enthält eine stark gesäuberte Sicht auf Services (Banners werden getrimmt, lange Base64‑Sequenzen redigiert). Trotzdem: diese Dateien können sensible Inhalte enthalten — behandeln wie vertrauliche Artefakte oder deaktivieren.

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

Lokale Änderungen direkt testen (ohne installierte Version):
```powershell
$env:USE_LOCAL_SRC=1; python scripts/run-jobs-direct.py
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

- 0) **Attack-Surface-Discovery** _(wenn `--domain` angegeben)_ — `scout_domain()` löst die Domain in alle exponierten IPs auf (DNS A/MX/NS, crt.sh, HackerTarget); CDN-IPs werden herausgefiltert; die beste IP wird als Analyse-Ziel gewählt.
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

```
324 passed, 9 skipped, 0 failed  (Stand 2026-03-31)
```

Tests lokal ausführen:
```powershell
python -m pytest -q
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
- **Shodan Integration** — Vollständige API-Anbindung
- **AssetSnapshot Model** — Datenmodell für konsistente Verarbeitung
- **EOL-Erkennungs-Engine** — statische Tabelle (28 Einträge); `evaluation/eol/eol_detector.py`; confidence high/medium/low; EOL als Priorität-1-Risiko
- **TLS Verified Findings** — `ssl_info.versions` (Shodan-Handshake-Daten); SSLv2/3 KRITISCH, TLSv1 HOCH, TLSv1.1 MITTEL; farbige Warn-Boxen im Technischen Anhang
- **Risikobewertung** — Regelbasierte Evaluation; RDP+EOL-Kombination als Ransomware-Narrativ in Management Summary
- **Trendanalyse** — Automatischer Monatsvergleich
- **PDF-Generierung** — ReportLab mit Corporate Design
- **Archivierung** — Revisionssicher mit SHA256 & Versionierung

---

## 📈 ROADMAP

### ABGESCHLOSSEN
- [x] Shodan API Integration & Daten-Parsing
- [x] AssetSnapshot Model & Daten-Normalisierung
- [x] Regelbasierte Evaluation & Risiko-Priorisierung
- [x] Management-Text Generierung mit Verified/Inferred-Unterscheidung
- [x] Professionelles PDF-Layout (9 Abschnitte)
- [x] Revisionssichere Archivierung (SHA256, Versionierung)
- [x] Vollständige CLI mit allen Parametern
- [x] Batch-Verarbeitung mit `jobs.txt`
- [x] EOL-Erkennungs-Engine (`evaluation/eol/`) — 28 Produkte, Priorität-1-Risiko
- [x] TLS Verified Findings — Warn-Boxen aus `ssl_info.versions`, 4 Schweregrade
- [x] RDP+EOL Ransomware-Narrativ in Management Summary
- [x] CVE-Integration (NVD/CISA, als Inferred Findings gekennzeichnet)
- [x] 324 Tests (9 skipped)

### ⏳ NÄCHSTE SCHRITTE (Priorisiert)
1. **TLS-Zertifikat-Details** — Ablaufdatum, selbstsigniert als eigene Warn-Box
2. **E-Mail-Versand** — Automatischer Report-Versand
3. **Web-Dashboard** — Übersicht aller Kundenreports

---

## RECHTLICHER HINWEIS

Jeder Report enthält automatisch:
> **Vertraulich – nur für den genannten Empfänger**  
> Dieser Bericht basiert auf öffentlich verfügbaren OSINT-Daten von Shodan.  
> Er stellt keine vollständige Sicherheitsanalyse dar und ersetzt keinen Penetrationstest.  
> Keine Garantie auf Vollständigkeit oder Richtigkeit. Dient ausschließlich zu Informationszwecken.

---

## Betriebs-Checklist (Kurz)

Vor einem Produktionslauf bitte sicherstellen:

- `SHODAN_API_KEY` ist gesetzt und gültig.
- `report.debug_mdata: false` in der Kundenconfig (verhindert Erzeugung sensibler Sidecar‑Dateien `.mdata.json`).
- `nvd.enabled` oder `NVD_LIVE` bewusst setzen (Live‑Lookups können Rate‑Limits verursachen).
- Offline‑Betrieb: vorab `python scripts/fetch_nvd_feeds.py --years <JAHRE>` ausführen, damit `.cache/nvd/` verfügbar ist.
- Logs/Monitoring: `generate_report_pipeline(..., verbose=True)` nur für Debug; in Produktion strukturierte Logs verwenden.

Siehe auch `SECURITY.md` für Responsible Disclosure und Umgang mit sicherheitsrelevanten Meldungen.

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
*Letzte Aktualisierung: 20.01.2026 - MVP funktional, PDF-Layout komplett, Inhalte werden dynamisiert*
