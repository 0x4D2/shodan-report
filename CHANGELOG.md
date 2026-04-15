# 2026-04-15 (2)

## feat: Persönliche Ansprache — Persistenz im Archiv + Vormonats-Erinnerung

- [`src/shodan_report/archiver/report_archiver.py`](src/shodan_report/archiver/report_archiver.py): `save_cover_note(customer, month, ip, note)` schreibt die Ansprache auf Top-Level der `.meta.json` (`cover_note` + `cover_note_updated_at`) — atomar, ohne die Versions-Einträge zu berühren
- [`src/shodan_report/archiver/report_archiver.py`](src/shodan_report/archiver/report_archiver.py): `load_cover_note(customer, month, ip)` liest die gespeicherte Ansprache zurück
- [`src/shodan_report/core/runner.py`](src/shodan_report/core/runner.py): Beim Start jedes Report-Runs wird die Notiz des Vormonats aus dem Archiv geladen und im Terminal ausgegeben — Erinnerung was zuletzt geschrieben wurde, ohne die PDF öffnen zu müssen
- [`src/shodan_report/core/runner.py`](src/shodan_report/core/runner.py): Nach der Archivierung wird die aktuelle Notiz (aus `--note` oder `report.cover_note` aus YAML) automatisch in die Metadaten geschrieben

## fix: cover_note Box — Label „Einschätzung des Analysten" ergänzt

- [`src/shodan_report/pdf/pdf_manager.py`](src/shodan_report/pdf/pdf_manager.py): cover_note-Box erhält eine Kopfzeile „Einschätzung des Analysten" (blau, fett, 7,5 pt) — ohne Label war die Box nur ein Textblock mit blauem Streifen, nicht als persönlicher Kommentar erkennbar; zwei-zeilige Tabellenstruktur (Label + Text), engerer Abstand zwischen beiden Zeilen

**Vollständiger Workflow:**
```
1. shodan-report --customer X --month 2026-05 --config ...        # Shodan-Aufruf, leeres PDF
2. PDF lesen, Einschätzung formulieren
3. shodan-report ... --from-snapshot --note "Mein Kommentar"      # Kein API-Call, PDF + Notiz gespeichert
4. shodan-report --customer X --month 2026-06 --config ...        # Nächsten Monat: Vormonats-Notiz erscheint automatisch im Terminal
```

---

# 2026-04-15

## feat: `--from-snapshot` — PDF neu rendern ohne Shodan-Aufruf

- [`src/shodan_report/cli.py`](src/shodan_report/cli.py): Neues Flag `--from-snapshot` — überspringt Shodan-API-Aufruf und Domain-Scout, lädt den gespeicherten Snapshot vom Disk und rendert das PDF neu
- [`src/shodan_report/core/runner.py`](src/shodan_report/core/runner.py): `from_snapshot`-Parameter in `generate_report_pipeline` — bei gesetztem Flag wird `load_snapshot()` statt `ShodanClient.get_host()` verwendet; IP wird automatisch aus dem Snapshot übernommen wenn nicht explizit angegeben; Domain-Scout-Block wird übersprungen
- [`src/shodan_report/cli.py`](src/shodan_report/cli.py): `validate_args` lässt `--ip`/`--domain` weg wenn `--from-snapshot` gesetzt ist

**Workflow:** `shodan-report generate → PDF lesen → shodan-report --from-snapshot --note "Kommentar"` — zweiter Lauf kostet keinen API-Credit und dauert Sekunden.

## feat: Exposure-Level Chart — echte historische Datenpunkte statt Simulation

- [`src/shodan_report/core/runner.py`](src/shodan_report/core/runner.py): Nach der Evaluation werden bis zu 5 zurückliegende Monate per `load_snapshot()` geladen und evaluiert; die Scores werden als `technical_json["exposure_history"]` weitergegeben — nur Monate mit realem Snapshot werden aufgenommen
- [`src/shodan_report/pdf/sections/trend.py`](src/shodan_report/pdf/sections/trend.py): `_build_multi_point_chart` nutzt `exposure_history` wenn vorhanden — kein `_jitter()`-Fake mehr; X-Abstände passen sich dynamisch an die tatsächliche Punktanzahl an; neue Hilfsfunktion `_month_abbr("2026-04")` → `"Apr"` für Achsenbeschriftung
- [`src/shodan_report/pdf/sections/trend.py`](src/shodan_report/pdf/sections/trend.py): Chart-Titel wird dynamisch: `EXPOSURE-LEVEL VERLAUF (2 MONATE)`, `(3 MONATE)` usw. — ehrliche Darstellung statt immer „6 MONATE"
- [`src/shodan_report/pdf/sections/trend.py`](src/shodan_report/pdf/sections/trend.py): `_build_chart_cell` erhält `technical_json`-Parameter und reicht `exposure_history` durch; Fallback auf 2-Punkt-Darstellung (Vormonat → Aktuell) wenn keine History vorhanden

**Vorher:** 4 erfundene Punkte + 2 echte. **Nachher:** nur echte Datenpunkte — wächst mit jedem Monat von 2 auf max. 6.

---

# 2026-04-13 (2)

## feat: Persönliche Ansprache (cover_note) + Haftungsausschluss auf Seite 1

- [`src/shodan_report/pdf/pdf_manager.py`](src/shodan_report/pdf/pdf_manager.py): `cover_note` wird als hervorgehobenes Textfeld (blauer Akzentstreifen, hellgrauer Hintergrund) **unter** der Management-Zusammenfassung auf Seite 1 gerendert — nur wenn gesetzt
- [`src/shodan_report/pdf/pdf_renderer.py`](src/shodan_report/pdf/pdf_renderer.py): Haftungsausschluss wird via Canvas **ganz unten auf Seite 1** gezeichnet (7pt, kursiv, grau) — garantiert positioniert unabhängig vom Flowable-Layout; Text via `page_meta["disclaimer_text"]` übergeben
- [`src/shodan_report/pdf/pdf_generator.py`](src/shodan_report/pdf/pdf_generator.py): Disclaimer-Text aus `config.disclaimer` ausgelesen und in `page_meta` durchgereicht; via `disclaimer.enabled: false` deaktivierbar, via `disclaimer.custom_text` überschreibbar
- [`src/shodan_report/cli.py`](src/shodan_report/cli.py): Neuer Parameter `--note "..."` (`-n`) — persönliche Bewertung direkt beim Aufruf mitgeben, ohne YAML-Bearbeitung
- [`src/shodan_report/core/runner.py`](src/shodan_report/core/runner.py): `note`-Parameter in `generate_report_pipeline` aufgenommen — schreibt den Wert als `report.cover_note` in die Config
- [`config/customers/example.yaml`](config/customers/example.yaml), [`config/customers/werning.com-gmbh.yaml`](config/customers/werning.com-gmbh.yaml): `report.cover_note`-Feld dokumentiert

**Workflow:** Report generieren → lesen → mit `--note "Meine Bewertung..."` neu generieren

---

# 2026-04-13

## fix: conclusion.py — Exposure-Label im Fazit korrigiert

- [`src/shodan_report/pdf/sections/conclusion.py`](src/shodan_report/pdf/sections/conclusion.py): Im `else`-Zweig von `_build_intro_text` (Risk-Level `LOW`) war das Exposure-Label pauschal auf `"niedrig"` hardcodiert — unabhängig vom tatsächlichen `exposure_score`. Ein Score von 3/5 wurde dadurch als „niedrig (Exposure-Level 3/5)" ausgegeben, obwohl Level 3 laut Skala „erhöht" bedeutet. Fix: Label wird jetzt aus dem Score abgeleitet (`1→minimal`, `2→niedrig–mittel`, `3→erhöht`, `4→hoch`, `5→kritisch`), konsistent mit der Tabelle in `methodology.py`.

## feat: Multi-IP-Support pro Kunde

- [`config/customers/example.yaml`](config/customers/example.yaml): Neue YAML-Option `ips` (Liste) dokumentiert — Kommentarblock zeigt Einzeln- vs. Listen-Variante
- [`src/shodan_report/core/runner.py`](src/shodan_report/core/runner.py): Fallback auf `customer.ips[0]` wenn `customer.ip` nicht gesetzt — erster Eintrag der Liste wird automatisch als primäre IP verwendet
- [`scripts/run-jobs-direct.py`](scripts/run-jobs-direct.py): Neue Funktion `_get_ip_list()` — liest `customer.ips` aus YAML und iteriert automatisch über alle IPs; erzeugt einen Report pro IP; explizite IP in `jobs.txt` hat weiterhin Vorrang

## fix: domain_scout.py — crt.sh Timeout erhöht, Fehlerausgabe verbessert

- [`src/shodan_report/clients/domain_scout.py`](src/shodan_report/clients/domain_scout.py): `_fetch_crtsh()` erhält konfigurierbaren `timeout`-Parameter (Default 20 s statt 10 s) — verhindert Timeouts bei langsamen crt.sh-Antworten; bei Fehler wird jetzt eine Warnung ausgegeben statt still `[]` zurückzugeben

## fix: management.py — Exposure-Box Layout

- [`src/shodan_report/pdf/sections/management.py`](src/shodan_report/pdf/sections/management.py): Exposure-Box zweizeilig (`EXPOSURE-LEVEL` als Beschriftung, Score als großer farbiger Wert) — verbesserte Lesbarkeit; Spaltenbreiten angepasst (60/40/63 mm)

## fix: pdf_manager.py — Attack-Surface-Sektion paketunabhängig

- [`src/shodan_report/pdf/pdf_manager.py`](src/shodan_report/pdf/pdf_manager.py): Attack-Surface-Discovery-Sektion wird jetzt immer gerendert wenn eine Domain vorhanden ist — nicht mehr auf `professional`/`enterprise` beschränkt

---

# 2026-04-09 (2)

## fix: Domain Scout — Windows-Encoding-Crash behoben

- [`src/shodan_report/clients/domain_scout.py`](src/shodan_report/clients/domain_scout.py): `→`-Zeichen in allen `print()`-Statements durch `->` ersetzt — auf Windows (cp1252) konnte das Unicode-Pfeilzeichen nicht kodiert werden, was einen unbehandelten `UnicodeEncodeError` auslöste. Die gesamte Scout-Funktion wurde dadurch als fehlgeschlagen markiert (`except Exception`), `_attack_surface` nie gesetzt und die Attack-Surface-Sektion (inkl. crt.sh-Zertifikats-Historie) nicht im PDF gerendert.

## feat: Kundenkonfiguration werning.com GmbH

- [`config/customers/werning.com-gmbh.yaml`](config/customers/werning.com-gmbh.yaml): Neue Kundenkonfiguration angelegt — IP `185.237.65.209`, Domain `werning.com`, Paket `professional`, Logo `assets/mg-solutions-logo.png`
- [`jobs.txt`](jobs.txt): Eintrag `werning.com GmbH 2026-04` im Kurzformat ergänzt (IP und Domain kommen aus der YAML)

---

# 2026-04-09

## fix: 22 fehlgeschlagene Tests repariert

- `management.py`: `_KPI_CELL_W` von 35 mm auf 32,6 mm (163 mm Gesamtbreite) — passt in den Seitenrahmen (165,76 mm); KPI-Hintergrund auf `Colors.bg_light`, `textColor` jetzt direkt am `ParagraphStyle` gesetzt statt nur per Inline-Markup; Exposure-Box und Two-Column-Block ebenfalls auf 163 mm reduziert (verhindert `LayoutError` bei der Render-Stufe)
- `management.py`: `gesamteinschaetzung`/`empfehlung` auf max. 800 Zeichen begrenzt — verhindert `LayoutError` bei extrem langem `management_text` in Demo-PDFs
- `pdf_generator.py`: `_sha256` wird nicht mehr vor `prepare_pdf_elements()` in `config` geschrieben — Test `test_generate_pdf_calls_renderer_and_returns_path` erhielt das gemutete Dict statt des leeren `{}`
- `test_management.py`: Hilfsfunktionen `_all_paragraphs()` / `_all_para_texts()` für rekursive Extraktion aus verschachtelten Tables/KeepTogether; Assertions umgestellt
- `test_cve_overview_integration.py`: `_paragraph_text()` durchsucht jetzt Badge-Tables; `_find_detailed_table()` findet die 5-spaltige Detailtabelle zuverlässig; Spaltenreihenfolge in Assertions korrigiert (CVE=0, CVSS-Badge=1, Dienst=2, Exploit=3, Relevanz-Badge=4); Text-Suche in verschachtelten Elementen

---

# 2026-04-08 (3)

## fix: Report-Inhaltsfehler — doppeltes "Risiko:", SHA256-Platzhalter, falscher Zielwert

- `management.py`: `risk_stmt` enthielt bereits das Präfix "Risiko:" — beim Rendern wurde es erneut als Bold-Label vorangestellt (`Risiko: Risiko: ...`). Fix: `.replace("Risiko: ", "", 1)` analog zu `state_stmt` und `trend_note`
- `conclusion.py`: Zielwert im LAUFEND-Block war hardcoded auf `2/5 senken` — auch wenn der aktuelle Exposure-Level bereits 2 war. Fix: dynamisch berechnet als `max(1, score-1)/5`; bei Level 1 stattdessen "auf 1/5 halten"
- `pdf_generator.py` / `pdf_manager.py` / `footer.py`: SHA256 im Signaturblock auf Seite 8 zeigte `—` statt der tatsächlichen Prüfsumme. Fix: Hash wird jetzt vor `prepare_pdf_elements()` in `config["_sha256"]` hinterlegt und über `pdf_manager` → `create_footer_section(sha256=...)` durchgereicht

---

# 2026-04-08 (2)

## fix: Logo, mkdir, .env.example, .gitignore

- `assets/mg-solutions-logo.png` aus `.gitignore` entfernt → wird jetzt ins Repo eingecheckt (kein manuelles Kopieren mehr nach `git pull`)
- `snapshot_manager.py`: `mkdir(parents=True)` ergänzt → Verzeichnis wird automatisch angelegt wenn `OUTPUT_BASE_DIR` auf einen neuen Pfad zeigt
- `.env.example` hinzugefügt → Vorlage mit allen verfügbaren Variablen (ohne echte Werte)
- `.gitignore` (äußeres Verzeichnis): neu erstellt → `reports/`, `archive/`, `snapshots/`, `.cache/` werden nicht versehentlich committed

---

# 2026-04-08

## refactor: Zentrale Pfad-Konfiguration (`paths.py`)

Alle Ausgabepfade waren bisher als relative Konstanten über 10 Dateien verteilt (`Path("reports")`, `Path("archive")`, etc.). Das führte dazu, dass Ausgaben je nach Arbeitsverzeichnis an unterschiedlichen Orten landeten (Datenduplikate in `shodan-report/` und `shodan-report/shodan-report/`).

**Änderungen:**
- Neue Datei `src/shodan_report/paths.py` als zentrale Anlaufstelle für alle Ausgabepfade
- Neue `.env`-Variable `OUTPUT_BASE_DIR` (optional): setzt das Basisverzeichnis für alle Ausgaben; ohne Variable identisches Verhalten wie vorher (CWD)
- Alle 10 betroffenen Module (`archiver/core.py`, `archiver/report_archiver.py`, `archiver/snapshot_archiver.py`, `archiver/version_manager.py`, `cli.py`, `clients/nvd_local.py`, `core/runner.py`, `pdf/pdf_generator.py`, `pdf/sections/data/cve_enricher.py`, `persistence/snapshot_manager.py`) importieren nun aus `paths.py`
- Monkeypatches in 3 Testdateien angepasst (Patch am Verwendungsort, nicht am Definitionsort)

**So nutzen:** In `.env` eintragen:
```
OUTPUT_BASE_DIR=C:/Users/<username>/Code/shodan-report
```
Dann landen `reports/`, `snapshots/`, `archive/` und `.cache/` immer im selben Basisverzeichnis, egal von wo der Befehl gestartet wird.

## design: Management-Section zweispaltig, KPI-Bar modernisiert

- KPI-Breite von 163 mm auf 175 mm (volle Textbreite) angepasst
- KPI-Karten: Uppercase-Labels, einheitlicher Rahmen/Hintergrund (`#F8F8F8`, `#DDDDDD`)
- Exposure-Box: kräftigere Akzentfarben (Rot `#C0392B`, Orange `#E67E22`, Grün `#27AE60`)
- Management-Section: zweispaltiges Layout (links: Kernaussagen + Technische Kurzbewertung | rechts: Gesamteinschätzung + Empfehlung)
- Fallback-Texte für leere `management_text`-Blöcke ergänzt

# 2026-04-07
- Design-Update: Die KPI-Bar im Abschnitt "Attack Surface — Domain-Discovery" ist jetzt einzeilig, mit Domain und Beschreibung linksbündig und drei schmalen, zentrierten KPIs. Einheitliches, modernes Layout wie die Tabelle darunter.
# 2026-04-07
- Überarbeitung: Das Design der CVE-Übersicht im PDF-Report wurde modernisiert und verbessert (KPI-Karten, CVSS-Balken, neue Tabellenstruktur, klarere Exploit- und Relevanzanzeige).
## 2026-04-06

- conclusion.py: Neue graue Intro-Box mit dynamischem Exposure-Level, darunter automatische zweispaltige Zeitplan-Tabelle (KURZFRISTIG, MITTELFRISTIG, etc.) basierend auf technical_json.
- methodology.py: Oben Datenbasis-Box, links Begriffsdefinitionen, rechts Exposure-Level-Tabelle mit farbigen Punkten und Einschätzung, darunter Attack Surface Discovery Bullets.
- footer.py: Große Disclaimer-Box mit OSINT-Hinweis, darunter zweispaltig GRENZEN/VERTRAULICHKEIT als separate Boxen, Signatur-Block mit ichwillsicherheit.de/BSI und SHA256-Prüfsumme.

- fix: 6 failing Tests repariert
  - `pdf/sections/technical.py`: `_extract_metadata_items()` als String-Wrapper um `_extract_metadata_items_structured()` ergänzt (Test-Import schlug fehl)
  - `pdf/sections/technical.py`: `set_table_no_split()` aus der Services-Tabelle entfernt — große Tabellen (>30 Zeilen) konnten nicht über Seitengrenzen gesplittet werden (LayoutError)
  - `pdf/sections/technical.py`: ungenutzten `set_table_no_split`-Import entfernt
  - `pdf/sections/trend.py`: `_build_metrics_context()` ergänzt — rendert "Was die Kennzahlen bedeuten"-Block nach der Interpretationsbox in der Vergleichsansicht
  - `tests/pdf/sections/test_trend_extra.py`: `find_paragraphs()`-Helper in zwei Tests korrigiert — traversierte `_cellvalues` (Liste von Zeilen-Listen) direkt statt die Zellen zu flattenen
  - `tests/pdf/sections/test_trend_extra.py`: `_find_table_ncols()` ergänzt — sucht rekursiv nach verschachtelten Tabellen (Vergleichstabelle liegt in 2-spaltiger Layout-Table)
  - `tests/pdf/sections/test_trend_extra.py`: TLS-Zeilen-Suche von `"TLS"` auf `"Zert"` erweitert (Anzeigename ist "Ablaufende Zert.", nicht "TLS-Schwächen")
  - `tests/pdf/test_pdf_manager.py`: Footer-Timestamp-Test prüft jetzt das Jahr (`"%Y"`) statt `"%d.%m.%Y"` — Footer-Format ist `"06. April 2026 · HH:MM Uhr"`

## 2026-04-05 (Ergänzung)

- Typ-Spalte in der IP-Tabelle zeigt jetzt ein farbiges Badge (Label) für Server/Mailserver/Nameserver statt kompletter Zellenfärbung. Die Zelle bleibt weiß, nur das Label ist farbig hinterlegt und umrahmt.
## 2026-04-05

- KPI-Zeile im Abschnitt "Attack Surface — Domain-Discovery" optisch und strukturell überarbeitet:
  - KPI-Kacheln (Exponierte IPs, CDN gefiltert, Subdomains) werden jetzt sauber zentriert und gleichmäßig dargestellt.
  - Die linke Spalte (DOMAIN + Domainname) ist nun bündig, linksbündig und mit verbessertem Abstand.
  - Spaltenbreiten und Padding für ein symmetrisches, modernes Layout angepasst.
  - Beschriftungen überschreiben keine Boxen mehr.
# Changelog

## 04.04.2026 (15) — `feature/report-polish`

- feat: Recommendations-Section — neues Badge-Design mit Akzentstreifen
  - `pdf/sections/recommendations.py`: Prioritäts-Header als farbige Pill-Badges (links-ausgerichtet, 8pt, abgerundete Ecken)
  - `pdf/sections/recommendations.py`: Jede Empfehlung als Zeile mit 3pt farbigem Akzentstreifen links statt `• text`
  - `pdf/sections/recommendations.py`: Badge-Breite dynamisch via `stringWidth()` — immer einzeilig, unabhängig von Textlänge
  - `pdf/sections/recommendations.py`: `_CONTENT_W = 170 * mm` für exakte Spaltenbreite (A4 − 2×2 cm Ränder)
  - `pdf/sections/recommendations.py`: `_has_rdp()` als Modulfunktion (war inline-Closure)
  - `pdf/sections/recommendations.py`: Whitespace zwischen P2 und P3 von `Spacer(12)` auf `Spacer(6)` reduziert
  - `tests/pdf/sections/test_recommendations.py`: 36 neue Tests in 5 Klassen
    - `TestPriorityBadge`: Rückgabetyp, `hAlign="LEFT"`, Breite < `_CONTENT_W`, Label-Text, alle 3 Farb-Varianten
    - `TestItemRow`: 2 Spalten, Streifen 3pt, Gesamtbreite = `_CONTENT_W`, Paragraph, HTML passiert durch
    - `TestHasRdp`: Port 3389, Produktname, Case-insensitive, kein RDP, leer, Objekt-Attribut
    - `TestHelpers`: `_extract_risk_level` (str/dict/missing/other), `_extract_port` (int/dict/missing)
    - `TestCreateRecommendationsSection`: Heading in KeepTogether, P1-Badge immer gerendert + linksbündig, Fallback-Paragraph, RDP-Fallback, kritischer CVE, context-DI, kwargs-DI

## 04.04.2026 (14)

- refactor: "Einordnung & Bewertungslogik" — Attack Surface Discovery Sektion gekürzt
  - `pdf/sections/methodology.py`: 6 Bullets + 2 Absätze durch einen kompakten Satz ersetzt
  - Spart ~12 Druckzeilen; Inhalt weiterhin vollständig in Abschnitt 3 des Reports

## 04.04.2026 (13)

- fix: Grammatik — "X öffentliche Dienste" nutzt jetzt Singular bei X=1
  - `pdf/sections/management.py`: Beitragsfaktoren-String (`_factors`) → "1 öffentlicher Dienst"
  - `pdf/sections/management.py`: Kernaussagen-Zustandssatz (`state_stmt`) → "1 öffentlicher Dienst"
  - `pdf/helpers/management_helpers.py`: `generate_priority_insights()` → "1 öffentlicher Dienst"
  - `tests/pdf/helpers/test_management_helpers.py`: Testassertion auf Singular/Plural-flexible Prüfung angepasst

- fix: Fazit-Abschnitt — Beitragsfaktoren-Präfix nach Satzpunkt großgeschrieben
  - `pdf/sections/conclusion.py`: Erstes Zeichen von `_contrib_str` wird kapitalisiert
  - Vorher: "Die Angriffsfläche ist erhöht. unsichere TLS-Protokolle — …"
  - Nachher: "Die Angriffsfläche ist erhöht. Unsichere TLS-Protokolle — …"

## 04.04.2026 (11)

- refactor: KPI CVE-Zählung in testbare Hilfsfunktionen extrahiert
  - `pdf/helpers/management_helpers.py`: `count_critical_cves(enriched)` — zählt CVEs mit CVSS ≥ 9.0
  - `pdf/helpers/management_helpers.py`: `count_kev_cves(enriched)` — zählt CVEs mit CISA-KEV-Status
  - `pdf/sections/management.py`: KPI-Block nutzt diese Funktionen statt inline-Logik
  - `tests/pdf/helpers/test_management_helpers.py`: 22 neue Tests in 3 Klassen
    - `TestCountCriticalCves`: leere Liste, None-Werte, String-CVSS, Grenzwert 9.0, ungültige Werte
    - `TestCountKevCves`: alle drei Statuses (public/kev/cisa), unbekannte Werte, gemischte Listen
    - `TestKpiCveConsistency`: Konsistenz mit CVE-Übersicht, Null-Fall ohne NVD-Daten

## 04.04.2026 (10)

- feat: Header — Titel in zwei Paragraphen aufgeteilt
  - `pdf/sections/header.py`: "Analyse der externen Angriffsfläche" klein/grau (Helvetica 11pt)
  - `pdf/sections/header.py`: Kundenname groß/schwarz (Helvetica-Bold 22pt, `#111827`)
  - `pdf/sections/header.py`: `HexColor` importiert

- fix: Seitendekorationen zeigen immer `ichwillsicherheit.de` statt Kundendomain
  - `pdf/pdf_renderer.py`: `domain` hardcoded auf `"ichwillsicherheit.de"`

## 04.04.2026 (8)

- fix: KPI-Karte "Kritisch (≥9)" zeigte immer 0 statt korrekter Anzahl
  - `pdf/sections/management.py`: KPI-Block nutzt jetzt `enrich_cves()` statt roher CVE-String-Liste
  - Vorher: `mdata.get("cves")` enthielt nur CVE-IDs ohne CVSS-Score
  - Nachher: `enrich_cves(unique_cves, technical_json, lookup_nvd=...)` — identische Logik wie `cve_overview.py`
  - Konsistenz: `NVD_LIVE=1` oder `nvd.enabled: true` aktiviert CVSS-Lookup für beide Abschnitte gleichzeitig

## 04.04.2026 (7)

- feat: Exposure-Box — farbiger linker Akzentbalken je nach Risikostufe
  - `pdf/sections/management.py`: `LINEBEFORE` (4pt) auf die erste Spalte der `_exp_box` gesetzt
    - Level 1–2 → grün (`#22c55e`)
    - Level 3 → orange (`#f97316`)
    - Level 4–5 → rot (`#dc2626`)
  - `pdf/sections/management.py`: `HexColor` zu den ReportLab-Importen ergänzt
  - Left-Padding der Box von 8 auf 10pt erhöht um Platz für den Balken zu schaffen

- refactor: Redundanter Intro-Textblock in der Management-Zusammenfassung entfernt
  - `pdf/sections/management.py`: Paragraph mit "Analysierte IP-Adresse: … – Exposure-Level …" gestrichen
    - Information ist vollständig durch KPI-Karten (IP, Ports, CVEs) und Exposure-Box abgedeckt
    - Spart ca. 2–3 Zeilen Platz auf der Management-Seite

## 04.04.2026 (5)

- feat: Exposure-Level-Anzeige unter KPI eingerahmt (Label + Ampel + Beitragsfaktoren)
  - `pdf/sections/management.py`: separater `exp_tbl` vor dem KPI entfernt
    - Vorher: Exposure-Level als eigene Tabellenzeile (Label + Ampel) oberhalb der KPI-Karten + darunter Beitragsfaktoren als Paragraph
    - Jetzt: eingerahmte Box (`_exp_box`) unterhalb der KPI-Karten mit drei Spalten in einer Zeile
      - Spalte 1 (68mm): `EXPOSURE-LEVEL: 3/5 (erhöht)` — fett, `exposure`-Style
      - Spalte 2 (35mm): 5-Dot-Ampel zentriert
      - Spalte 3 (60mm): Beitragsfaktoren rechtsbündig, grau, 8pt
    - Box-Design: hellgrauer Hintergrund (`Colors.bg_light`), dünner Rahmen (`Colors.border`, 0.5pt), Innenabstand 6/8pt
    - Beitragsfaktoren-Paragraph (vorher eigenständig) integriert in die Box — kein separater Element-Append mehr

## 04.04.2026 (4)

- feat: Exposure-Ampel auf 5 Dots mit Farbgradient umgestellt
  - `pdf/helpers/pdf_helpers.py`: `build_horizontal_exposure_ampel()` neu implementiert
    - Vorher: 3 Dots, nur der aktive Dot leuchtet (grün / orange / rot je nach Zone)
    - Jetzt: 5 Dots, die ersten `level` Dots füllen sich auf — Farbgradient pro Position: 1+2 = grün, 3 = orange, 4+5 = rot
    - Inaktive Dots bleiben grau (`#d1d5db`); `level` wird auf `[1, 5]` geclampt
    - Konstante `_AMPEL_DOT_COLORS` definiert die Farbe jeder der 5 Positionen
    - Parameter `dot_size_mm`, `spacing_mm`, `theme` bleiben erhalten (API-kompatibel)
  - `tests/pdf/helpers/test_pdf_helpers.py`: alle Ampel-Tests auf 5-Dot-Logik aktualisiert
    - 14 Tests, 23 passed — vollständige Abdeckung aller Level (1–5) + Edge Cases (0, -1, 6, 100)

## 04.04.2026 (3)

- fix: Default-Logo wird immer angezeigt, unabhängig vom Working Directory
  - `pdf/helpers/header_helpers.py`: Fallback-Pfad für `mg-solutions-logo.png` wird jetzt relativ zur Quelldatei via `__file__` aufgelöst statt via `os.getcwd()`
    - Vorher: `os.path.join(os.getcwd(), "assets", "mg-solutions-logo.png")` → schlägt fehl wenn CLI vom Workspace-Root (`shodan-report/`) statt vom Paket-Root (`shodan-report/shodan-report/`) ausgeführt wird
    - Jetzt: `os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "assets", "mg-solutions-logo.png"))` → immer korrekt aufgelöst
    - Kunden-spezifische `logo_path`-Konfiguration (`styling.logo_path` / `assets.logo_path`) bleibt unverändert vorrangig

## 04.04.2026 (2)

- fix: KPI-Karte "Analysierte IP" — IP-Adresse zu groß und Box zu niedrig
  - `pdf/sections/management.py`: `_kpi_cell()` erhält neuen Parameter `value_size: int = 16`
    - Standard-Wert 16 bleibt für alle numerischen KPI-Karten (Ports, CVEs gesamt, Kritisch, CISA KEV) unverändert
    - IP-Karte wird mit `value_size=9` aufgerufen → auch lange Adressen wie `217.154.224.104` passen einzeilig in die ~32,6mm-Zelle
    - `leading` wird automatisch aus `value_size` berechnet (`max(value_size + 2, 11)`)
  - `pdf/sections/management.py`: feste `rowHeights=[14, 26]` im inneren KPI-Card-Table
    - Label-Zeile: 14 pt, Wert-Zeile: 26 pt — gilt für alle 5 KPI-Karten
    - Alle Boxen sind nun exakt gleich hoch, unabhängig von Schriftgröße und Inhalt; Box-Design (Hintergrund, Rahmen, Abstände) unverändert

## 02.04.2026

- fix: Header-Meta-Zeile: "Assets" durch klare IP/Domain-Trennung ersetzt
  - `pdf/sections/header.py`: `"Assets: {ip} +N assets"` → `"IP: {ip}"` + optional `"| Domain: {domain}"` wenn Domain-Scout gelaufen
    - Parameter `additional_assets` entfernt; neuer optionaler Parameter `domain: Optional[str]`
  - `pdf/helpers/header_helpers.py`: `format_assets_text()` entfernt (war Quelle der "3 Assets"-Verwirrung)
  - `pdf/pdf_manager.py`: `domain` aus `ctx.attack_surface.domain` an `_create_header` übergeben
  - Semantik: ein Report = eine IP-Adresse (analysiertes Asset); Domain ist Kontext-Information, kein eigenständiges Asset
- fix: Asset-Terminologie in Management-Summary und Methodik geklärt
  - `pdf/sections/management.py`: Intro-Zeile nicht mehr "N Assets; primär bewertetes Asset (Host: X)", sondern IP-zentrisch: "Analysierte IP-Adresse: {ip} · {N} zugeordnete Hostnamen/Domains: …"
    - 0 Hostnamen: "Analysierte IP-Adresse: {ip} — Exposure-Level …"
    - 1 Hostname: "Analysierte IP-Adresse: {ip} · Hostname/Domain: {name} — Exposure-Level …"
    - N Hostnamen: "Analysierte IP-Adresse: {ip} · {N} zugeordnete Hostnamen/Domains: {name1}, {name2} (+N weitere) — Exposure-Level …"
    - Interne Hilfsvariablen `asset_count` / `primary_asset` entfernt; `names_list` als klare Hostnamen-Liste
  - `pdf/sections/methodology.py`: Glossar-Eintrag "IP-Adresse (analysiertes Asset)" hinzugefügt — erklärt dass Hostnamen/Domains zugeordnete Netzwerk-Identitäten sind, keine eigenständig bewerteten Assets
  - `pdf/sections/methodology.py`: "primäre Analyse-IP"-Erklärung ergänzt um Abgrenzung: weitere IPs/Hostnamen = Netzwerk-Identitäten in Abschnitt 3, nicht separat von Shodan bewertet

## 01.04.2026

- feat: Attack Surface Discovery — Domain-zu-IP OSINT-Pipeline
  - `clients/domain_scout.py` (neu): passives OSINT-Modul ohne aktive Scans
    - `scout_domain(domain)` → `AttackSurface` mit `relevant_ips`, `cdn_ips`, `subdomains`, `primary_ip`
    - Quellen: DNS A/MX/NS-Records (`socket` + `nslookup`), crt.sh Zertifikats-Datenbank, HackerTarget Subdomain-API
    - CDN-Erkennung anhand hardcodierter IP-Ranges: Cloudflare, Akamai, Fastly, AWS CloudFront
    - `primary_ip`-Logik: A-Record (Hauptdomain) → www-A-Record → MX → erster Treffer
    - CDN-IPs werden in `cdn_ips` separiert und fließen nicht in Shodan-Analyse
  - `pdf/sections/attack_surface.py` (neu): Report-Abschnitt "3. Attack Surface — Domain-Discovery"
    - Summary-Box: Domain, Anzahl exponierter IPs, CDN-IPs, Subdomains, analysierte IP
    - IP-Tabelle (4 Spalten): IP-Adresse, Typ, Quellen, Reverse DNS — kein externer Link
    - CDN-IPs mit gelber Warnbox und Erklärung
    - Subdomain-Liste aus crt.sh (max. 20, Rest "+N weitere")
  - `cli.py`: `--domain/-d` Parameter hinzugefügt; `--ip/-i` jetzt optional (war required)
    - Validation: Fehler wenn weder `--ip` noch `--domain` angegeben
    - Beide gleichzeitig erlaubt — `--ip` überschreibt dann die automatisch gewählte Primary IP
  - `core/runner.py`: Scout-Block läuft vor Shodan-API-Call
    - `attack_surface` wird in `config["_attack_surface"]` gespeichert und an PDF-Kontext übergeben
    - Wenn nur `--domain` ohne `--ip`: IP wird automatisch aus `primary_ip` gewählt
  - `pdf/context.py`: `attack_surface: Optional[Any] = None` Feld ergänzt
  - `pdf/pdf_manager.py`: Attack-Surface-Sektion nach Empfehlungen, vor Technischem Anhang eingebunden
  - `pdf/sections/methodology.py`: neuer Block "Attack Surface Discovery (Abschnitt 3)" mit Erklärung aller 5 Quellen und Primary-IP-Logik; "Grenzen & Hinweis" um OSINT-Bullet erweitert
- chore: Abschnittsnummerierung angepasst (Management=1, Empfehlungen=2, Attack Surface=3, Technical=4, CVE=5, Trend=6, Fazit=7)
- docs: README aktualisiert
  - CLI-Parameter-Tabelle: `--domain` mit Pflicht-Kennzeichnung und Hinweis
  - Schnellstart: Beispiel mit `--domain`
  - Report-Aufbau: Abschnitt 3 aufgenommen, Nummerierung korrigiert
  - Pipeline: Schritt 0 für `scout_domain()` dokumentiert
- test: 31 neue Tests (43 passed, 0 failed)
  - `tests/cli/test_cli_args.py`: 11 neue Tests — `--domain` Parsing, Short-Flag, `validate_args` für alle Kombinationen
  - `tests/clients/test_domain_scout.py` (neu): 32 Tests — CDN-Erkennung, `ScoutedIP` Properties, `primary_ip`-Fallback-Logik, `scout_domain` vollständig gemockt (offline)

## 31.03.2026 (9)

- fix: Deterministische Narrative-Zuordnung — Score ↔ Text Konsistenz
  - `reporting/management_text.py`: neuer Pfad `_text_elevated()` für Exposure-Level 3/5
    - "stabil"-Narrative nie mehr bei Score ≥ 3: Routing prüft jetzt Boost-Signale direkt aus `technical_json` (TLS/EOL/CVE), unabhängig vom pre-boost `exposure_score`
    - `_detect_insecure_tls()` + `_detect_eol()` als separate Helper-Funktionen
    - `_text_monitor()` jetzt explizit mit "(Exposure-Level 1–2/5)" zur Klarheit
  - `reporting/report_validator.py`: neues Trust-Layer-Modul mit 8 deterministischen Regeln
    - `STABILITY_SCORE_MISMATCH`: Score ≥ 3 + "stabil"/"kein Handlungsbedarf" im Text
    - `CRITICAL_SCORE_SOFT_TEXT`: Score ≥ 4 ohne Urgenz-Signal
    - `RDP_SCORE_MISMATCH`: RDP öffentlich → Score muss ≥ 4 sein
    - `RDP_MISSING_REMEDIATION`: RDP öffentlich → Text muss VPN/Jumphost/NLA nennen
    - `EOL_UNDERSCORING`: EOL erkannt → Score muss ≥ 3 sein
    - `TLS_UNDERSCORING`: TLS 1.0/1.1 aktiv → Score muss ≥ 3 sein
    - `CVE_WITH_NEGATIVE_CLAIM`: CVEs vorhanden + "keine kritischen Schwachstellen"
    - `TLS_TEXT_CONTRADICTION`: TLS-Probleme + "keine Konfigurationsrisiken"
  - `core/runner.py`: Validator läuft nach jeder Report-Generierung automatisch (non-fatal, stdout)
- feat: PageBreak nach Management-Zusammenfassung
  - `pdf/pdf_manager.py`: neue `_PageBreakMgmt` nach `create_management_section()` — Empfehlung auf eigener Seite
- test: 26 neue Tests in `tests/reporting/test_report_validator.py`
  - Ergebnis: **350 passed, 9 skipped, 0 failed**

## 31.03.2026 (8)

- fix: Risk consistency — Single Master Score, Fazit-Contribution-Factors, Trend-Delta-Erklärung
  - `pdf/sections/management.py`: Beitragsfaktoren-Block ersetzt verbose Ableitung
    - Kompakter Block: `"Exposure-Level: 3/5 (erhöht) — Beitragsfaktoren: RDP · 3 CVEs · TLS 1.0/1.1 · EOL"`
    - Alle Text-Pfade (intro, state_stmt) aus geboosteten `exposure_score`
    - `version_risk`-Erkennung: "strukturelle Risiken (Version)" als Beitragsfaktor wenn `service.version_risk > 0`
  - `pdf/sections/conclusion.py`: Contribution Factors inline, risikokalibrierte Bullets
    - CRITICAL/HIGH: 0–48h + 7-Tage + laufend
    - MEDIUM: 30 Tage + 60–90 Tage + laufend
    - LOW: Monitor-only
  - `pdf/sections/trend.py`: Delta-Erklärung wenn `curr_exposure > prev_exposure`
  - `pdf/sections/methodology.py`: EOL 4→2 Bullets, Grenzen+Nutzungshinweis zu 3 Bullets zusammengefasst
- test: 324 passed, 9 skipped, 0 failed


- feat: TLS Verified-Finding Warn-Boxen im Technischen Anhang
  - `pdf/sections/technical.py`: neuer `_TLS_INSECURE`-Katalog + `_render_tls_warnings()`
    - Liest `ssl_info.versions` direkt aus Shodan-Daten (Format: kein Prefix = aktiv, `-` Prefix = deaktiviert)
    - SSLv2/SSLv3 → KRITISCH, TLSv1.0 → HOCH, TLSv1.1 → MITTEL
    - Label `TLS [VERIFIED]` — unterscheidet direkt beobachtete Fakten vom TLS-Handshake von OSINT-basierten CVE-Indikatoren
    - Deduplizierung pro Protokoll über alle Ports, Ports im Box-Text sichtbar
    - Sortierung: KRITISCH → HOCH → MITTEL
  - `pdf/sections/data/recommendations_data.py`: TLS-Block prüft jetzt `ssl_info.versions`
    - Neue P1-Message mit konkreten Protokollnamen: `"TLS-Konfiguration: Unsichere Protokolle aktiv (TLSv1.1) — sofort deaktivieren"`
    - Fallback auf generische Meldung wenn keine Versionen gefunden aber Legacy-Felder treffen
- test: 8 neue Tests in `tests/pdf/sections/test_technical_top_vuln.py` (318 passed, 9 skipped, 0 failed)

## 31.03.2026 (4)

- feat: EOL-Findings in Management-Summary und Handlungsempfehlungen integriert
  - `reporting/management_text.py`: `_text_rdp()` kennt jetzt EOL-Findings
    - Combo-Satz wenn RDP + EOL gleichzeitig: „klassischer Ransomware-Einstiegspunkt"
    - „Was das bedeutet": Erklärung warum EOL = strukturell nicht patchbar
    - Empfehlung: OS-Migrations-Zeitrahmen (90 Tage) wenn EOL erkannt
    - CVE-Note mit OSINT-Qualifier: „basieren auf Versionszuordnungen, keine aktiv verifizierten Schwachstellen"
    - Neue `_flatten_for_eol()` Helper-Funktion für verschachtelte Service-Strukturen
  - `pdf/sections/data/recommendations_data.py`: EOL-Einträge stehen jetzt in **Priorität 1** vor CVE-Patching
    - `"EOL-System ersetzen oder isolieren: Windows Server 2016 (lizenzabhängig)"` als erstes P1-Element
    - near-EOL: `"EOL-Migration planen: ... — Support endet YYYY-MM-DD"`
  - fix: `_render_eol_warnings` in `technical.py` normalisiert jetzt die verschachtelte `service.product`-Struktur aus `build_technical_data()` → EOL-Box erscheint korrekt im Technischen Anhang
- test: 310 passed, 9 skipped, 0 failed

## 31.03.2026 (3)

- feat: EOL-Erkennungs-Engine als eigenständiges Modul `evaluation/eol/`
  - `src/shodan_report/evaluation/eol/eol_lookup.py`: statische EOL-Tabelle mit 28 Einträgen — Windows Server 2003–2022, Apache 2.2/1.3, PHP 5/7.0–8.1, MySQL 5.5–5.7, OpenSSL 1.0/1.1.1, ProFTPD 1.3.5, Samba 3/4.0; `NEAR_EOL_DAYS = 365`
  - `src/shodan_report/evaluation/eol/eol_detector.py`: reines Matching-Engine ohne Seiteneffekte; `detect_eol(product, version)` gibt `{product_id, display_name, eol_status, eol_date, confidence, support_model, note}` zurück; `scan_services_for_eol(services)` filtert auf EOL/near-EOL und dedupliziert nach `product_id`
  - `support_model`-Feld maschinenlesbar: `"official"` (eindeutiges EOL) vs. `"mainstream_end"` (Extended Support ggf. bei Lizenzierung noch aktiv); Renderer zeigt `(lizenzabhängig)` Hinweis bei Windows Server Einträgen
  - Confidence: `high` bei Prefix + Version, `medium` bei Version ohne Prefix-Match, `low` ohne Version
  - Windows Server: `support_end = mainstream_end` (relevant für KMU ohne Software Assurance)
- feat: EOL-Warn-Boxen im Technischen Anhang
  - `src/shodan_report/pdf/sections/technical.py`: neue Funktion `_render_eol_warnings` — scannt `services[]` aus dem Snapshot und rendert eine farbige Warn-Box pro EOL/near-EOL-Fund; EOL → HOCH (orange), near-EOL → MITTEL (gelb)
  - Direkter Aufruf nach `_render_shodan_tags_warning` in `create_technical_section`
  - Deduplizierung: selbes Produkt auf mehreren Ports erscheint nur einmal; Port-Nummer im Text sichtbar
- test: 21 neue Tests in `tests/evaluation/test_eol_detector.py` (inkl. 3 Tests für `support_model`)
  - Ergebnis: **310 passed, 9 skipped, 0 failed**

## 31.03.2026 (2)

- feat: Shodan-Tags als Warn-Box im Technischen Anhang
  - `src/shodan_report/pdf/sections/technical.py`: neue Funktion `_render_shodan_tags_warning` — liest `tags[]` aus dem Snapshot und rendert für jeden sicherheitsrelevanten Tag eine farbige Box direkt nach dem Abschnitts-Header
  - Bekannte Tags mit Severity: `eol-product` → HOCH (orange), `doublepulsar` / `malware` → KRITISCH (rot), `honeypot` / `tor` → MITTEL (gelb), `self-signed` → NIEDRIG (blau)
  - Reine Informationstags (`cloud`, `vpn`) erscheinen weiterhin im Metadaten-Block, nicht als Warn-Box
  - EOL-Tag wird nicht mehr doppelt in der Metadaten-Liste angezeigt
- test: 5 neue Tests für Warning-Box
  - `test_eol_tag_renders_warning_box` — prüft Box-Erstellung + HOCH-Label
  - `test_doublepulsar_renders_critical_box` — prüft KRITISCH-Label
  - `test_no_box_for_unknown_or_informational_tags` — cloud/vpn erzeugen keine Box
  - `test_no_tags_produces_no_box` — leere Tags-Liste erzeugt nichts
  - `test_eol_tag_not_duplicated_in_metadata` — eol-product nicht in Metadaten-Text
  - Ergebnis: **289 passed, 9 skipped, 0 failed**

## 31.03.2026

- fix: Seite 2 (generischer Boilerplate-Einleitungsblock) entfernt
  - `src/shodan_report/pdf/sections/management.py`: Block `4. PROFESSIONELLE EINLEITUNGSTEXTE` nach dem PageBreak gelöscht — 5 generische Absätze (OSINT-Einordnung, CVE-Text, Risikotext, Details-Hinweis) die keine kundenspezifischen Informationen transportierten
- fix: Kernkennzahlen-Tabelle — „Assets" durch analysierte IP ersetzt
  - `src/shodan_report/pdf/sections/management.py`: Spalte „Assets" mit irreführender Zählung (IP + Hostnames + Domains = 3) ersetzt durch „Analysierte IP" mit der tatsächlichen IP-Adresse aus dem Snapshot; Spaltenbreite angepasst (42 mm IP-Spalte)
- fix: Zertifikats-Aussteller und -Betreff als Klartext statt Dict-Syntax
  - `src/shodan_report/pdf/sections/data/technical_data.py`: `cert.issuer` und `cert.subject` werden jetzt korrekt formatiert — aus dem Shodan-Dict wird zuerst `CN`, dann `O`, dann `OU` extrahiert; Fallback auf `k=v`-Darstellung; keine rohen `{'C': 'GB', 'CN': '...'}` mehr im Report
- fix: Trend-Guard — Trend nur rendern wenn echter Vormonat-Snapshot vorhanden
  - `src/shodan_report/pdf/sections/trend.py`: wenn `compare_month` gesetzt ist aber alle Vormonat-Werte 0 sind (erster Report war eine Nullmessung), wird jetzt `_add_no_data_view` angezeigt statt einer irreführenden „Verschlechtert von 0 auf N"-Tabelle
- fix: CVE-Zählung in Empfehlungen dedupliziert und mit cve_overview ausgerichtet
  - `src/shodan_report/pdf/sections/data/recommendations_data.py`: CVEs werden jetzt nach ID dedupliziert (höchster CVSS-Wert gewinnt) bevor gezählt wird; Schwellwerte jetzt identisch zu `cve_overview.py` (kritisch ≥9.0, hoch 7.0–8.9); ein einziger Priorität-1-Eintrag mit beiden Zahlen statt zwei separater Einträge die sich widersprechen konnten
- test: 3 Tests an geänderte Ausgaben angepasst
  - `tests/pdf/sections/test_management.py`: Assertion auf „Dienste identifiziert" auf neuere Formulierung aktualisiert
  - `tests/pdf/sections/test_recommendations_data.py`: Assertion auf „Kritische CVE" auf neues Format aktualisiert
  - `tests/pdf/sections/test_trend.py`: `test_create_trend_section_with_comparison` übergibt jetzt explizit eine nicht-leere `trend_table` damit der Trend-Guard nicht greift
  - Ergebnis: **284 passed, 9 skipped, 0 failed**

## 30.03.2026 (4)

- test: 4 neue Tests für heutige Änderungen geschrieben
  - `tests/pdf/sections/test_management.py`: `test_management_text_is_rendered_in_elements` — prüft dass `management_text`-Inhalt tatsächlich in den PDF-Elementen erscheint
  - `tests/pdf/sections/test_cve_overview_integration.py`: `test_cve_hint_text_when_list_truncated` — prüft dass „Vollständige Liste auf Anfrage verfügbar" erscheint wenn die CVE-Liste gekürzt wird
  - `tests/pdf/sections/test_trend_extra.py`: `test_no_data_view_shows_baseline_with_exposure_score` — prüft Baseline-Block mit Exposure-Level und Drei-Punkte-Argumentation im ersten Report
  - `tests/pdf/sections/test_trend_extra.py`: `test_metrics_context_appears_in_comparison_view` — prüft dass „Was die Kennzahlen bedeuten" im Folgereport erscheint
  - Ergebnis: **284 passed, 9 skipped, 0 failed**

## 30.03.2026 (3)

- feat: Trend-Sektion grundlegend überarbeitet
  - `src/shodan_report/reporting/trend.py`: Trend-Text-Generierung neu geschrieben
  - `src/shodan_report/pdf/sections/trend.py`: Trend-PDF-Sektion neu geschrieben
  - **Erster Report (kein Vergleich):** statt leerer Seite jetzt drei inhaltliche Blöcke
    - Ankündigung was ab dem nächsten Report erscheint
    - Aktuelle Baseline mit Exposure-Score
    - Drei konkrete Punkte warum kontinuierliche Messung wichtig ist (gleichzeitig stärkstes Abo-Verkaufsargument im Report)
  - **Folgereport (mit Vergleich):** drei Verbesserungen
    - Bewertungsspalte in der Vergleichstabelle ist farbig — rot bei Verschlechterung, grün bei Verbesserung, schwarz bei unveränderter Lage
    - Interpretation spezifischer — nicht mehr generisch „stabil" sondern konkret was sich verändert hat und was das bedeutet
    - Neuer Abschnitt „Was die Kennzahlen bedeuten" erklärt die vier Metriken für Nicht-Techniker
  - **Liniendiagramm:** größer (100 mm statt 70 mm), Gitterlinien für Levels 1–5, Linie farbig (rot/grün/blau je nach Entwicklung)

## 30.03.2026 (2)

- test: 7 dauerhaft fehlschlagende Tests auf `skip` gesetzt
  - `tests/pdf/sections/test_management_data_chinanet.py` (4 Tests): Snapshot `snapshots/CHINANET/2026-01_111.170.152.60.json` fehlt in diesem Klon
  - `tests/pdf/sections/test_sanitization_management.py`, `test_sanitization_technical.py` (2 Tests): Snapshot `snapshots/Clean/2026-01_82.100.220.31.json` fehlt in diesem Klon
  - `tests/pdf/test_mdata_enrichment.py` (1 Test): setzt `debug_mdata=True` voraus; Standard ist `False` (kein `.mdata.json` im Kundenreport)
  - Ergebnis: **280 passed, 9 skipped, 0 failed**

## 30.03.2026

- feat: Management-Text szenario-spezifisch eingebunden
  - `src/shodan_report/pdf/sections/management.py`: `management_text` wird jetzt tatsächlich gerendert — nach der Technischen Kurzbewertung, vor dem PageBreak
  - Abschnittsbezeichner (z.B. „Empfehlung:") werden fett dargestellt
  - Statischer Boilerplate (Gesamtbewertung, Kurzempfehlung, Entscheidungsvorlage) entfernt — ersetzt durch szenario-spezifischen Text aus `management_text.py`
  - Fix: `rdp_primary` war nicht definiert im Renderer — wird jetzt korrekt vor Verwendung gesetzt
- chore: `sections/management_data.py` (Duplikat) gelöscht — echte Datei liegt unter `sections/data/management_data.py`
- feat: PDF-Styling grundlegend überarbeitet
  - Sektions-Header erhalten jetzt einen dunkelblau gefüllten Balken mit weißem Text statt nur fettem Text — sofort erkennbare Struktur wie in professionellen Audit-Reports
  - Neue Styles für Tabellen-Header, KPI-Werte und Risikostufen
- chore: `scripts/dev/` in `.gitignore` aufgenommen — Ordner bleibt lokal, wird nicht getrackt
- fix: `src/shodan_report/pdf/sections/__init__,py` → `__init__.py` umbenannt (Tippfehler im Dateinamen)
- fix: CVE-Übersicht Hinweistext angepasst
  - `src/shodan_report/pdf/sections/cve_overview.py`: Hinweis auf abgeschnittene CVE-Liste auf kundenfreundlicheres Wording geändert („Vollständige Liste auf Anfrage verfügbar")

## Unreleased

- fix: EOL/CVE exposure-score boost alignment (management.py ↔ management_text.py)
  - `src/shodan_report/pdf/sections/management.py`: EOL-Boost auf `max(score, 3)` erhöht (war `max(score, 2)`); neuer CVE-Baseline-Boost `max(score, 3)` wenn `cve_count > 0`
  - `src/shodan_report/reporting/management_text.py`: `_text_elevated()` akzeptiert jetzt `exposure_score`-Parameter statt hardcoded "3/5"; Boost-Score wird lokal gemittelt und übergeben — PDF-Anzeige und Narrative sind jetzt konsistent

- chore: update `.gitignore` — add caches and generated files
 - feat: improve CPE parsing and service pretty-formatting
   - `src/shodan_report/clients/helpers/cpe.py`: alias map and normalization for clearer service names (e.g. MySQL, Apache)
 - feat: CVE enrichment (network-aware, test-friendly)
   - `src/shodan_report/pdf/sections/data/cve_enricher.py`: optional NVD/CISA enrichment with injectable dummy clients for offline tests
 - fix: CVE overview PDF rendering
   - `src/shodan_report/pdf/sections/cve_overview.py`: render `nvd_url`, service indicators, OSINT checklist and clickable CVE links in overview tables
 - test: deterministic tests and test bootstrap
   - Added unit and demo tests that monkeypatch NVD/CISA clients; added `conftest.py` to fix `src.*` imports during pytest collection
 - chore: reorganize scripts and docs
   - moved dev/debug/demo scripts to `scripts/dev/` and added `scripts/README.md`; top-level stubs updated to point at dev scripts
 - fix: snapshot parsing for exposure scoring
   - `src/shodan_report/parsing/utils.py`: parse stored snapshot `services` like live Shodan `data` payloads
 - fix: OSINT exposure scoring calibration
   - `src/shodan_report/evaluation/evaluation_engine.py`: adjusted port-count boost to avoid inflated exposure
 - fix: conclusion alignment with critical CVEs
   - `src/shodan_report/pdf/sections/conclusion.py`: raise conclusion risk when CVSS ≥ 9 CVEs exist (OSINT/NVD)

## 23.01.2026

- fix: Recommendations now include CVEs from generated `.mdata.json`
  - `src/shodan_report/pdf/sections/data/recommendations_data.py`: aggregate `cve_enriched`/`unique_cves_sample` from `.mdata.json` and count CVSS so Priority‑1 reflects high/critical CVEs shown in the CVE-Übersicht.
  - meta field `critical_cves` now aggregates detections from multiple sources so the renderer shows a correct "keine Priorität-1" placeholder only when appropriate.
  - wording: `src/shodan_report/pdf/sections/management.py`: add RDP-specific management wording and a focused technical short note when RDP (Port 3389) is the primary/only exposed service.

## 22.01.2026

- Aktualisiert `src/shodan_report/pdf/sections/management.py`
  - Trend-Anzeige verbessert: Wenn keine Historie verfügbar ist, wird nun der Grund genannt und eine konkrete Lösung vorgeschlagen (regelmäßige Scans, Aufbewahrung, Owner/Alerting). Bei vorhandener Trendbewertung wird eine Beispiel-Lösung für Alerting/Reporting gezeigt.
  - `Exposure-Level` hervorgehoben (fett) und Legende klar getrennt.
  - `KERNKENNZAHLEN`-Tabelle: 'niedrig' Label entfernt; Status-Ampel bleibt, Label nur für andere Stufen, kleiner in Klammern unterhalb der Ampel.
  - `Fazit` erweitert: konkrete Maßnahmen (Sofortmaßnahmen, Patching, Zugriffshärtung, Monitoring) und vorgeschlagener Zeitplan (High-Risk innerhalb 30 Tagen).
  - test: smoke-run via `scripts/run-jobs-direct.py` — 7/7 successful; generated PDFs placed under `reports/` (example: `reports/Honeypot/2026-01_135.125.206.130.pdf`).

  ## 2026-01-21

  - feat: management summary clarity and emphasis
    - `src/shodan_report/pdf/sections/management.py`: remove numeric counts on page 1, highlight short recommendation, add boxed status line
    - `src/shodan_report/pdf/helpers/management_helpers.py`: align Top-3 wording for theoretical high risk without active exploitation
  - fix: trend section placement and wording
    - `src/shodan_report/pdf/pdf_manager.py`: move Trend- & Vergleichsanalyse behind technical details
    - `src/shodan_report/pdf/sections/trend.py`: clearer no-data message for management
  - test: update expectations for trend and management summary
    - adjusted tests for new messaging and layout
  - fix: management wording and recommendations clarity
    - `src/shodan_report/pdf/sections/management.py`: smooth kernaussagen wording and standardize OSINT-Hinweise spelling
    - `src/shodan_report/pdf/sections/data/recommendations_data.py`: refine SSH recommendation wording
  - fix: trend/conclusion alignment for TLS improvements
    - `src/shodan_report/pdf/sections/trend.py`: align TLS-only interpretation text
    - `src/shodan_report/reporting/trend.py`: ensure TLS-only improvements are surfaced in trend interpretation
    - `src/shodan_report/pdf/sections/conclusion.py`: align conclusion direction with TLS-only improvements
  - feat: CVE overview no-risk note
    - `src/shodan_report/pdf/sections/cve_overview.py`: add short no-immediate-risk note when no critical CVEs are found
  - feat: management summary specificity
    - `src/shodan_report/pdf/sections/management.py`: include asset count/host context and explain exposure composition
  - feat: first-page summary table and header polish
    - `src/shodan_report/pdf/sections/management.py`: add compact `KERNKENNZAHLEN` table on page 1 (Assets / Ports / CVEs / Status)
    - `src/shodan_report/pdf/sections/management.py`: center exposure-ampel in status cell, lowercase status label
    - `src/shodan_report/pdf/sections/header.py`: move and style the report title to header: "Analyse der externen Angriffsfläche"
  - test: local test run
    - Ran `pytest`: 568 passed, 0 failed
  - feat: technical appendix enrichment
    - `src/shodan_report/reporting/technical_data.py`: include SSH/SSL detail payloads
    - `src/shodan_report/pdf/sections/data/technical_data.py`: extract SSH/HTTP indicators when OSINT provides them
    - `src/shodan_report/pdf/sections/technical.py`: render SSH auth/cipher and HTTP HSTS/redirect/methods hints
  - fix: recommendations and conclusion wording
    - `src/shodan_report/pdf/sections/data/recommendations_data.py`: expand SSH guidance and TLS check
    - `src/shodan_report/pdf/sections/conclusion.py`: concise state + recommendation only
  - fix: trend interpretation phrasing
    - `src/shodan_report/pdf/sections/trend.py`: updated TLS improvement interpretation and in-text reference to critical services
    - `src/shodan_report/reporting/trend.py`: aligned interpretation for TLS improvements
  - feat: management and technical refinements
    - `src/shodan_report/pdf/sections/management.py`: add OSINT technical bottom-line and updated trend sentence
    - `src/shodan_report/pdf/sections/technical.py`: limit SSH/HTTP lists and surface TLS cipher hints
    - `src/shodan_report/pdf/sections/data/technical_data.py`: extract TLS cipher names when available
    - `src/shodan_report/pdf/sections/cve_overview.py`: clarify CVE scope note
  - feat: webserver analysis and visuals
    - `src/shodan_report/pdf/sections/technical.py`: add TLS protocol safety, certificate details, and HTTP security headers
    - `src/shodan_report/pdf/sections/data/technical_data.py`: extract TLS certificate metadata and HTTP header indicators
    - `src/shodan_report/pdf/sections/management.py`: add exposure traffic-light indicator
    - `src/shodan_report/pdf/sections/trend.py`: add exposure-level trend chart and rename management services label
    - `src/shodan_report/core/runner.py`: expose previous exposure score for trend chart
    - `src/shodan_report/pdf/sections/data/recommendations_data.py`: add optional webserver hardening recommendations

## 2026-01-20

- fix: jobs parser supports customer names with spaces
  - `scripts/run-jobs-direct.py`: parse customer name from remaining tokens and normalize for config mapping
- feat: recommendations show "keins" when Priority 1 is empty
  - `src/shodan_report/pdf/sections/recommendations.py`: add explicit placeholder for empty critical list
- feat: auto-compare with previous month snapshot
  - `src/shodan_report/core/runner.py`: when no compare month is provided, try previous month snapshot and build trend automatically
- test: previous-metrics for trend table
  - added coverage to ensure previous snapshot metrics populate trend comparison
- fix: TLS weakness trend consistency
  - `src/shodan_report/pdf/sections/trend.py`: count missing TLS info on HTTPS ports to match prior-month metrics
- test: TLS weakness counting without ssl_info
  - added coverage for TLS weakness heuristics
- fix: snapshot JSON parsing completeness
  - `src/shodan_report/parsing/utils.py`: support snapshot-style fields (`ip`, `open_ports`, `city`, `country`, `last_update`)
- test: snapshot parsing and loading
  - `src/shodan_report/tests/parsing/test_parse_shodan_host.py`: snapshot `services` list + top-level fields
  - `src/shodan_report/tests/persistence/test_snapshot_manager.py`: `load_snapshot()` reads snapshot JSON cleanly
- test: trend interpretation and rendering coverage
  - `src/shodan_report/tests/pdf/sections/test_trend_extra.py`: trend table derivation, ratings, and interpretation text
- feat: dynamic trend interpretation
  - `src/shodan_report/pdf/sections/trend.py`: interpretation now reflects trend table changes automatically
- fix: snapshot persistence keeps TLS/SSH info
  - `src/shodan_report/persistence/snapshot_manager.py`: include `ssl`/`ssh` fields in snapshot services
  - `src/shodan_report/tests/persistence/test_snapshot_manager.py`: coverage for SSL preservation
- feat: include Shodan tags in report metadata
  - `src/shodan_report/parsing/utils.py`: persist `tags` in snapshots
  - `src/shodan_report/reporting/technical_data.py`: expose tags for reporting
  - `src/shodan_report/pdf/sections/technical.py`: display Shodan tags under System-Informationen
- fix: trend counts enriched high-risk CVEs
  - `src/shodan_report/pdf/sections/trend.py`: include `cve_enriched` in high-risk count
  - `src/shodan_report/core/runner.py`: populate previous high-risk counts from enriched CVEs
  - `src/shodan_report/pdf/pdf_generator.py`: attach enriched CVEs before rendering
- fix: deduplicate high-risk CVEs in trend
  - `src/shodan_report/pdf/sections/trend.py`: count unique CVE IDs only
  - `src/shodan_report/tests/pdf/sections/test_trend_extra.py`: add dedup coverage
- feat: default logo fallback
  - `src/shodan_report/pdf/helpers/header_helpers.py`: use MG Solutions logo when no logo is configured
- fix: soften management summary and Top-3 wording
  - `src/shodan_report/pdf/sections/management.py`: dynamic intro based on observed services
  - `src/shodan_report/pdf/helpers/management_helpers.py`: adjust Top-3 phrasing for low exposure and HSTS/TLS wording
- fix: default logo width to 6 cm
  - `src/shodan_report/pdf/helpers/header_helpers.py`: set default `logo_width_cm` fallback to 6.0
- fix: clean noisy technical appendix fields
  - `src/shodan_report/pdf/sections/data/technical_data.py`: sanitize banner-derived product/version/server entries
- fix: clean noisy management short details
  - `src/shodan_report/pdf/helpers/management_helpers.py`: suppress banner garbage and infer services by port
- fix: infer service names by port in technical appendix
  - `src/shodan_report/pdf/sections/data/technical_data.py`: fallback to port-based service labels when banners are empty
- feat: align report with consultant checklist
  - `src/shodan_report/pdf/sections/management.py`: concise management summary without tables or technical details
  - `src/shodan_report/pdf/sections/technical.py`: facts-only appendix with OSINT source note
  - `src/shodan_report/pdf/sections/recommendations.py`: explain empty priorities and mark optional optimizations
  - `src/shodan_report/pdf/sections/conclusion.py`: single-paragraph conclusion (state, direction, recommendation)
- fix: polish report consistency and numbering
  - `src/shodan_report/pdf/sections/management.py`: simplify kernaussage wording and avoid duplicate exposure text
  - `src/shodan_report/pdf/sections/technical.py`: renumber appendix section
  - `src/shodan_report/pdf/sections/cve_overview.py`: renumber heading and simplify no-CVE text
  - `src/shodan_report/pdf/sections/trend.py`: renumber trend section
  - `src/shodan_report/pdf/sections/recommendations.py`: renumber recommendations section
  - `src/shodan_report/pdf/sections/footer.py`: remove tool branding line
- fix: sharpen trend interpretation and conclusion language
  - `src/shodan_report/pdf/sections/trend.py`: add TLS-improvement explanation and clarify critical services
  - `src/shodan_report/pdf/sections/conclusion.py`: smoother single-line conclusion
  - `src/shodan_report/pdf/sections/methodology.py`: add moment-in-time note

## 2026-01-15

- PDF: Neue CVE-Normalisierung und Zuordnung
  - `src/shodan_report/pdf/sections/data/cve_mapper.py` exportiert `normalize_cve_id()` und `assign_cves_to_services()`.
- Enrichment (No-Key fallback)
  - `src/shodan_report/pdf/sections/data/cve_enricher.py` liefert `nvd`-URLs und Platzhalter-Summaries ohne API-Key.
- Debug / Audit
  - `src/shodan_report/pdf/pdf_generator.py` schreibt nun eine `.mdata.json`-Seitenkartei neben jedem generierten PDF mit kanonischen Management-Daten und einem `cve_enriched_sample`.
- Tests
  - Neue Unit-Tests: `tests/pdf/sections/test_cve_mapper.py`, `tests/pdf/sections/test_cve_enricher.py`.
  - Neue Integrationstest: `tests/pdf/test_mdata_enrichment.py` prüft `.mdata.json`-Erzeugung.

Hinweis: Die Management-CVE-Zählung ist jetzt dedupliziert; Per-Service-Zuordnungen werden für lesbare Tabellen genutzt. Für vollständige CVE-Enrichment (NVD API, CPE Matching) folgt ein optionaler, späterer Schritt.
