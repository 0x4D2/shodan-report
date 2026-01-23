# Changelog

## Unreleased

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
