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
- feat: management summary clarity and emphasis
  - `src/shodan_report/pdf/sections/management.py`: remove numeric counts on page 1, highlight short recommendation, add boxed status line
  - `src/shodan_report/pdf/helpers/management_helpers.py`: align Top-3 wording for theoretical high risk without active exploitation
- fix: trend section placement and wording
  - `src/shodan_report/pdf/pdf_manager.py`: move Trend- & Vergleichsanalyse behind technical details
  - `src/shodan_report/pdf/sections/trend.py`: clearer no-data message for management
- test: update expectations for trend and management summary
  - adjusted tests for new messaging and layout

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
