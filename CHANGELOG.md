# Changelog

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
