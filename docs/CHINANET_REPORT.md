CHINANET Report — Kurzbeschreibung

Ziel
----
Dieses Dokument beschreibt knapp und lesbar, wie der CHINANET-Report (Beispiel-Output) ab 2026-01 aufgebaut ist.

Aufbau (kurz)
--------------
1. Header
   - Metadaten: Kunde, IP, Monat, Generierungsdatum, Report-Version.

2. Management-Zusammenfassung
   - Executive-Summary mit Exposure-Level.
   - Deduplizierte Gesamtzahl identifizierter CVEs (z. B. "Identifizierte Sicherheitslücken: 107").
   - Kurzbeschreibung der wichtigsten Handlungsfelder (1–3 Punkte).

3. Management-Tabelle (pro Service)
   - Spalten: Port | Dienst/Produkt | Version | Zugeordnete CVEs | CVSS>=7 | Empfohlene Sofortmaßnahme
   - Ziel: Verantwortlichen eine kurze, priorisierte Checkliste an die Hand geben.

4. Technischer Anhang
   - Pro Service: Banner, TLS-Info (Protocol/weak_ciphers/cert_expiry), Liste zugeordneter CVEs.
   - Unassigned CVEs: am Ende eine Liste aller CVEs, die nicht eindeutig zugeordnet werden konnten.

5. CVE-Übersicht (vorläufig)
   - CVE-IDs sind dedupliziert und alphabetisch sortiert.
   - Die begleitende `.mdata.json` enthält eine No-Key-Enrichment-Vorschau (NVD-Links, Platzhalter-Summaries).
   - Hinweis: Eine eigenständige, ausführliche CVE-Section mit NVD/CPE-Anreicherung ist als nächster Schritt geplant.

6. Trend/Comparison (falls `--compare` gesetzt)
   - Tabelle mit Vergleichszahlen (Ports, CVEs) und einer kurzen Interpretation.

Audit / Debug
-------------
- Neben jeder generierten PDF wird eine `.mdata.json` geschrieben (Beispiel: `reports/CHINANET/2026-01_111.170.152.60.mdata.json`).
  Sie enthält: `cve_count`, `total_ports`, `risk_level`, `unique_cves`, `cve_enriched_sample`.
- Zweck: schnelle Verifikation der Zahlen ohne PDF-Parsing.

Designprinzipien
-----------------
- Kurz & handlungsorientiert für Management.
- Technische Details bleiben im Annex nachvollziehbar.
- Zahlen müssen deterministisch und reproduzierbar sein (CVE-Deduplication).

Nächste Schritte
----------------
- Implementierung einer eigenen CVE-Section mit NVD/CPE-Anreicherung.
- Optional: Links in der PDF direkt anklickbar machen (je nach Layout-Möglichkeiten von ReportLab).

