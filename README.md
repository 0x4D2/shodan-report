# Shodan Report — Monatsberichte aus externer Sicht

Kurz: dieses Projekt erstellt monatliche Sicherheitsreports auf Basis von Shodan‑Snapshots. Ziel ist ein leichtgewichtiger, automatisierter Report‑Generator, der für Kund:innen die öffentliche Angriffsfläche dokumentiert, bewertet und als PDF archiviert und ausliefert.

## Kernfunktionen (MVP)
- IP‑basierte Snapshot‑Erfassung (via Shodan)
- Normalisierung der Rohdaten
- Bewertung & Priorisierung von Risiken
- Erkennen von Änderungen (Monat zu Monat)
- Erzeugung Management‑Text in verständlicher deutscher Sprache
- Technischer Anhang (offene Ports, Dienste, Versionen)
- PDF‑Erzeugung und Archivierung (Dateisystem, meta JSON)
- Unit‑ und Integrationstests (pytest)

## Architekturüberblick
- `shodan_report/evaluation` — Logik zur Bewertung (`evaluate_snapshot`, `prioritize_risk`).
- `shodan_report/reporting` — Management‑Text, technische Datenaufbereitung, Trendanalyse.
- `shodan_report/pdf` — PDF‑Elements + Renderer.
- `shodan_report/persistence` — Snapshot‑Speicherung, Vergleichsfunktionen.
- `shodan_report/archive` — Archivierung (MVP: Dateisystem + meta JSON; später SQLite/S3).

## Archivierungsstrategie (MVP)
- Dateien: `archive/{customer_slug}/{YYYY-MM}/{YYYY-MM}_{ip}_v{N}.pdf`
- Metadaten: begleitende JSON `{...}.meta.json` mit Feldern: `customer_slug`, `customer_name`, `ip`, `month`, `pdf_path`, `sha256`, `size_bytes`, `version`, `generator`, `created_at`, `extra`.
- Schreibregeln: atomarer Write (temp → mv), niemals überschreiben (Versionierung), einfache File‑Locking beim Versionieren.
- Backup: regelmässiges `rsync` zu externem Speicher (S3/Spaces) empfohlen.

## Wie man lokal entwickelt / Tests
Voraussetzung: Python 3.11+, `pip install -r requirements.txt` (falls vorhanden).

Tests laufen mit pytest:

```bash
python -m pip install -r requirements.txt
pytest -q
```

Wichtige Tests: Unit‑Tests für `evaluate_snapshot`, `compare_snapshots`, `analyze_trend`, `generate_pdf`; Integrationstest für den Full‑Flow (mocked renderer).

## Nächste Schritte / Roadmap
- Archivierung: robustes `archiver`‑Modul (Datei‑MVP → optional SQLite/S3 Backend)
- PDF‑Qualität: PDF/A, eingebettete Fonts, Template‑Verbesserungen für Vertrieb
- Automatisierung: n8n‑Workflows zur Planung/Scheduling
- Versand: sichere Lieferung (signed URLs / E‑Mail mit Attachment)
- Erweiterung Datenpunkte: CVE‑Enrichment, SSL‑Checks, Exposure‑Scoring
- Rechtliches: Disclaimer, DSGVO‑Prozesse, Zustimmung durch Kunden

## Lizenz
Dieses Repository steht unter der MIT‑Lizenz (siehe `LICENSE`).

## Kontakt / Betrieb
Dieses Projekt wurde ursprünglich für den Betrieb auf einem VPS entworfen. Empfohlen: separate Backups, Monitoring und eine einfache Admin‑Konfiguration pro Kunde (IPs, E‑Mail, Retention).

---
Wenn du möchtest, implementiere ich jetzt das `archiver`‑Modul (Dateibasiert) und integriere es in den PDF‑Flow.
# Shodan Report Tool

Automatisiertes Tool zur externen Sicherheitsbewertung von öffentlich erreichbaren
IT-Systemen auf Basis von Shodan.

Der Fokus liegt auf **monatlichen Snapshots**, **vergleichbarer Historie**
und **nachvollziehbaren Risikoänderungen** aus Angreifer-Sicht.

---

## Grundidee

- Jede IP wird **regelmäßig (monatlich)** gescannt
- Jeder Scan erzeugt einen **Snapshot**
- Snapshots werden **archiviert**
- Neue Snapshots werden **gegen den letzten Monat verglichen**
- Daraus entsteht ein **Management- und Technikreport**

Ziel:  
Nicht „einmal scannen“, sondern **Sicherheitsentwicklung sichtbar machen**.

---

## Aktueller Stand

✔ Daten von Shodan abrufen  
✔ Rohdaten normalisieren (`AssetSnapshot`)  
✔ Regelbasierte Sicherheitsbewertung (`low / medium / high`)
✔ Vergleich: aktueller Monat vs. Vormonat
✔ Risiko-Priorisierung über Zeit
✔ Kunden- / IP-Verwaltung
✔ Management-Text + Historie (Trend, Veränderung)

Die Bewertung basiert aktuell auf:
- Anzahl offener Dienste
- Kritische Dienste (z. B. SSH, RDP)
- Einfache Versions-Indikatoren (Platzhalter)

⚠️ **Hinweis:**  
Die Versionsbewertung ist bewusst vereinfacht.  
Eine echte CVE- und Exploit-Bewertung folgt später.

---

## Noch nicht umgesetzt (bewusst)

- Report-Generierung (PDF)
- Automatisierung (z. B. n8n)

Diese Punkte sind **Teil des Zielbilds**, aber aktuell **nicht implementiert**.

---

## Architektur-Idee

Trennung in klare Schichten:

- **Rohdaten**
  - Unveränderte Shodan-API-Antwort

- **Normalisierung**
  - Einheitliches internes Modell (`AssetSnapshot`)

- **Bewertung**
  - Regelbasierte Analyse (`Evaluation`)

- **Historie**
  - Speicherung pro IP und Monat
  - Vergleich mit vorherigem Snapshot

- **Reporting**
  - Management-Zusammenfassung
  - Technischer Detailanhang

---

## Warum Historie entscheidend ist

Ein einzelner Scan sagt wenig aus.  
Erst der **Vergleich über Zeit** zeigt:

- neue offene Ports
- neu exponierte Dienste
- steigendes oder sinkendes Risiko
- Sicherheitsverschlechterung trotz „keiner Änderung“

Dieses Tool ist daher **historienzentriert**, nicht scan-zentriert.

---

## Status

Dieses Projekt befindet sich im **aktiven Aufbau**.
Der Fokus liegt aktuell auf **sauberer Datenbasis und Bewertung**,
nicht auf UI oder PDF-Ausgabe.
