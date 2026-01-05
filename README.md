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
