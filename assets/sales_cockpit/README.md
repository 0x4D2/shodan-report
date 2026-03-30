Sales Cockpit — Integration Notes

Platzierung
- Diese statische Seite liegt unter `assets/sales_cockpit/index.html`.

Repo‑Daten (optional)
- Um die Schaltfläche „Aus Repo laden" zu nutzen, lege zwei JSON Dateien im Ordner `snapshots/` ab (relativ zur Web‑Root):
  - `snapshots/leads.json` — Array mit Lead‑Objekten (Felder: Firma, Entscheider, Telefon, Webseite, Status, Shodan-Link, Notizen, Rating, Nächster Schritt)
  - `snapshots/json_map.json` — Objekt, das IP → Shodan‑Snapshot (JSON) mappt

Beispiel: Wenn du das Repo im Webserver unter `/` bereitstellst, müssen die Dateien erreichbar sein unter
  - `http://<host>/snapshots/leads.json`
  - `http://<host>/snapshots/json_map.json`

Lokaler Test
- Starte einen einfachen HTTP‑Server im Repo‑Root (wichtig, damit `fetch()` Directory‑Requests funktionieren):

  ```powershell
  # Windows / PowerShell
  cd c:\pfad\zu\shodan-report\shodan-report
  python -m http.server 8000
  # dann im Browser: http://localhost:8000/assets/sales_cockpit/index.html
  ```

Hinweis
- Wenn die Dateien nicht vorhanden sind, funktioniert weiterhin die manuelle Datei‑Auswahl (Excel + JSONs).
- Call‑Logs und zuletzt geladene Leads werden lokal in `localStorage` gespeichert (Key: `mg_callLog`, `mg_leads`, `mg_jsonMap`).

Nächste Schritte (empfohlen)
- Vollständige PDF‑Generierung (aktuell Platzhalter in index.html) kopieren/aktivieren aus der Originaldatei.
- Optional: Ein kurzes Backend (Flask/FastAPI) implementieren, das `snapshots/leads.json` und `json_map.json` erzeugt/servet.
