Kurzinfo zu scripts/
---------------------

Zweck:
- Top-Level `scripts/` enthält produktive, wiederverwendbare Entrypoints (PDF-Generierung, Report-Runner, Snapshot-Tools).
- Alle experimentellen, Debug- oder Demo-Variantenskripte sind in `scripts/dev/` abgelegt.

Wie nutzen:
- Produktiv / Standard: `python scripts/generate_demo_pdf.py` oder andere Top-Level-Skripte.
- Dev / Untersuchung: `python scripts/dev/<script>.py` (z. B. `scripts/dev/debug_inspect.py`).

Konventionen:
- Keine Snapshots oder generierten Reports in Git committen. Nutze `snapshots/` und `reports/` lokal.
- Wenn du ein Debug-/Experiment-Skript erstellst, lege es unter `scripts/dev/` ab.

Wenn du möchtest, kann ich `generate_demo_pdf.py` als CLI mit Flags (`--snapshot`, `--nvd {real|dummy|circl}`, `--out`) erweitern.
