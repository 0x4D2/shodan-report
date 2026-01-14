Kurz: Test‑freundliche PDF‑Orchestrierung
======================================

Dieses Verzeichnis enthält die PDF‑Erzeugung für den Report (ReportLab).
Die Hauptfunktionen sind:

- `prepare_pdf_elements(...)` — erzeugt die Berichtselemente (Paragraphs, Tables, Drawings).
- `generate_pdf(...)` — Wrapper, der `prepare_pdf_elements` aufruft und das PDF rendert.

Dependency Injection (Testbarkeit)
---------------------------------

Ab Version der aktuellen Änderungen akzeptiert `prepare_pdf_elements` optional
eine Liste von `sections`-Callables. Dadurch können Tests oder Mock‑Implementierungen
Section‑Aufrufe ersetzen und die gesamte PDF‑Orchestrierung ohne ReportLab gerendert
werden.

Erwartetes Verhalten der `sections`-Callables:
- Jede Section wird mit Keyword‑Argumenten aufgerufen; mindestens `elements` und
  `styles` sollten unterstützt werden.
- Sections können zusätzliche Keys ignorieren (z. B. `theme`, `technical_json`).

Beispiel (Test):

```python
def mock_section(items=None, **kwargs):
    elements = kwargs.get("elements")
    elements.append("MOCK")

elements = prepare_pdf_elements(
    customer_name="ACME",
    month="2026-01",
    ip="1.2.3.4",
    management_text="...",
    trend_text="...",
    technical_json={},
    evaluation={},
    business_risk="LOW",
    config={},
    sections=[mock_section],
)
assert elements == ["MOCK"]
```

Kompatibilität
---------------

`generate_pdf` verhält sich weiterhin wie zuvor — die neue `sections`-Option ist
optional und beeinflusst nur Tests oder Erweiterungen, die eine eigene
Section‑Reihenfolge benötigen.

Weiteres
-------

Empfehlung: Bei größeren Refactors die reine Logik (Insights / Normalisierung)
in `src/shodan_report/pdf/helpers` behalten und die Section‑Module (unter
`src/shodan_report/pdf/sections`) rein für das Assembling/Rendering verwenden.
