Contributing
============

Kurz: Danke fürs Mitwirken! Bitte folge diesen Schritten beim Beitrag.

1) Umgebung einrichten

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

2) Tests lokal ausführen

```powershell
pytest -q
```

3) Coding‑Guidelines

- Schreibe klare, kleine Commits.
- Füge Unit‑Tests für neue Logik hinzu (`src/shodan_report/tests/`).
- Verwende aussagekräftige Namen und docstrings.

4) Neue Evaluatoren hinzufügen

- Lege eine Datei in `src/shodan_report/evaluation/evaluators/` an.
- Implementiere eine `ServiceEvaluator` Subklasse oder nutze vorhandene Hilfen.
- Registriere den Evaluator in `ServiceEvaluatorRegistry` (siehe `registry.py`).
- Füge Tests, Fixtures und Beispiele hinzu.

5) Pull Request

- Fork → Branch → Commit → PR.
- Beschreibe das Problem und die Änderung kurz im PR‑Text.
- CI führt Tests automatisch aus (wenn eingerichtet). Bitte alle Tests lokal grün bekommen.

6) Sicherheit / Disclosure

- Wenn dein Beitrag sicherheitsrelevante Informationen enthält (z. B. reale Exploit‑Details), kontaktiere das Team privat und füge diese nicht in öffentlichen PRs hinzu.

Danke — dein Beitrag hilft, das Projekt besser zu machen.
