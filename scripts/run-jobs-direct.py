# scripts/run-jobs-direct.py
"""Batch-Verarbeitung aus jobs.txt.

Format jobs.txt (eine Job-Definition pro Zeile):
  Kundenname IP YYYY-MM [--compare YYYY-MM] [--config pfad.yaml]

Beispiele:
  Acme GmbH 1.2.3.4 2026-04
  Acme GmbH 1.2.3.4 2026-04 --compare 2026-03
  Acme GmbH 1.2.3.4 2026-04 --config config/customers/acme.yaml

Config-Datei wird automatisch gesucht unter:
  config/customers/<kundenname-lowercase-mit-bindestrich>.yaml
"""
import sys
import os
import argparse
from pathlib import Path

if os.getenv("USE_LOCAL_SRC") == "1":
    src_path = Path(__file__).resolve().parents[1] / "src"
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))

from shodan_report.core.runner import generate_report_pipeline

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _find_config(customer: str) -> Path | None:
    """Sucht automatisch nach einer passenden Config-Datei."""
    slug = customer.lower().replace(" ", "-").replace("_", "-")
    candidates = [
        _REPO_ROOT / "config" / "customers" / f"{slug}.yaml",
        _REPO_ROOT / "config" / "customers" / f"{slug}.yml",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def _parse_job_line(line: str) -> dict | None:
    """Parst eine jobs.txt-Zeile in ein Job-Dict."""
    # Trenne Flags (--compare, --config) vom Pflicht-Teil ab
    tokens = line.split()
    compare_month = None
    config_path = None

    # Flags extrahieren
    i = 0
    positional = []
    while i < len(tokens):
        if tokens[i] == "--compare" and i + 1 < len(tokens):
            compare_month = tokens[i + 1]
            i += 2
        elif tokens[i] == "--config" and i + 1 < len(tokens):
            config_path = Path(tokens[i + 1])
            i += 2
        else:
            positional.append(tokens[i])
            i += 1

    if len(positional) < 3:
        return None

    month = positional[-1]
    ip = positional[-2]
    customer = " ".join(positional[:-2])

    if not customer or not ip or not month:
        return None

    return {
        "customer": customer,
        "ip": ip,
        "month": month,
        "compare_month": compare_month,
        "config_path": config_path,
    }


def main():
    parser = argparse.ArgumentParser(description="Batch-Report-Generierung aus jobs.txt")
    parser.add_argument("--jobs", default="jobs.txt", help="Pfad zur jobs.txt")
    parser.add_argument("--archive", action="store_true", help="Revisionssichere Archivierung aktivieren")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    jobs_file = Path(args.jobs)
    if not jobs_file.exists():
        print(f"Fehler: {jobs_file} nicht gefunden")
        sys.exit(1)

    lines = [
        l.strip() for l in jobs_file.read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.startswith("#")
    ]

    total = len(lines)
    success = 0
    print(f"=== Batch Processing — {total} Jobs ===\n")

    for i, line in enumerate(lines, 1):
        job = _parse_job_line(line)
        if not job:
            print(f"[{i}/{total}] ⚠️  Ungültige Zeile: {line}")
            continue

        # Config automatisch suchen wenn nicht explizit angegeben
        config_path = job["config_path"]
        if config_path is None:
            config_path = _find_config(job["customer"])

        print(f"[{i}/{total}] {job['customer']} — {job['ip']} — {job['month']}", end="")
        if config_path:
            print(f" (config: {config_path.name})", end="")
        print()

        result = generate_report_pipeline(
            customer_name=job["customer"],
            ip=job["ip"],
            month=job["month"],
            config_path=config_path,
            archive=args.archive,
            compare_month=job["compare_month"],
            verbose=args.verbose,
        )

        if result.get("success"):
            print(f"  ✓ {result.get('pdf_path', '?')}")
            success += 1
        else:
            print(f"  ✗ {result.get('error', 'Unbekannter Fehler')}")

    print(f"\n=== Fertig: {success}/{total} erfolgreich ===")


if __name__ == "__main__":
    main()
