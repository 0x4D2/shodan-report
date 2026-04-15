#!/usr/bin/env python3
"""CLI für Shodan Report Generator."""

import argparse
import sys
from pathlib import Path
from typing import Optional
from shodan_report.paths import reports_dir


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Shodan Report Generator - Revisionssichere Sicherheitsberichte",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
    %(prog)s --customer "CHINANET HUBEI" --ip 0.0.0.0 --month 2025-01
    %(prog)s --customer "MG Solutions" --ip 217.154.224.104 --month 2025-01 --compare 2024-12
    %(prog)s --customer "Example Corp" --ip 192.168.1.1 --month 2025-01 --config config/customers/example.yaml
    %(prog)s --customer "Example Corp" --domain example.com --month 2026-04
            """,
    )

    # Required arguments
    parser.add_argument(
        "--customer",
        "-c",
        required=True,
        help="Kundenname (z.B. 'CHINANET HUBEI PROVINCE NETWORK')",
    )

    parser.add_argument(
        "--ip", "-i",
        default=None,
        help="IP-Adresse (z.B. '0.0.0.0'). Optional wenn --domain angegeben.",
    )

    parser.add_argument(
        "--domain", "-d",
        default=None,
        help="Kundendomain für Attack-Surface-Discovery (z.B. 'example.com'). "
             "Ermittelt automatisch alle echten IPs via passivem OSINT.",
    )

    parser.add_argument(
        "--month", "-m", required=True, help="Monat im Format YYYY-MM (z.B. '2025-01')"
    )

    # Optional arguments
    parser.add_argument(
        "--compare", help="Vergleichsmonat im Format YYYY-MM (z.B. '2024-12')"
    )

    parser.add_argument(
        "--config", type=Path, help="Pfad zur Kundenkonfiguration (YAML)"
    )

    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=None,
        help="Ausgabeverzeichnis für PDFs (default: OUTPUT_BASE_DIR/reports oder ./reports)",
    )

    parser.add_argument(
        "--no-archive",
        action="store_true",
        help="PDF nicht im Archiv speichern (nur lokal)",
    )

    parser.add_argument(
        "--note", "-n",
        default=None,
        metavar="TEXT",
        help="Persönliche Ansprache/Bewertung — erscheint auf Seite 1. "
             "Überschreibt report.cover_note aus der YAML.",
    )

    parser.add_argument(
        "--from-snapshot",
        action="store_true",
        help="Kein Shodan-Aufruf — PDF aus gespeichertem Snapshot neu rendern. "
             "Ideal um nach dem Lesen des Reports eine --note hinzuzufügen.",
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Ausführliche Ausgabe"
    )

    parser.add_argument("--quiet", "-q", action="store_true", help="Minimale Ausgabe")

    return parser.parse_args(args)


def validate_args(args: argparse.Namespace) -> bool:
    """Validate command line arguments."""
    # Validate month format
    try:
        from datetime import datetime

        datetime.strptime(args.month, "%Y-%m")
    except ValueError:
        print(
            f"ERROR: Ungültiges Monatsformat: {args.month}. Erwartet: YYYY-MM",
            file=sys.stderr,
        )
        return False

    # Validate compare month if provided
    if args.compare:
        try:
            datetime.strptime(args.compare, "%Y-%m")
        except ValueError:
            print(f"ERROR: Ungültiges Vergleichsmonat: {args.compare}", file=sys.stderr)
            return False

    # --ip oder --domain muss vorhanden sein (außer bei --from-snapshot)
    if not args.ip and not args.domain and not args.from_snapshot:
        print(
            "ERROR: Entweder --ip oder --domain muss angegeben werden.",
            file=sys.stderr,
        )
        return False

    # Validate output directory
    output_dir = args.output_dir if args.output_dir is not None else reports_dir()
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError) as e:
        print(f"ERROR: Kann Ausgabeverzeichnis nicht erstellen: {e}", file=sys.stderr)
        return False

    return True


def build_pipeline_kwargs(args: argparse.Namespace) -> dict:
    """Build keyword arguments for `generate_report_pipeline` from parsed args."""
    return {
        "customer_name": args.customer,
        "ip": args.ip,
        "month": args.month,
        "compare_month": args.compare,
        "config_path": args.config,
        "output_dir": args.output_dir,
        "archive": not args.no_archive,
        "verbose": args.verbose,
        "domain": args.domain,
        "note": args.note,
        "from_snapshot": args.from_snapshot,
    }


def run_pipeline_with_args(args: argparse.Namespace) -> dict:
    """Import and run `generate_report_pipeline` using an args namespace.

    Kept as a small helper to avoid import-time issues and make testing easier.
    """
    from shodan_report.core.runner import generate_report_pipeline

    return generate_report_pipeline(**build_pipeline_kwargs(args))

def main() -> int:
    """Main entry point."""
    args = parse_args()

    if not validate_args(args):
        return 1

    if args.verbose:
        print(f"Generiere Report für Kunde: {args.customer}")
        if args.domain:
            print(f"Domain: {args.domain} (Attack-Surface-Discovery aktiv)")
        if args.ip:
            print(f"IP: {args.ip}")
        print(f"Monat: {args.month}")
        if args.compare:
            print(f"Vergleich mit: {args.compare}")
        if args.config:
            print(f"Konfiguration: {args.config}")

    try:
        result = run_pipeline_with_args(args)

        if result.get("success"):
            if not args.quiet:
                print(f"\n Report erfolgreich generiert:")
                print(f"   PDF: {result['pdf_path']}")
                if result.get("archived"):
                    print(f"   Archiviert als: {result['archive_path']}")
                print(f"   Business-Risiko: {result['business_risk']}")
            return 0
        else:
            print(
                f"\n Fehler: {result.get('error', 'Unbekannter Fehler')}",
                file=sys.stderr,
            )
            return 1

    except KeyboardInterrupt:
        print("\n Abgebrochen durch Benutzer", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"\n Unerwarteter Fehler: {e}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
