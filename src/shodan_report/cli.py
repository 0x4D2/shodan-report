#!/usr/bin/env python3
"""CLI für Shodan Report Generator."""

import argparse
import sys
from pathlib import Path
from typing import Optional

from shodan_report.core.runner import generate_report_pipeline


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Shodan Report Generator - Revisionssichere Sicherheitsberichte",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  %(prog)s --customer "CHINANET HUBEI" --ip 0.0.0.0 --month 2025-01
  %(prog)s --customer "MG Solutions" --ip 217.154.224.104 --month 2025-01 --compare 2024-12
  %(prog)s --customer "Example Corp" --ip 192.168.1.1 --month 2025-01 --config config/customers/example.yaml
        """
    )
    
    # Required arguments
    parser.add_argument(
        "--customer", "-c",
        required=True,
        help="Kundenname (z.B. 'CHINANET HUBEI PROVINCE NETWORK')"
    )
    
    parser.add_argument(
        "--ip", "-i",
        required=True,
        help="IP-Adresse (z.B. '0.0.0.0')"
    )
    
    parser.add_argument(
        "--month", "-m",
        required=True,
        help="Monat im Format YYYY-MM (z.B. '2025-01')"
    )
    
    # Optional arguments
    parser.add_argument(
        "--compare",
        help="Vergleichsmonat im Format YYYY-MM (z.B. '2024-12')"
    )
    
    parser.add_argument(
        "--config",
        type=Path,
        help="Pfad zur Kundenkonfiguration (YAML)"
    )
    
    parser.add_argument(
        "--output-dir", "-o",
        type=Path,
        default=Path("./reports"),
        help="Ausgabeverzeichnis für PDFs (default: ./reports)"
    )
    
    parser.add_argument(
        "--no-archive",
        action="store_true",
        help="PDF nicht im Archiv speichern (nur lokal)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Ausführliche Ausgabe"
    )
    
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Minimale Ausgabe"
    )
    
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> bool:
    """Validate command line arguments."""
    # Validate month format
    try:
        from datetime import datetime
        datetime.strptime(args.month, "%Y-%m")
    except ValueError:
        print(f"ERROR: Ungültiges Monatsformat: {args.month}. Erwartet: YYYY-MM", file=sys.stderr)
        return False
    
    # Validate compare month if provided
    if args.compare:
        try:
            datetime.strptime(args.compare, "%Y-%m")
        except ValueError:
            print(f"ERROR: Ungültiges Vergleichsmonat: {args.compare}", file=sys.stderr)
            return False
    
    # Validate output directory
    try:
        args.output_dir.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError) as e:
        print(f"ERROR: Kann Ausgabeverzeichnis nicht erstellen: {e}", file=sys.stderr)
        return False
    
    return True


def main() -> int:
    """Main entry point."""
    args = parse_args()
    
    if not validate_args(args):
        return 1
    
    if args.verbose:
        print(f"Generiere Report für Kunde: {args.customer}")
        print(f"IP: {args.ip}")
        print(f"Monat: {args.month}")
        if args.compare:
            print(f"Vergleich mit: {args.compare}")
        if args.config:
            print(f"Konfiguration: {args.config}")
    
    try:
        # Import here to avoid circular imports
        from shodan_report.core.runner import generate_report_pipeline
        
        result = generate_report_pipeline(
            customer_name=args.customer,
            ip=args.ip,
            month=args.month,
            compare_month=args.compare,
            config_path=args.config,
            output_dir=args.output_dir,
            archive=not args.no_archive,
            verbose=args.verbose
        )
        
        if result.get("success"):
            if not args.quiet:
                print(f"\n Report erfolgreich generiert:")
                print(f"   PDF: {result['pdf_path']}")
                if result.get('archived'):
                    print(f"   Archiviert als: {result['archive_path']}")
                print(f"   Business-Risiko: {result['business_risk']}")
            return 0
        else:
            print(f"\n Fehler: {result.get('error', 'Unbekannter Fehler')}", file=sys.stderr)
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