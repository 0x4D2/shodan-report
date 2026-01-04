from importlib.resources import files
import os
import json
import glob
from pathlib import Path

from dotenv import load_dotenv
from datetime import datetime

from shodan_report.shodan_client import ShodanClient
from shodan_report.utils import parse_shodan_host
from shodan_report.evaluation import evaluate_snapshot
from shodan_report.snapshot_manager import save_snapshot, load_snapshot, compare_snapshots


def main():
    # Config laden
    load_dotenv()

    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise RuntimeError("SHODAN_API_KEY fehlt")
    
    #ip = "217.154.224.104" # my VPS ip
    ip = "111.170.152.60" # test ip
    month ="2024-06"
    prev_month ="2025-12"

    client = ShodanClient(api_key)
    raw_data = client.get_host(ip)
    snapshot = parse_shodan_host(raw_data)

    save_snapshot(snapshot,"kunde1", month)

    prev_snapshot = load_snapshot(prev_month)

    if prev_snapshot:
        changes = compare_snapshots(prev_snapshot, snapshot)
        print("Änderungen seit Vormonat:")
        print(changes)
    else:
        print("Kein Snapshot vom Vormonat gefunden. Änderungen können nicht berechnet werden.")

    evaluation = evaluate_snapshot(snapshot)
    print("Bewertung:")
    print(f"IP: {evaluation.ip}")
    print(f"Risikostufe: {evaluation.risk.value}")
    print(f"Kritische Punkte: {evaluation.critical_points}")

if __name__ == "__main__":
    main()