import os
import json
from pathlib import Path

from dotenv import load_dotenv

from shodan_report.shodan_client import ShodanClient
from shodan_report.utils import parse_shodan_host


def main():
    # Config laden
    load_dotenv()

    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise RuntimeError("SHODAN_API_KEY fehlt")
    
    ip = "217.154.224.104" # my VPS ip

    client = ShodanClient(api_key)
    raw_data = client.get_host(ip)

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    raw_path = output_dir / "raw_shodan_output.json"
    with raw_path.open("w", encoding="utf-8") as f:
        json.dump(raw_data, f, indent=2)

    snapshot = parse_shodan_host(raw_data)

    snapshot_path = output_dir / "asset_snapshot.json"
    with snapshot_path.open("w",encoding="utf8") as f:
        json.dump(snapshot.__dict__, f, indent=2, default=str)

    print("Snapshot erfolgreich erzeugt.")
    print(f"IP: {snapshot.ip}")
    print(f"Offene Ports: {len(snapshot.open_ports)}")
    print(f"Dienste: {len(snapshot.services)}")

if __name__ == "__main__":
    main()