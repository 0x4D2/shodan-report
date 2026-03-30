#!/usr/bin/env python3
"""Generate snapshots/leads.json and snapshots/json_map.json for Sales Cockpit

Scans the repository `snapshots/` directory for JSON files, builds a mapping
IP -> JSON content and a minimal leads list (Firma + Shodan link) so the
Sales Cockpit can load data via /snapshots/*.json when served statically.

Usage:
  python scripts/generate_sales_snapshots.py

Output files (written to repo snapshots/):
  - snapshots/json_map.json
  - snapshots/leads.json
"""
import json
import os
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SNAP_DIR = REPO_ROOT / 'snapshots'
OUT_JSON_MAP = SNAP_DIR / 'json_map.json'
OUT_LEADS = SNAP_DIR / 'leads.json'


def extract_ip_from_name(name: str):
    m = re.search(r'(\d+\.\d+\.\d+\.\d+)', name)
    return m.group(1) if m else None


def main():
    if not SNAP_DIR.exists():
        print(f"snapshots directory not found at {SNAP_DIR}")
        return

    json_map = {}
    leads = []
    seen_ips = set()

    for root, dirs, files in os.walk(SNAP_DIR):
        for fn in files:
            if not fn.lower().endswith('.json'):
                continue
            path = Path(root) / fn
            # skip output files if present
            if path in (OUT_JSON_MAP, OUT_LEADS):
                continue
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except Exception as e:
                print(f"Warning: failed to parse {path}: {e}")
                continue

            # try to find ip
            ip = extract_ip_from_name(fn)
            if not ip:
                # try common fields inside JSON
                if isinstance(data, dict):
                    ip = data.get('ip') or data.get('host') or data.get('ip_str')
            if not ip:
                # try parent folder name
                ip = extract_ip_from_name(Path(root).name)

            if not ip:
                # fallback: use filename as key (unique)
                ip = fn

            # store in map if not duplicate
            if ip in seen_ips:
                # prefer dict content with 'ip' field to update mapping
                json_map[ip] = data
                continue

            seen_ips.add(ip)
            json_map[ip] = data

            # create minimal lead entry
            firma = Path(root).name if Path(root).name and Path(root).name != '.' else fn.replace('.json','')
            shodan = f"https://www.shodan.io/host/{ip}" if re.match(r'\d+\.\d+\.\d+\.\d+$', ip) else ''
            leads.append({
                'Firma': firma,
                'Entscheider': '',
                'Telefon': '',
                'Webseite': '',
                'Status': 'Offen',
                'Shodan-Link': shodan,
                'Notizen': '',
                'Rating': '',
                'Nächster Schritt': '',
            })

    # write outputs
    try:
        OUT_JSON_MAP.parent.mkdir(parents=True, exist_ok=True)
        with open(OUT_JSON_MAP, 'w', encoding='utf-8') as f:
            json.dump(json_map, f, ensure_ascii=False, indent=2)
        with open(OUT_LEADS, 'w', encoding='utf-8') as f:
            json.dump(leads, f, ensure_ascii=False, indent=2)
        print(f"Wrote {OUT_JSON_MAP} ({len(json_map)} entries) and {OUT_LEADS} ({len(leads)} leads)")
    except Exception as e:
        print(f"Error writing outputs: {e}")


if __name__ == '__main__':
    main()
