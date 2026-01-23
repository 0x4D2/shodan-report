#!/usr/bin/env python3
"""Download minimal NVD JSON feeds into .cache/nvd/ for local lookup.

Usage: python scripts/fetch_nvd_feeds.py [--years 2026,2025] [--force]

This is a minimal, robust downloader: fetches 'modified' and specified years.
"""
import argparse
import gzip
import json
import os
from pathlib import Path
from urllib.request import urlopen, Request
import os
try:
    import requests
except Exception:
    requests = None


BASE = "https://nvd.nist.gov/feeds/json/cve/1.1"


def download(url: str) -> bytes:
    # Prefer requests for more robust handling; fall back to urllib
    api_key = os.environ.get('NVD_API_KEY')
    headers = {"User-Agent": "shodan-report-feed-fetcher/1.0"}
    if api_key:
        headers['apiKey'] = api_key
        headers['X-Api-Key'] = api_key
    if requests:
        r = requests.get(url, headers=headers, timeout=60)
        r.raise_for_status()
        return r.content
    req = Request(url, headers=headers)
    with urlopen(req, timeout=60) as resp:
        return resp.read()


def save_gzip_json(data: bytes, out_path: Path) -> None:
    # if data is gzipped, decompress and save as .json
    try:
        content = gzip.decompress(data)
    except Exception:
        content = data
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(content)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--years", default="2026", help="comma-separated years to fetch")
    p.add_argument("--force", action="store_true")
    args = p.parse_args()

    years = [y.strip() for y in args.years.split(",") if y.strip()]
    cache_dir = Path('.cache') / 'nvd'
    cache_dir.mkdir(parents=True, exist_ok=True)

    targets = ["nvdcve-1.1-modified.json.gz"]
    for y in years:
        targets.append(f"nvdcve-1.1-{y}.json.gz")

    for name in targets:
        out_file = cache_dir / name.replace('.gz', '')
        if out_file.exists() and not args.force:
            print(f"Skipping existing {out_file}")
            continue
        url = f"{BASE}/{name}"
        print(f"Downloading {url} -> {out_file}")
        try:
            raw = download(url)
            save_gzip_json(raw, out_file)
            print(f"Saved {out_file} ({out_file.stat().st_size} bytes)")
        except Exception as e:
            print(f"Failed to download {url}: {e}")


if __name__ == '__main__':
    main()
