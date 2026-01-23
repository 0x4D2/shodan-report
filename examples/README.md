Examples — Quick Demo
======================

This folder contains a small demo snapshot and instructions to generate a PDF locally using the project's demo script.

Files:
- `snapshots/demo_snapshot.json` — minimal AssetSnapshot-like JSON used for demo runs.
- `run_demo.ps1` — PowerShell helper to copy the demo snapshot into `snapshots/CHINANET/` and run the provided `scripts/generate_from_snapshot.py` script.

Steps (Windows PowerShell):

1) Create the target snapshots folder (if not present) and copy demo snapshot:

```powershell
mkdir -Force snapshots\CHINANET
Copy-Item examples\snapshots\demo_snapshot.json snapshots\CHINANET\2026-01_203.0.113.10.json
```

2) Run the demo generator script from repo root:

```powershell
python scripts\generate_from_snapshot.py
```

3) Result:
- A PDF will be written to `reports/demo/CHINANET/` (see `scripts/generate_from_snapshot.py` for exact path).
- If `report.debug_mdata` is enabled in config, a `.mdata.json` debug sidecar may be created next to the PDF.

Notes:
- The demo uses local snapshot JSON and does not query Shodan.
- Adjust `scripts/generate_from_snapshot.py` if you want to point at another snapshot path or change the customer/month.
