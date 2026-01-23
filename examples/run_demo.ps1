# PowerShell helper: copy demo snapshot and run demo script

# Ensure running from repository root
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $repoRoot

# Create snapshots target
$targetDir = "snapshots\CHINANET"
if (-Not (Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }

# Copy demo snapshot
Copy-Item -Force "examples\snapshots\demo_snapshot.json" "$targetDir\2026-01_203.0.113.10.json"

# Run demo generator
python scripts\generate_from_snapshot.py
