"""Pytest bootstrap: ensure repo root and `src/` are on sys.path for tests.

Some tests import modules as `src.shodan_report.*`. Adding the repository
root and the `src/` directory to `sys.path` here makes those imports work
when running `pytest` from the project root.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[0]
# Add repo root so `import src...` resolves to the `src` folder in the repo
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SRC = ROOT / "src"
if SRC.exists() and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
