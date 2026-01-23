import sys
from pathlib import Path
import runpy

# ensure src is on sys.path
root = Path(__file__).resolve().parents[1]
src_dir = root / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

# execute the original script
runpy.run_path(str(root / "scripts" / "run-jobs-direct.py"), run_name="__main__")
