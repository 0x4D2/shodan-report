from pathlib import Path
import json
from shodan_report.models import AssetSnapshot

SNAPSHOT_DIR = Path("snapshots")
SNAPSHOT_DIR.mkdir(exist_ok=True)

def save_snapshot(snapshot: AssetSnapshot, customer_name: str, month: str) -> Path:

    path = SNAPSHOT_DIR / f"{month}_snapshot_{customer_name}.json"
    with path.open("w", encoding="utf-8") as f:
        json.dump(snapshot.__dict__, f, indent=2, default=str)
    return path

def load_snapshot(month: str) -> AssetSnapshot | None:
    path = SNAPSHOT_DIR / f"{month}_snapshot.json"
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    from shodan_report.utils import parse_shodan_host
    return parse_shodan_host(data)    

def compare_snapshots(prev: AssetSnapshot, current: AssetSnapshot) -> dict:
    changes = {
        "new_ports": list(set(current.open_port) - set(prev.open_port)),
        "removed_ports": list(set(prev.open_port) - set(current.open_port)),
        "new_services": [s.product for s in current.services if s.product not in [ps.product for ps in prev.services]],
        "removed_services": [s.product for s in prev.services if s.product not in [cs.product for cs in current.services]],  
    }

    return changes  