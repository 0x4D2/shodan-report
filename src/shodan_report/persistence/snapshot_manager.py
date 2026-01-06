from pathlib import Path
import json
from shodan_report.models import AssetSnapshot

BASE_DATA_DIR = Path("data")
SNAPSHOT_DIR = Path("snapshots")
SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)

def serialize_service(service) -> dict:
   # Hilfsfunktion zum Serialisieren eines Service-Objekts
    return {
        "port": service.port,
        "product": service.product or getattr(service, "banner", "unbekannt"),
        "version": service.version or getattr(service, "banner", "unbekannt"),
    }
def save_snapshot(snapshot: AssetSnapshot, customer_name: str, month: str) -> Path:

    customer_dir = SNAPSHOT_DIR / customer_name.replace(" ", "_")
    customer_dir.mkdir(exist_ok=True)

    filename = f"{month}_{snapshot.ip}.json"
    path = customer_dir / filename

    serializable_snapshot = snapshot.__dict__.copy()
    serializable_snapshot["services"] = [serialize_service(s) for s in snapshot.services]

    with path.open("w", encoding="utf-8") as f:
        json.dump(serializable_snapshot, f, indent=2, default=str)
    return path

def load_snapshot(customer_name: str, month: str) -> AssetSnapshot | None:

    customer_dir = SNAPSHOT_DIR / customer_name.replace(" ", "_")
    if not customer_dir.exists():
        return None
    
    # * erlaubt spätere mehrere IPs 
    paths = list(customer_dir.glob(f"{month}_*.json"))
    if not paths:
        return None
    
    path = paths[0]
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    # Lazy import
    from shodan_report.parsing.utils import parse_shodan_host
    return parse_shodan_host(data)

def compare_snapshots(prev: AssetSnapshot, current: AssetSnapshot) -> dict:
    changes = {
        "new_ports": list(set(current.open_port) - set(prev.open_port)),
        "removed_ports": list(set(prev.open_port) - set(current.open_port)),
        "new_services": [s.product for s in current.services if s.product not in [ps.product for ps in prev.services]],
        "removed_services": [s.product for s in prev.services if s.product not in [cs.product for cs in current.services]],  
    }

    return changes  