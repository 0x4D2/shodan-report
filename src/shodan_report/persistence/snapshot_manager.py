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
    prev_ports = set(getattr(prev, "open_ports", []) or [])
    curr_ports = set(getattr(current, "open_ports", []) or [])

    new_ports = sorted(list(curr_ports - prev_ports))
    removed_ports = sorted(list(prev_ports - curr_ports))

    def _product_list(services):
        names = []
        for s in services or []:
            name = s.product if getattr(s, "product", None) else getattr(s, "banner", None) or "unbekannt"
            names.append(name)
        return names

    prev_products = _product_list(prev.services)
    curr_products = _product_list(current.services)

    new_services = sorted(list(set(curr_products) - set(prev_products)))
    removed_services = sorted(list(set(prev_products) - set(curr_products)))

    changes = {
        "new_ports": new_ports,
        "removed_ports": removed_ports,
        "new_services": new_services,
        "removed_services": removed_services,
    }

    return changes