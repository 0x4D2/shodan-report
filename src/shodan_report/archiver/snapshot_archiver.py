from pathlib import Path
import json
from typing import Optional, List

from shodan_report.models import AssetSnapshot, Service

ARCHIVE_DIR = Path("archive")
ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)


def _customer_dir(customer_name: str) -> Path:
    dir_path = ARCHIVE_DIR / customer_name.replace(" ", "_")
    dir_path.mkdir(parents=True, exist_ok=True)
    return dir_path


def archive_snapshot(snapshot: AssetSnapshot, customer_name: str, month: str) -> Path:
    customer_dir = _customer_dir(customer_name)
    filename = f"{month}_{snapshot.ip}.json"
    path = customer_dir / filename

    serializable_snapshot = snapshot.__dict__.copy()
    serializable_snapshot["services"] = [
        {
            "port": s.port,
            "product": s.product or getattr(s, "banner", "unbekannt"),
            "version": s.version or getattr(s, "banner", "unbekannt"),
        }
        for s in snapshot.services
    ]

    with path.open("w", encoding="utf-8") as f:
        json.dump(serializable_snapshot, f, indent=2, default=str)
    return path


def list_archived_snapshots(customer_name: str) -> List[Path]:
    customer_dir = _customer_dir(customer_name)
    return list(customer_dir.glob("*.json"))


def retrieve_archived_snapshot(
    customer_name: str, month: str, ip: str
) -> Optional[AssetSnapshot]:
    """Directly load JSON back into AssetSnapshot without parse_shodan_host."""
    customer_dir = _customer_dir(customer_name)
    path = customer_dir / f"{month}_{ip}.json"

    if not path.exists():
        return None

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    # Services wieder in Objekte umwandeln
    services = [
        Service(
            port=s.get("port", 0),
            product=s.get("product"),
            version=s.get("version"),
            transport=s.get("transport", "tcp"),  # default falls nicht gesetzt
        )
        for s in data.get("services", [])
    ]

    return AssetSnapshot(
        ip=data.get("ip"),
        hostnames=data.get("hostnames", []),
        domains=data.get("domains", []),
        org=data.get("org"),
        isp=data.get("isp"),
        os=data.get("os"),
        city=data.get("city"),
        country=data.get("country"),
        services=services,
        open_ports=data.get("open_ports", []),
        last_update=data.get("last_update"),
        raw_banner=data.get("raw_banner", []),
        ssl_info=data.get("ssl_info"),
        ssh_info=data.get("ssh_info"),
    )
