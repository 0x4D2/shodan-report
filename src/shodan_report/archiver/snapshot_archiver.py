from pathlib import Path
import json
import tempfile
import shutil
from typing import Optional, List

from shodan_report.models import AssetSnapshot, Service

ARCHIVE_DIR = Path("archive")


def _customer_dir(customer_name: str) -> Path:
    """Return customer archive directory path (does not create it)."""
    return ARCHIVE_DIR / customer_name.replace(" ", "_")


def _ensure_customer_dir(customer_name: str) -> Path:
    dir_path = _customer_dir(customer_name)
    dir_path.mkdir(parents=True, exist_ok=True)
    return dir_path


def archive_snapshot(snapshot: AssetSnapshot, customer_name: str, month: str) -> Path:
    """Serialize and atomically write an `AssetSnapshot` JSON to the archive.

    The archive directory is created if necessary.
    """
    customer_dir = _ensure_customer_dir(customer_name)
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

    # atomic write via temp file and replace
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=str(customer_dir), prefix=f".tmp_{filename}", delete=False) as tf:
            tmp_path = Path(tf.name)
            json.dump(serializable_snapshot, tf, indent=2, default=str)

        tmp_path.replace(path)
    finally:
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass

    return path


def list_archived_snapshots(customer_name: str) -> List[Path]:
    customer_dir = _customer_dir(customer_name)
    if not customer_dir.exists():
        return []
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
