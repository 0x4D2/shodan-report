from .asset_snapshot import AssetSnapshot
from .service import Service
from datetime import datetime


def snapshot_to_dict(snapshot: AssetSnapshot) -> dict:
    return {
        "ip": snapshot.ip,
        "hostnames": snapshot.hostnames,
        "domains": snapshot.domains,
        "org": snapshot.org,
        "isp": snapshot.isp,
        "os": snapshot.os,
        "city": snapshot.city,
        "country": snapshot.country,
        "services": [
            {
                "port": s.port,
                "transport": s.transport,
                "product": s.product,
                "version": s.version,
                "ssl_info": s.ssl_info,
                "ssh_info": s.ssh_info,
            }
            for s in snapshot.services
        ],
        "last_update": (
            snapshot.last_update.isoformat() if snapshot.last_update else None
        ),
        "open_ports": snapshot.open_ports,
        "raw_banner": snapshot.raw_banner,
    }
