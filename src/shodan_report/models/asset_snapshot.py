from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime
from .service import Service

@dataclass
class AssetSnapshot:
    ip: str
    hostnames: List[str]
    domains: List[str]

    org: str
    isp: str
    os: Optional[str]

    city: str
    country: str
    services: List[Service] = field(default_factory=list)

    last_update: Optional[datetime] = None

    open_ports: List[int] = field(default_factory=list)

    #Optinal
    raw_banner: List[str] = field(default_factory=list)
    ssl_info: Optional[dict] = None
    ssh_info: Optional[dict] = None 