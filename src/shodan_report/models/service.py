from dataclasses import dataclass, field
from typing import Optional
from typing import Optional, List, Dict


@dataclass
class Service:
    port: int
    transport: str  # tcp/upd
    product: Optional[str] = None
    version: Optional[str] = None

    ssl_info: Optional[dict] = None
    ssh_info: Optional[dict] = None

    # EXPLIZITE Flags
    is_encrypted: bool = False
    requires_auth: bool = False

    vulnerabilities: List[Dict] = field(default_factory=list)  # NEU

    # KEINE Annahmen!
    vpn_protected: bool = False  # nur true, wenn Quelle es sagt
    tunneled: bool = False  # nur true, wenn Quelle es sagt
    cert_required: bool = False  # nur true, wenn Quelle es sagt

    raw: Optional[dict] = None
