from dataclasses import dataclass, field
from typing import  Optional 


@dataclass
class Service:
    port: int
    transport: str # tcp/upd
    product: Optional[str] = None
    version: Optional[str] = None

    ssl_info: Optional[dict] = None
    ssh_info: Optional[dict] = None

    # Rohaten 
    raw: Optional[dict] = None