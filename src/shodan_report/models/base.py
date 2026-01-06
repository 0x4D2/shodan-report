from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

@dataclass
class BaseModel:
    """Basis-Dataclass für gemeinsame Felder aller Models."""
    last_update: Optional[datetime] = None
    raw: Optional[dict] = None
