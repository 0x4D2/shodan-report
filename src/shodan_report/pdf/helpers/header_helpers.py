from datetime import datetime
import re
from typing import List, Optional
from reportlab.platypus import Image, Spacer
import os
from reportlab.lib.units import cm

# ──────────────
# Report-ID
# ──────────────
def generate_compact_report_id(customer_name: str, month: str, ip: str) -> str:
   # Format: <Kunde3><YYMM><IP3><DD>
    clean_name = re.sub(r"[^A-Za-z]", "", customer_name)
    customer_code = clean_name[:3].upper() if clean_name else "CST"

    month_code = month.replace("-", "")[-4:]

    ip_parts = ip.split(".")
    ip_code = ip_parts[-1].zfill(3) if len(ip_parts) == 4 else "000"

    day_code = datetime.now().strftime("%d")

    return f"{customer_code}{month_code}{ip_code}{day_code}"


# ──────────────
# Assets-Text kompakt
# ──────────────
def format_assets_text(ip: str, additional_assets: Optional[List[str]] = None) -> str:
    total_assets = 1 + (len(additional_assets) if additional_assets else 0)
    return ip if total_assets == 1 else f"{ip} +{total_assets - 1} assets"


# ──────────────
# Logo Helper
# ──────────────
def add_logo_to_elements(elements: list, config: dict) -> None:
    # Pfad asu Yaml
    styling = config.get("styling", {})

    logo_path = styling.get("logo_path")
    if logo_path and os.path.exists(logo_path):
        try:
            logo_width = styling.get("logo_width", 2.0) * cm
            logo_position = styling.get("logo_position", "center").upper()

            elements.append(
                Image(
                    logo_path,
                    width=logo_width,
                    height=logo_width * 0.25,  # 4:1 Ratio
                    hAlign=logo_position,
                )
            )
            elements.append(Spacer(1, 6))
        except Exception as e:
            print(f"⚠️ Logo konnte nicht geladen werden: {logo_path} – {e}")
