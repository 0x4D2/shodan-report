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
    # Pfad aus Kunden-Konfiguration: unterstütze sowohl `styling` als auch `assets`
    styling = config.get("styling", {}) or {}
    assets = config.get("assets", {}) or {}

    # Logo-Pfad: styling.logo_path bevorzugen, sonst assets.logo_path
    logo_path = styling.get("logo_path") or assets.get("logo_path")
    if not logo_path:
        return

    # Normalize path: allow relative paths from project root
    if not os.path.isabs(logo_path):
        logo_path = os.path.join(os.getcwd(), logo_path)

    if logo_path and os.path.exists(logo_path):
        try:
            # Width: styling.logo_width (cm) or assets.logo_width_cm
            if styling.get("logo_width") is not None:
                logo_width_cm = styling.get("logo_width")
            else:
                logo_width_cm = assets.get("logo_width_cm", 2.0)

            logo_width = float(logo_width_cm) * cm

            logo_position = (styling.get("logo_position") or assets.get("logo_position") or "center").upper()

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
