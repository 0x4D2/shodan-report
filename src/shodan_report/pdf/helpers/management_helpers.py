from typing import List, Dict, Any, Union
from shodan_report.evaluation import RiskLevel, Evaluation
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.colors import HexColor
from reportlab.platypus import Table, TableStyle
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing, Circle
from reportlab.lib.units import mm


# ─────────────────────────────────────────────
# Exposure-Level Berechnung + Farbe
# ─────────────────────────────────────────────
def calculate_exposure_level(risk: Union[RiskLevel, str], critical_points: List[str]) -> int:
    """Berechne Exposure-Level 1-5 basierend auf Risiko & kritischen Punkten."""
    risk_to_exposure = {"low": 2, "medium": 3, "high": 4}
    risk_str = risk.value if hasattr(risk, "value") else str(risk)
    base_level = risk_to_exposure.get(risk_str.lower(), 2)
    
    critical_count = len(critical_points) if critical_points else 0
    if critical_count >= 3:
        return min(base_level + 1, 5)
    elif critical_count == 0:
        return max(base_level - 1, 1)
    else:
        return base_level


def get_exposure_color(level: int) -> str:
    """Farbe basierend auf Exposure-Level für Ampel."""
    if level >= 4:
        return "#dc2626"  # Rot
    elif level == 3:
        return "#f97316"  # Orange
    elif level == 2:
        return "#22c55e"  # Grün
    else:
        return "#16a34a"  # Dunkelgrün


def build_exposure_ampel(
    exposure_level: int,
    size_mm: int = 6,
):
    """
    Erzeugt eine kompakte Ampel (ein Kreis) für Exposure-Level.

    Level:
        1–2 → Grün
        3   → Gelb
        4–5 → Rot
    """

    if exposure_level >= 4:
        color = colors.HexColor("#dc2626")   # Rot
    elif exposure_level == 3:
        color = colors.HexColor("#f97316")   # Orange/Gelb
    else:
        color = colors.HexColor("#22c55e")   # Grün

    d = Drawing(size_mm * mm, size_mm * mm)
    d.add(
        Circle(
            size_mm * mm / 2,
            size_mm * mm / 2,
            size_mm * mm / 2,
            fillColor=color,
            strokeColor=color,
        )
    )

    return d

def build_horizontal_exposure_ampel(
    exposure_level: int,
    dot_size_mm: float = 3.2,
    spacing_mm: float = 1.8,
):
    """
    Horizontale Ampel mit 3 Punkten.
    Nur der aktive Punkt ist farbig, die anderen grau.
    """

    # Farben
    green = colors.HexColor("#22c55e")
    yellow = colors.HexColor("#f97316")
    red = colors.HexColor("#dc2626")
    inactive = colors.HexColor("#d1d5db")

    # Aktiv bestimmen
    if exposure_level >= 4:
        active = "red"
    elif exposure_level == 3:
        active = "yellow"
    else:
        active = "green"

    width = (dot_size_mm * 3 + spacing_mm * 2) * mm
    height = dot_size_mm * mm

    d = Drawing(width, height)

    colors_map = [
        green if active == "green" else inactive,
        yellow if active == "yellow" else inactive,
        red if active == "red" else inactive,
    ]

    for i, color in enumerate(colors_map):
        x = (dot_size_mm / 2 + i * (dot_size_mm + spacing_mm)) * mm
        y = (dot_size_mm / 2) * mm
        d.add(Circle(x, y, (dot_size_mm / 2) * mm, fillColor=color, strokeColor=color))

    return d


# ─────────────────────────────────────────────
# Textaufbereitung
# ─────────────────────────────────────────────
def extract_first_sentence(text: str) -> str:
    """Extrahiere den ersten Satz aus einem Text für Management-Kernaussage."""
    import re
    match = re.search(r"[^.!?]+[.!?]", text.strip())
    if match:
        return match.group(0).strip()
    return text[:100].strip() + ("..." if len(text) > 100 else "")


def extract_business_risk_level(business_risk_input) -> str:
    """Extrahiert Business Risk Level als String."""
    if isinstance(business_risk_input, dict):
        return str(business_risk_input.get('level', 'MEDIUM'))
    elif isinstance(business_risk_input, str):
        return business_risk_input
    else:
        return str(business_risk_input)


# ─────────────────────────────────────────────
# Insights generieren
# ─────────────────────────────────────────────
def generate_priority_insights(
    technical_json: Dict[str, Any],
    evaluation: Evaluation,
    business_risk: str
) -> List[str]:
    """Erstelle die 4 wichtigsten Erkenntnisse für Management."""
    insights = []

    # 1. Öffentliche Dienste
    open_ports = technical_json.get("open_ports", [])
    if open_ports:
        insights.append(f"{len(open_ports)} öffentliche Dienste erreichbar")

    # 2. Kritische CVEs
    vulnerabilities = technical_json.get("vulnerabilities", [])
    critical_cves = sum(1 for v in vulnerabilities if isinstance(v, dict) and v.get("cvss", 0) >= 9.0)
    insights.append(f"{critical_cves} kritische Schwachstellen" if critical_cves else "Keine kritischen Schwachstellen")

    # 3. Kritische Punkte
    critical_count = len(evaluation.critical_points) if evaluation.critical_points else 0
    if critical_count > 0:
        insights.append(f"{critical_count} kritische Risikopunkte")

    # 4. Business-Risk Check
    business_level = extract_business_risk_level(business_risk)
    if business_level.upper() in ["HIGH", "CRITICAL"]:
        insights.append("Erhöhter Handlungsbedarf")

    return insights[:4]  # Maximal 4 Insights


# ─────────────────────────────────────────────
# Empfehlungen generieren
# ─────────────────────────────────────────────
def generate_priority_recommendations(
    business_risk: str,
    technical_json: Dict[str, Any],
    evaluation: Evaluation
) -> List[str]:
    """Erstelle bis zu 3 Management-Empfehlungen."""
    recommendations = []

    base_recommendations = {
        "CRITICAL": ["Sofortige Notfallmaßnahmen einleiten", "Kritische Dienste temporär isolieren"],
        "HIGH": ["Priorisierte Maßnahmen innerhalb von 7 Tagen", "Kritische Konfigurationen überprüfen"],
        "MEDIUM": ["Geplante Maßnahmen innerhalb von 30 Tagen", "Regelmäßige Sicherheitsscans etablieren"],
        "LOW": ["Keine sofortigen Notfallmaßnahmen erforderlich", "Kurzfristig: Einzelne Konfigurationen optimieren"]
    }

    business_level = extract_business_risk_level(business_risk).upper()
    recommendations.extend(base_recommendations.get(business_level, [
        "Regelmäßige Überprüfung der Angriffsfläche", 
        "Proaktive Schwachstellenscans etablieren"
    ])[:2])

    # Spezifische Empfehlungen für SSH/RDP
    open_ports = technical_json.get("open_ports", [])
    for port_info in open_ports:
        port = port_info.get("port")
        product = port_info.get("product", "").lower()
        if port == 22 and "ssh" in product:
            recommendations.append("SSH: Schlüsselbasierte Authentifizierung erzwingen")
            break
        elif port == 3389 and "rdp" in product:
            recommendations.append("RDP: Netzwerk-Level-Authentifizierung aktivieren")
            break

    return recommendations[:3]  # Maximal 3 Empfehlungen

def clone_style_with_color(
    base_style: ParagraphStyle,
    text_color: str,
    name_suffix: str = "_colored",
) -> ParagraphStyle:
    """
    Klont einen bestehenden ParagraphStyle und setzt eine neue Textfarbe.
    Wichtig: verändert NICHT den Original-Style (PDF-safe).
    """
    return ParagraphStyle(
        name=f"{base_style.name}{name_suffix}",
        parent=base_style,
        textColor=HexColor(text_color),
    )