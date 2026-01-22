"""Methodik & Grenzen der Analyse (kompakt).

Nur die vereinbarten Bullet-Punkte werden hier ausgegeben.
"""

from typing import List, Dict, Any
from reportlab.platypus import Paragraph, Spacer


def create_methodology_section(elements: List[Any], styles: Dict[str, Any], *args, **kwargs) -> None:
    """Fügt die kompakte Methodik-Section mit vier Bullet-Punkten hinzu.

    Diese Funktion ändert nur lokale PDF-Elemente und führt keine I/O-Operationen
    außerhalb der PDF-Erzeugung durch.
    """

    elements.append(Spacer(1, 18))
    elements.append(Paragraph("6. Methodik & Grenzen der Analyse", styles.get("heading1") or styles.get("heading2") or styles.get("normal")))
    elements.append(Spacer(1, 8))

    bullets = [
        "Ausschließlich passive OSINT-Daten (keine aktiven Scans)",
        "Die Analyse stellt eine Momentaufnahme zum angegebenen Zeitpunkt dar",
        "Keine Garantie auf Vollständigkeit",
        "Keine Aussage über interne Systeme oder nicht öffentlich erreichbare Dienste",
        "Keine Simulation realer Angriffe",
    ]

    for b in bullets:
        elements.append(Paragraph(f"• {b}", styles.get("bullet") or styles.get("normal")))
        elements.append(Spacer(1, 6))
