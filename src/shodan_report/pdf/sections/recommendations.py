"""
Priorisierte Handlungsempfehlungen für PDF-Reports.
"""

from typing import List, Dict
from reportlab.platypus import Spacer, Paragraph, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import mm
from .data.recommendations_data import prepare_recommendations_data
from shodan_report.pdf.layout import keep_section


# ── Farben ───────────────────────────────────────────────────────────────────
COLOR_P1_BG     = colors.HexColor("#FDECEA")   # hellrot
COLOR_P1_BORDER = colors.HexColor("#C0392B")   # dunkelrot
COLOR_P1_TEXT   = colors.HexColor("#C0392B")

COLOR_P2_BG     = colors.HexColor("#FEF3E8")   # hellorange
COLOR_P2_BORDER = colors.HexColor("#E67E22")   # orange
COLOR_P2_TEXT   = colors.HexColor("#E67E22")

COLOR_P3_BG     = colors.HexColor("#F4F8F4")   # hellgrün
COLOR_P3_BORDER = colors.HexColor("#27AE60")   # grün
COLOR_P3_TEXT   = colors.HexColor("#27AE60")

# A4 − 2 × 2 cm Seitenränder = nutzbarer Inhaltsbereich
_CONTENT_W = 170 * mm


def _hex(c: colors.Color) -> str:
    """Gibt Hex-String ohne # zurück, für ReportLab font-color tags."""
    r = int(c.red * 255)
    g = int(c.green * 255)
    b = int(c.blue * 255)
    return f"{r:02X}{g:02X}{b:02X}"


def _priority_badge(label: str, bg: colors.Color, border: colors.Color,
                    text_color: colors.Color, styles: Dict) -> Table:
    """Erstellt ein farbiges Badge für Prioritäts-Header."""
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase.pdfmetrics import stringWidth
    badge_style = ParagraphStyle(
        "BadgeLabel",
        parent=styles["normal"],
        fontSize=8,
        leading=11,
    )
    para = Paragraph(
        f'<font color="#{_hex(text_color)}"><b>{label}</b></font>',
        badge_style,
    )
    # Breite exakt auf den Text zuschneiden – immer einzeilig
    badge_w = stringWidth(label, "Helvetica-Bold", 8) + 20  # 8+8 padding + 4 Puffer
    tbl = Table([[para]], colWidths=[badge_w])
    tbl.hAlign = "LEFT"
    tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, -1), bg),
        ("BOX",            (0, 0), (-1, -1), 0.8, border),
        ("TOPPADDING",     (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 3),
        ("LEFTPADDING",    (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 8),
        ("ROUNDEDCORNERS", [4]),
    ]))
    return tbl


def _item_row(text: str, stripe_color: colors.Color, styles: Dict) -> Table:
    """Bullet-Zeile mit linkem farbigem Akzentstreifen."""
    para = Paragraph(text, styles["bullet"])
    tbl = Table(
        [["", para]],
        colWidths=[3, _CONTENT_W - 3],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, 0), stripe_color),
        ("BACKGROUND",    (1, 0), (1, 0), colors.white),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (1, 0), (1, 0), 10),
        ("RIGHTPADDING",  (1, 0), (1, 0), 4),
        ("LEFTPADDING",   (0, 0), (0, 0), 0),
        ("RIGHTPADDING",  (0, 0), (0, 0), 0),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.3, colors.HexColor("#F0F0F0")),
    ]))
    return tbl


def _has_rdp(tech_json: Dict) -> bool:
    """Prüft ob RDP (Port 3389) in den technischen Daten vorhanden ist."""
    try:
        services = tech_json.get("services") or tech_json.get("open_ports") or []
        for s in services:
            if isinstance(s, dict):
                port = s.get("port")
                prod = (s.get("product") or "").lower()
            else:
                port = getattr(s, "port", None)
                prod = (getattr(s, "product", "") or "").lower()
            if port == 3389 or "rdp" in prod:
                return True
    except Exception:
        pass
    return False


def create_recommendations_section(elements: List, styles: Dict, *args, **kwargs) -> None:
    """Erstelle Section mit priorisierten Handlungsempfehlungen."""
    # Context / legacy DI
    if "context" in kwargs and kwargs.get("context") is not None:
        ctx = kwargs["context"]
        business_risk  = getattr(ctx, "business_risk", "MEDIUM")
        technical_json = getattr(ctx, "technical_json", {})
        evaluation     = getattr(ctx, "evaluation", {})
    else:
        business_risk  = kwargs.get("business_risk")
        technical_json = kwargs.get("technical_json", {})
        evaluation     = kwargs.get("evaluation", {})

    elements.append(keep_section([
        Paragraph("<b>2. Priorisierte Handlungsempfehlungen</b>", styles["heading1"]),
        Spacer(1, 12),
    ]))

    buckets = prepare_recommendations_data(technical_json, evaluation, business_risk)

    # ── PRIORITÄT 1 ──────────────────────────────────────────────────────────
    elements.append(_priority_badge(
        "Priorität 1 – Kritisch",
        COLOR_P1_BG, COLOR_P1_BORDER, COLOR_P1_TEXT, styles,
    ))
    elements.append(Spacer(1, 6))

    priority1_items = buckets.get("priority1", [])
    if priority1_items:
        for item in priority1_items:
            elements.append(_item_row(item, COLOR_P1_BORDER, styles))
            elements.append(Spacer(1, 2))
    else:
        if _has_rdp(technical_json):
            for line in [
                "Öffentlich erreichbarer Managementdienst: <b>RDP (Port 3389)</b>",
                "Maßnahme: Abschalten oder Zugriff ausschließlich über <b>VPN / RD-Gateway / Jump Host</b>",
                "Risiko: Server-Übernahme, Ransomware, laterale Bewegung",
            ]:
                elements.append(_item_row(line, COLOR_P1_BORDER, styles))
                elements.append(Spacer(1, 2))
        else:
            meta = buckets.get("meta", {}) or {}
            crit = meta.get("critical_cves", 0)
            tls_issues = meta.get("tls_issues", 0)
            if crit == 0 and tls_issues == 0:
                reason = "Keine Priorität-1-Maßnahmen aus OSINT ableitbar (keine kritischen CVEs/keine TLS-Schwachstellen in den Daten)."
            else:
                reason = "Keine Priorität-1-Maßnahmen aus OSINT ableitbar."
            elements.append(Paragraph(reason, styles["bullet"]))

    elements.append(Spacer(1, 12))

    # ── PRIORITÄT 2 ──────────────────────────────────────────────────────────
    elements.append(_priority_badge(
        "Priorität 2 – Spezifische Empfehlungen",
        COLOR_P2_BG, COLOR_P2_BORDER, COLOR_P2_TEXT, styles,
    ))
    elements.append(Spacer(1, 6))
    if buckets.get("priority2"):
        for item in buckets["priority2"]:
            elements.append(_item_row(item, COLOR_P2_BORDER, styles))
            elements.append(Spacer(1, 2))
    else:
        elements.append(Paragraph(
            "Keine spezifischen Maßnahmen aus OSINT ableitbar — Monitoring und Härtung gemäß Priorität 3.",
            styles["bullet"],
        ))
    elements.append(Spacer(1, 12))

    # ── PRIORITÄT 3 ──────────────────────────────────────────────────────────
    if buckets.get("priority3"):
        elements.append(_priority_badge(
            "Priorität 3 – Optional (Optimierung)",
            COLOR_P3_BG, COLOR_P3_BORDER, COLOR_P3_TEXT, styles,
        ))
        elements.append(Spacer(1, 6))
        for item in buckets["priority3"]:
            elements.append(_item_row(item, COLOR_P3_BORDER, styles))
            elements.append(Spacer(1, 2))


# ── Hilfsfunktionen (externe Nutzung) ────────────────────────────────────────

def _extract_risk_level(business_risk) -> str:
    """Extrahiert Risiko-Level aus verschiedenen Input-Formaten."""
    if isinstance(business_risk, dict):
        return str(business_risk.get("level", "MEDIUM"))
    elif isinstance(business_risk, str):
        return business_risk
    return str(business_risk)


def _extract_port(port_info):
    """Extrahiert Port-Nummer aus verschiedenen Formaten."""
    if isinstance(port_info, dict):
        return port_info.get("port")
    return port_info
