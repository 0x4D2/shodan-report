"""
Credential Exposure Section.

Zeigt HIBP-Ergebnisse im Report:
  - API-Modus: echte Breach-Counts + Namen
  - Manual-Modus: Check-Links für manuelle Prüfung

Wird nur gerendert wenn technical_json["hibp"] vorhanden ist.
"""

from typing import Any, Dict, List
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor


_C_RED_BG   = HexColor("#FEF2F2")
_C_RED_BD   = HexColor("#FECACA")
_C_RED_BAR  = HexColor("#DC2626")
_C_AMB_BG   = HexColor("#FFFBEB")
_C_AMB_BD   = HexColor("#F59E0B")
_C_AMB_BAR  = HexColor("#F59E0B")
_C_GRY_BG   = HexColor("#F8F8F8")
_C_BORDER   = HexColor("#DDDDDD")


def create_credential_exposure_section(
    elements: List[Any],
    styles: Dict[str, Any],
    technical_json: Dict[str, Any],
    has_ssh: bool = False,
) -> None:
    hibp = technical_json.get("hibp")
    if not hibp:
        return

    ns = styles.get("normal") or styles.get("Normal")
    mode   = hibp.get("mode", "manual")
    emails = hibp.get("emails") or []
    total_breached = hibp.get("total_breached")

    if not emails:
        return

    elements.append(Spacer(1, 10))

    # Titelzeile
    elements.append(Paragraph(
        '<font size="9" color="#1A1A1A"><b>Credential Exposure</b></font>'
        '<font size="8" color="#888888"> — stichprobenbasierte Pr\xfcfung bekannter Datenlecks (HIBP)</font>',
        ns,
    ))
    elements.append(Spacer(1, 6))

    if mode == "api":
        _render_api_results(elements, styles, emails, total_breached, has_ssh)
    else:
        _render_manual_links(elements, styles, emails, has_ssh)


def _render_api_results(
    elements, styles, emails, total_breached, has_ssh
):
    ns = styles.get("normal") or styles.get("Normal")
    breached = [e for e in emails if e.get("breached")]
    clean    = [e for e in emails if e.get("breached") is False]

    # Kombinations-Warnung SSH + Credentials
    if has_ssh and breached:
        _combo_warning(elements, styles, len(breached))

    # Tabelle
    rows = [[
        Paragraph('<font size="8" color="#666666"><b>E-MAIL</b></font>', ns),
        Paragraph('<font size="8" color="#666666"><b>STATUS</b></font>', ns),
        Paragraph('<font size="8" color="#666666"><b>BREACHES</b></font>', ns),
    ]]

    for e in emails:
        if e.get("breached"):
            status_txt = '<font size="8" color="#DC2626"><b>BETROFFEN</b></font>'
            names = ", ".join((e.get("breach_names") or [])[:4])
            if len(e.get("breach_names") or []) > 4:
                names += f" +{len(e['breach_names']) - 4}"
            breach_txt = f'<font size="8" color="#991b1b">{names}</font>' if names else "—"
        elif e.get("breached") is False:
            status_txt = '<font size="8" color="#166534"><b>CLEAN</b></font>'
            breach_txt = '<font size="8" color="#888888">—</font>'
        else:
            status_txt = '<font size="8" color="#888888">n/a</font>'
            breach_txt = '<font size="8" color="#888888">—</font>'

        rows.append([
            Paragraph(f'<font size="8" color="#333333">{e["email"]}</font>', ns),
            Paragraph(status_txt, ns),
            Paragraph(breach_txt, ns),
        ])

    tbl = Table(rows, colWidths=[70 * mm, 28 * mm, 77 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), _C_GRY_BG),
        ("BOX",           (0, 0), (-1, -1), 0.5, _C_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, _C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(tbl)

    # Fußnote
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        '<font size="7" color="#888888">'
        'Quelle: HaveIBeenPwned.com · Stichprobe: Standard-Adressen + konfigurierte Adressen · '
        'Kein vollst\xe4ndiger Domain-Scan.'
        '</font>',
        ns,
    ))


def _render_manual_links(elements, styles, emails, has_ssh):
    ns = styles.get("normal") or styles.get("Normal")

    # Amber-Box: manuelle Prüfung empfohlen
    lines = [
        '<font size="8" color="#92400e"><b>Manuelle Pr\xfcfung empfohlen</b></font><br/>'
        '<font size="8" color="#78350f">'
        'Kein HIBP_API_KEY gesetzt — folgende Adressen bitte manuell pr\xfcfen:'
        '</font>',
    ]
    for e in emails:
        url = e.get("check_url", "")
        addr = e.get("email", "")
        lines.append(
            f'<font size="8" color="#1d4ed8">→ <a href="{url}">{addr}</a></font>'
        )

    if has_ssh:
        lines.append(
            '<font size="8" color="#7f1d1d"><b>'
            'Hinweis: SSH (Port 22) offen — bei betroffenen Credentials ist der Angriffspfad direkt ausnutzbar.'
            '</b></font>'
        )

    content = "<br/>".join(lines)
    box = Table([[Paragraph(content, ns)]], colWidths=[175 * mm])
    box.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _C_AMB_BG),
        ("BOX",           (0, 0), (-1, -1), 0.5, _C_AMB_BD),
        ("LINEBEFORE",    (0, 0), (0, -1),  4,   _C_AMB_BAR),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    elements.append(box)

    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        '<font size="7" color="#888888">'
        'Quelle: HaveIBeenPwned.com · HIBP_API_KEY in .env setzen f\xfcr automatische Pr\xfcfung.'
        '</font>',
        ns,
    ))


def _combo_warning(elements, styles, breached_count):
    ns = styles.get("normal") or styles.get("Normal")
    box = Table([[Paragraph(
        f'<font size="8" color="#7f1d1d"><b>'
        f'Kritische Kombination: SSH offen + {breached_count} betroffene Adresse(n) in bekannten Datenlecks'
        f'</b></font><br/>'
        '<font size="8" color="#991b1b">'
        'Angriffspfad direkt ausnutzbar: bekannte Credentials + direkter SSH-Zugang = sofortiger Handlungsbedarf.'
        '</font>',
        ns,
    )]], colWidths=[175 * mm])
    box.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _C_RED_BG),
        ("BOX",           (0, 0), (-1, -1), 0.5, _C_RED_BD),
        ("LINEBEFORE",    (0, 0), (0, -1),  4,   _C_RED_BAR),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    elements.append(box)
    elements.append(Spacer(1, 6))
