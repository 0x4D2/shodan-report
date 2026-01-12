"""
CVE- & Exploit-Übersicht für PDF-Reports - KOMPAKTE VERSION für One-Page Design.
"""

import re
from typing import List, Dict, Any, Optional
from reportlab.platypus import Spacer, Paragraph, Table, TableStyle, KeepTogether
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle


def create_cve_overview_section(
    elements: List, 
    styles: Dict,
    technical_json: Dict[str, Any],
    evaluation: Optional[Dict[str, Any]] = None
) -> None:
    """
    Erstelle KOMPAKTE CVE-Übersicht Section für One-Page Design.
    
    Args:
        elements: Liste der PDF-Elemente
        styles: Dictionary mit PDF-Styles
        technical_json: Technische Daten mit CVEs
        evaluation: Optional - Evaluation Ergebnisse
    """
    # Weniger Abstand für kompaktes Design
    elements.append(Spacer(1, 8))
    elements.append(Paragraph("5. CVE-ÜBERSICHT", styles['heading2']))
    elements.append(Spacer(1, 4))
    
    # Extrahiere CVE-Daten
    cve_data = _extract_cve_data(technical_json)
    
    if not cve_data:
        # Minimal "Keine CVEs" Darstellung
        elements.append(Paragraph(
            "✓ Keine kritischen CVEs identifiziert",
            styles['normal']
        ))
        return
    
    # 1. RISIKO-ÜBERSICHT (kompakte farbige Boxen)
    _create_risk_overview(elements, styles, cve_data)
    
    # 2. TOP-RISIKEN Tabelle (kompakt, farbcodiert)
    _create_compact_cve_table(elements, styles, cve_data)
    
    # 3. EXPLOIT STATUS (einzeilig)
    _create_exploit_summary(elements, styles, cve_data)


def _extract_cve_data(technical_json: Dict[str, Any]) -> List[Dict]:
    """Extrahiert CVE-Daten aus technical_json."""
    cve_data = []
    vulnerabilities = technical_json.get('vulnerabilities', [])
    
    if isinstance(vulnerabilities, list):
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                cve_id = vuln.get('id') or vuln.get('cve_id') or vuln.get('cve', 'Unknown')
                cvss_score = vuln.get('cvss') or vuln.get('score') or vuln.get('cvss_score') or 0
                
                cve_data.append({
                    'id': str(cve_id),
                    'cvss': float(cvss_score) if str(cvss_score).replace('.', '', 1).isdigit() else 0,
                    'service': vuln.get('service', vuln.get('product', 'Various'))[:20],  # Kürzer
                    'summary': vuln.get('summary', vuln.get('description', ''))[:50],  # Kürzer
                    'exploit_status': vuln.get('exploit_status', 'unknown')
                })
                
            elif isinstance(vuln, str):
                # String CVE-ID
                year_match = re.search(r'CVE-(\d{4})', vuln)
                cvss_estimate = 6.0 if year_match and int(year_match.group(1)) >= 2023 else 4.0
                
                cve_data.append({
                    'id': vuln,
                    'cvss': cvss_estimate,
                    'service': 'Multiple',
                    'summary': 'CVE detected',
                    'exploit_status': 'unknown'
                })
    
    return cve_data


def _create_risk_overview(elements: List, styles: Dict, cve_data: List[Dict]) -> None:
    """Erstelle kompakte Risiko-Übersicht mit farbigen Boxen."""
    
    # Zähle CVEs nach Risiko-Level
    critical = [c for c in cve_data if c.get('cvss', 0) >= 9.0]
    high = [c for c in cve_data if 7.0 <= c.get('cvss', 0) < 9.0]
    medium = [c for c in cve_data if 4.0 <= c.get('cvss', 0) < 7.0]
    low = [c for c in cve_data if c.get('cvss', 0) < 4.0]
    
    # Farbdefinitionen
    color_critical = colors.HexColor('#dc2626')  # Rot
    color_high = colors.HexColor('#f97316')      # Orange
    color_medium = colors.HexColor('#eab308')    # Gelb
    color_low = colors.HexColor('#16a34a')       # Grün
    
    # Kompakte Tabelle für Risiko-Boxen
    table_data = [
        [
            _create_risk_cell("KRITISCH", len(critical), color_critical),
            _create_risk_cell("HOCH", len(high), color_high),
            _create_risk_cell("MEDIUM", len(medium), color_medium),
            _create_risk_cell("NIEDRIG", len(low), color_low),
        ]
    ]
    
    table = Table(table_data, colWidths=[45, 45, 45, 45])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), color_critical),
        ('BACKGROUND', (1, 0), (1, 0), color_high),
        ('BACKGROUND', (2, 0), (2, 0), color_medium),
        ('BACKGROUND', (3, 0), (3, 0), color_low),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGNMENT', (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('PADDING', (0, 0), (-1, 0), (6, 4)),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    
    elements.append(table)
    elements.append(Spacer(1, 6))


def _create_risk_cell(label: str, count: int, color) -> Paragraph:
    """Erstelle eine Risiko-Zelle für die Übersicht."""
    text = f"<b>{label}<br/>{count}</b>"
    return Paragraph(text, style=ParagraphStyle(
        'RiskCell',
        alignment=1,  # Center
        textColor=colors.white,
        fontSize=9,
        leading=11,
        spaceBefore=0,
        spaceAfter=0
    ))


def _create_compact_cve_table(elements: List, styles: Dict, cve_data: List[Dict]) -> None:
    """Erstelle kompakte CVE-Tabelle mit Farbcodierung."""
    
    # Sortiere nach CVSS (höchste zuerst) und nehme nur Top 8
    sorted_cves = sorted(cve_data, key=lambda x: x.get('cvss', 0), reverse=True)[:8]
    
    if not sorted_cves:
        return
    
    # Tabellen-Header (kompakt)
    table_data = [
        [
            Paragraph('<b>CVE ID</b>', styles['normal']),
            Paragraph('<b>CVSS</b>', styles['normal']),
            Paragraph('<b>Service</b>', styles['normal']),
            Paragraph('<b>Exploit</b>', styles['normal'])
        ]
    ]
    
    # Datenzeilen mit Farbcodierung
    for cve in sorted_cves:
        cvss = cve.get('cvss', 0)
        
        # Bestimme Farbe basierend auf CVSS
        if cvss >= 9.0:
            bg_color = colors.HexColor('#fee2e2')  # Hellrot
            text_color = colors.HexColor('#991b1b')
        elif cvss >= 7.0:
            bg_color = colors.HexColor('#ffedd5')  # Hellorange
            text_color = colors.HexColor('#9a3412')
        elif cvss >= 4.0:
            bg_color = colors.HexColor('#fef9c3')  # Hellgelb
            text_color = colors.HexColor('#854d0e')
        else:
            bg_color = colors.HexColor('#dcfce7')  # Hellgrün
            text_color = colors.HexColor('#166534')
        
        # Exploit Status Icon
        exploit_status = cve.get('exploit_status', 'unknown')
        exploit_icon = {
            'public': '🔴',
            'private': '🟡', 
            'none': '🟢',
            'unknown': '⚪'
        }.get(exploit_status, '⚪')
        
        # Zellen mit minimalem Inhalt
        table_data.append([
            Paragraph(f"<font color='{text_color.hexval()}'>{cve['id']}</font>", 
                     styles['normal']),
            Paragraph(f"<font color='{text_color.hexval()}'><b>{cvss}</b></font>", 
                     styles['normal']),
            Paragraph(f"<font color='{text_color.hexval()}'>{cve['service']}</font>", 
                     styles['normal']),
            Paragraph(exploit_icon, styles['normal'])
        ])
    
    # Tabelle erstellen (sehr schmale Spalten)
    col_widths = [40, 20, 35, 15]  # mm statt Punkte für bessere Kontrolle
    
    table = Table(table_data, colWidths=col_widths, repeatRows=1)
    
    # Styling für kompakte Tabelle
    table_style = TableStyle([
        # Header
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#374151')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8),
        
        # Grid
        ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
        ('PADDING', (0, 0), (-1, -1), (2, 1)),  # Minimal padding
        
        # Zeilen-Hintergrund für bessere Lesbarkeit
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9fafb')]),
        
        # Alignment
        ('ALIGNMENT', (1, 1), (1, -1), 'CENTER'),  # CVSS zentrieren
        ('ALIGNMENT', (3, 1), (3, -1), 'CENTER'),  # Exploit Icon zentrieren
    ])
    
    # Individuelle Zellen-Hintergründe für CVEs
    for i, cve in enumerate(sorted_cves, start=1):  # i=1 wegen Header
        cvss = cve.get('cvss', 0)
        if cvss >= 9.0:
            table_style.add('BACKGROUND', (0, i), (-1, i), colors.HexColor('#fee2e2'))
        elif cvss >= 7.0:
            table_style.add('BACKGROUND', (0, i), (-1, i), colors.HexColor('#ffedd5'))
        elif cvss >= 4.0:
            table_style.add('BACKGROUND', (0, i), (-1, i), colors.HexColor('#fef9c3'))
    
    table.setStyle(table_style)
    elements.append(table)
    elements.append(Spacer(1, 4))
    
    # Hinweis für viele CVEs (kompakt)
    total_cves = len(cve_data)
    if total_cves > 8:
        elements.append(Paragraph(
            f"<i>... und {total_cves - 8} weitere CVEs</i>",
            ParagraphStyle(
                'SmallItalic',
                parent=styles['normal'],
                fontSize=7,
                textColor=colors.grey
            )
        ))


def _create_exploit_summary(elements: List, styles: Dict, cve_data: List[Dict]) -> None:
    """Erstelle kompakte Exploit-Zusammenfassung."""
    
    # Zähle Exploit-Status
    exploit_counts = {
        'public': 0,
        'private': 0,
        'none': 0,
        'unknown': 0
    }
    
    for cve in cve_data:
        status = cve.get('exploit_status', 'unknown')
        if status in exploit_counts:
            exploit_counts[status] += 1
    
    # Kompakte einzeilige Darstellung
    summary_parts = []
    if exploit_counts['public'] > 0:
        summary_parts.append(f"🔴 {exploit_counts['public']} public")
    if exploit_counts['private'] > 0:
        summary_parts.append(f"🟡 {exploit_counts['private']} private")
    if exploit_counts['none'] > 0:
        summary_parts.append(f"🟢 {exploit_counts['none']} none")
    if exploit_counts['unknown'] > 0:
        summary_parts.append(f"⚪ {exploit_counts['unknown']} unknown")
    
    if summary_parts:
        elements.append(Paragraph(
            f"<b>Exploits:</b> {' | '.join(summary_parts)}",
            ParagraphStyle(
                'SmallSummary',
                parent=styles['normal'],
                fontSize=8,
                textColor=colors.HexColor('#4b5563')
            )
        ))