from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor
from typing import Dict

def _create_styles(primary_hex: str, secondary_hex: str) -> Dict[str, ParagraphStyle]:

    styles = getSampleStyleSheet()
    
    return {
        'title': ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=16,
            textColor=HexColor(primary_hex),
            spaceAfter=12,
            alignment=1
        ),
        'heading1': ParagraphStyle(
            'CustomHeading1',
            parent=styles['Heading1'],
            fontSize=12,
            textColor=HexColor(primary_hex),
            spaceBefore=16,
            spaceAfter=8,
            leftIndent=0,
            borderPadding=(0, 0, 0, 6),
            borderColor=HexColor(primary_hex),
            borderWidth=(0, 0, 1, 0)
        ),
        'heading2': ParagraphStyle(
            'CustomHeading2',
            parent=styles['Heading2'],
            fontSize=11,  # Etwas kleiner
            textColor=HexColor(secondary_hex),
            spaceBefore=12,
            spaceAfter=6,
            leftIndent=0
        ),
        'normal': ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            spaceAfter=3
        ),
        'bullet': ParagraphStyle(
            'CustomBullet',
            parent=styles['Normal'],
            fontSize=10,
            leftIndent=20,
            firstLineIndent=-10,
            spaceAfter=2,
            bulletIndent=10
        ),
        'disclaimer': ParagraphStyle(
            'Disclaimer',
            parent=styles['Normal'],
            fontSize=7,
            textColor='gray',
            alignment=1,
            leading=10,
            spaceBefore=12,
            spaceAfter=6
        ),
        'footer': ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor='darkgray',
            alignment=1,
            leading=10
        )
    }
create_styles = _create_styles # Alias 