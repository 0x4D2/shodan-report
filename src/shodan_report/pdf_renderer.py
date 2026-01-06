from reportlab.platypus import SimpleDocTemplate
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from pathlib import Path

def render_pdf(output_path: Path, elements: list):
    
    try:
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm
        )
        doc.build(elements)
        print(f"PDF erfolgreich erstellt: {output_path}")
    except Exception as e:
        print(f"Fehler beim Erstellen der PDF: {e}")
        raise
