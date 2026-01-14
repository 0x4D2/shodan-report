from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.units import mm

import sys
from pathlib import Path

SRC = Path(__file__).parent.parent / 'reports' / 'MG_Solutions' / '2026-01_217.154.224.104_review.txt'
OUT = Path(__file__).parent.parent / 'reports' / 'MG_Solutions' / '2026-01_217.154.224.104_executive.pdf'

if not SRC.exists():
    print(f"Source review file not found: {SRC}")
    sys.exit(1)

text = SRC.read_text(encoding='utf-8')
# Take only the top part up to "---" to keep executive short
parts = text.split('\n---\n')
exec_text = parts[0] if parts else text

styles = getSampleStyleSheet()
styleN = styles['Normal']
styleH = styles['Heading1']

doc = SimpleDocTemplate(str(OUT), pagesize=A4,
                        leftMargin=20*mm, rightMargin=20*mm, topMargin=20*mm, bottomMargin=20*mm)
story = []

# Title
story.append(Paragraph('SICHERHEITSREPORT — Executive Summary', styleH))
story.append(Spacer(1, 6))

# Split lines and add paragraphs with small spacing
for line in exec_text.splitlines():
    if not line.strip():
        story.append(Spacer(1, 4))
        continue
    story.append(Paragraph(line.strip().replace('  ', '&nbsp;&nbsp;'), styleN))
    story.append(Spacer(1, 4))

try:
    doc.build(story)
    print(f"Created PDF: {OUT}")
except Exception as e:
    print("Failed to create PDF:", e)
    sys.exit(2)
