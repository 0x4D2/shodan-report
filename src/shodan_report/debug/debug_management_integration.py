# test_management_integration.py
import json
from shodan_report.pdf.sections.management import create_management_section

# Lade echte Shodan-Daten mit MySQL 8.0.33
with open("test_data_mysql.json", "r") as f:
    technical_json = json.load(f)

# Mock PDF-Elemente
elements = []
styles = {
    "heading1": None,
    "normal": None,
    "exposure": None,
    "bullet": None,
    "small": None,
}

# Test mit neuer Engine
create_management_section(
    elements=elements,
    styles=styles,
    management_text="Test Management Text",
    technical_json=technical_json,
    evaluation={},  # Leeres Dict (wird ignoriert)
    business_risk="HIGH",
)

# Überprüfe ob MySQL als kritisch erkannt wird
# (Müsste jetzt Exposure 5 und kritische Punkte zeigen)
