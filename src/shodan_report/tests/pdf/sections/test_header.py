# """
# Tests für die Header-Section mit Logo-Unterstützung - KORRIGIERTE VERSION.
# """

# import pytest
# from unittest.mock import Mock, patch, MagicMock, call
# import os
# import tempfile
# from datetime import datetime
# from pathlib import Path

# from reportlab.platypus import Paragraph, Spacer, Image
# from reportlab.lib.styles import ParagraphStyle

# from shodan_report.pdf.sections.header import (
#     create_header_section,
#     _generate_compact_report_id,
#     extract_assets_from_technical_data,
#     _create_header  # Legacy-Funktion
# )


# class TestHeaderSection:
#     """Tests für die neue Header-Section mit Logo-Unterstützung."""

#     def test_create_header_section_basic(self):
#         """Teste grundlegende Header-Erstellung ohne Config."""
#         elements = []
#         styles = {}

#         create_header_section(
#             elements=elements,
#             styles=styles,
#             customer_name="Testkunde GmbH",
#             month="2025-01",
#             ip="192.168.1.1",
#             config=None
#         )

#         assert len(elements) >= 4  # Titel + Metadaten + Trennlinie + Spacer
#         assert any(isinstance(elem, Paragraph) for elem in elements)

#     def test_create_header_with_styling_config(self):
#         """Teste Header mit Styling-Config."""
#         elements = []
#         styles = {}

#         config = {
#             "styling": {
#                 "primary_color": "#FF0000",
#                 "secondary_color": "#00FF00"
#             }
#         }

#         create_header_section(
#             elements=elements,
#             styles=styles,
#             customer_name="Testkunde",
#             month="2025-01",
#             ip="192.168.1.1",
#             config=config
#         )

#         assert len(elements) > 0
#         paragraphs = [e for e in elements if isinstance(e, Paragraph)]
#         assert len(paragraphs) >= 2

#     def test_logo_loading_success(self, tmp_path):
#         """Teste erfolgreiches Logo-Loading."""
#         # Mock Image komplett, da wir keine echten PNGs laden wollen
#         with patch('shodan_report.pdf.sections.header.Image') as mock_image_class:
#             mock_img_instance = MagicMock()
#             mock_image_class.return_value = mock_img_instance

#             elements = []
#             styles = {}

#             config = {
#                 "styling": {
#                     "logo_path": "/fake/path/logo.png",
#                     "logo_width": 2.5,
#                     "logo_position": "center"
#                 }
#             }

#             # Mock os.path.exists für diesen Test
#             with patch('os.path.exists', return_value=True):
#                 create_header_section(
#                     elements=elements,
#                     styles=styles,
#                     customer_name="Testkunde",
#                     month="2025-01",
#                     ip="192.168.1.1",
#                     config=config
#                 )

#             # Prüfe ob Image aufgerufen wurde
#             mock_image_class.assert_called_once()
#             # Prüfe ob Logo in elements hinzugefügt wurde
#             assert mock_img_instance in elements
#             # Prüfe ob Spacer nach Logo hinzugefügt wurde
#             assert any(isinstance(e, Spacer) for e in elements)

#     def test_logo_loading_file_not_found(self):
#         """Teste Logo-Loading wenn Datei nicht existiert."""
#         elements = []
#         styles = {}

#         config = {
#             "styling": {
#                 "logo_path": "non-existent-logo.png"
#             }
#         }

#         # Mock os.path.exists für konsistente Tests
#         with patch('os.path.exists', return_value=False):
#             # Mock print um Console-Ausgabe zu vermeiden
#             with patch('builtins.print'):
#                 create_header_section(
#                     elements=elements,
#                     styles=styles,
#                     customer_name="Testkunde",
#                     month="2025-01",
#                     ip="192.168.1.1",
#                     config=config
#                 )

#         # Header sollte trotzdem erstellt werden
#         assert len(elements) > 0

#     def test_logo_exception_handling(self):
#         """Teste Exception-Handling beim Logo-Loading."""
#         elements = []
#         styles = {}

#         config = {
#             "styling": {
#                 "logo_path": "test.png"
#             }
#         }

#         with patch('os.path.exists', return_value=True):
#             with patch('reportlab.platypus.Image', side_effect=Exception("Test-Exception")):
#                 # Statt print zu mocken, testen wir einfach dass keine Exception an den Aufrufer weitergegeben wird
#                 try:
#                     create_header_section(
#                         elements=elements,
#                         styles=styles,
#                         customer_name="Test",
#                         month="2025-01",
#                         ip="192.168.1.1",
#                         config=config
#                     )
#                     # Erfolg: Funktion hat trotz Exception nicht abgestürzt
#                     assert True
#                 except Exception as e:
#                     pytest.fail(f"Function should handle logo exceptions internally. Got: {e}")

#     def test_additional_assets_none(self):
#         """Teste Header mit additional_assets=None."""
#         elements = []
#         styles = {}

#         create_header_section(
#             elements=elements,
#             styles=styles,
#             customer_name="Test",
#             month="2025-01",
#             ip="192.168.1.1",
#             config={},
#             additional_assets=None  # Explizit None
#         )

#         assert len(elements) > 0

#     def test_logo_loading_invalid_position(self):
#         """Teste dass ungültige logo_position nicht zum Absturz führt."""
#         from unittest.mock import patch, MagicMock

#         elements = []
#         styles = {}

#         config = {
#             "styling": {
#                 "logo_path": "test.png",
#                 "logo_position": "invalid_position"  # Ungültiger Wert
#             }
#         }

#         # Mock nur das Dateisystem und die Bildverarbeitung
#         with patch('os.path.exists', return_value=True):
#             with patch('PIL.Image.open') as mock_pil_open:
#                 with patch('reportlab.platypus.Image') as mock_rl_image:
#                     # PIL Mock
#                     mock_pil_img = MagicMock()
#                     mock_pil_open.return_value = mock_pil_img

#                     # ReportLab Image Mock
#                     mock_rl_img_instance = MagicMock()
#                     mock_rl_image.return_value = mock_rl_img_instance

#                     # Führe Funktion aus - sollte nicht abstürzen!
#                     try:
#                         create_header_section(
#                             elements=elements,
#                             styles=styles,
#                             customer_name="Testkunde",
#                             month="2025-01",
#                             ip="192.168.1.1",
#                             config=config
#                         )
#                         # Erfolg!
#                         assert True
#                     except ValueError as e:
#                         # ValueError wäre ok, wenn ungültige Position abgefangen wird
#                         assert "logo_position" in str(e).lower()
#                     except Exception as e:
#                         # Jede andere Exception ist ein Fehler
#                         pytest.fail(f"Unexpected exception with invalid logo_position: {type(e).__name__}: {e}")

#     def test_generate_compact_report_id(self):
#         """Teste Report-ID Generierung."""
#         fixed_date = datetime(2026, 1, 12)

#         with patch('shodan_report.pdf.sections.header.datetime') as mock_datetime:
#             mock_datetime.now.return_value = fixed_date

#             test_cases = [
#                 {
#                     "customer": "CHINANET HUBEI",
#                     "month": "2026-01",
#                     "ip": "111.170.152.60",
#                     "expected": "CHI260106012",
#                     "explanation": "CHI (Kunde) + 2601 (Jan 2026) + 060 (IP .60) + 12 (Tag)"
#                 },
#                 {
#                     "customer": "Test Company",
#                     "month": "2025-12",
#                     "ip": "192.168.1.100",
#                     "expected": "TES251210012",
#                     "explanation": "TES (Kunde) + 2512 (Dez 2025) + 100 (IP .100) + 12 (Tag)"
#                 },
#                 {
#                     "customer": "A&B-Corp",
#                     "month": "2024-06",
#                     "ip": "10.0.0.1",
#                     "expected": "ABC240600112",
#                     "explanation": "ABC (Kunde) + 2406 (Jun 2024) + 001 (IP .1) + 12 (Tag)"
#                 },
#             ]

#             for test in test_cases:
#                 report_id = _generate_compact_report_id(
#                     test["customer"],
#                     test["month"],
#                     test["ip"]
#                 )

#                 # Debug-Ausgabe bei Fehler
#                 if report_id != test["expected"]:
#                     print(f"\n🔍 DEBUG für {test['customer']}:")
#                     print(f"  Eingabe: {test['customer']}, {test['month']}, {test['ip']}")
#                     print(f"  Erwartet: {test['expected']} ({test['explanation']})")
#                     print(f"  Erhalten: {report_id}")

#                     # Zerlege die ID zur Analyse
#                     if len(report_id) >= 11:
#                         print(f"  Analyse: {report_id[:3]} + {report_id[3:7]} + {report_id[7:10]} + {report_id[10:]}")

#                 assert report_id == test["expected"], (
#                     f"Für {test['customer']}, {test['month']}, {test['ip']}:\n"
#                     f"  Erwartet: {test['expected']} ({test['explanation']})\n"
#                     f"  Erhalten: {report_id}"
#                 )

#     def test_report_id_uniqueness_with_mocked_date(self):
#         """Teste dass Report-IDs bei unterschiedlichen Eingaben unterschiedlich sind."""
#         fixed_date = datetime(2026, 1, 12)

#         with patch('shodan_report.pdf.sections.header.datetime') as mock_datetime:
#             mock_datetime.now.return_value = fixed_date

#             # Testfälle mit Erwartungen
#             test_cases = [
#                 {
#                     "name": "Apple Jan .1",
#                     "customer": "Apple Inc",
#                     "month": "2025-01",
#                     "ip": "192.168.1.1",
#                     "expected_parts": ["APP", "2501", "001", "12"]
#                 },
#                 {
#                     "name": "Banana Jan .1",
#                     "customer": "Banana Corp",
#                     "month": "2025-01",
#                     "ip": "192.168.1.1",
#                     "expected_parts": ["BAN", "2501", "001", "12"]
#                 },
#                 {
#                     "name": "Apple Feb .1",
#                     "customer": "Apple Inc",
#                     "month": "2025-02",
#                     "ip": "192.168.1.1",
#                     "expected_parts": ["APP", "2502", "001", "12"]
#                 },
#                 {
#                     "name": "Apple Jan .2",
#                     "customer": "Apple Inc",
#                     "month": "2025-01",
#                     "ip": "192.168.1.2",
#                     "expected_parts": ["APP", "2501", "002", "12"]
#                 },
#             ]

#             results = []
#             for test in test_cases:
#                 report_id = _generate_compact_report_id(
#                     test["customer"],
#                     test["month"],
#                     test["ip"]
#                 )

#                 # Extrahiere die Teile zur Überprüfung
#                 if len(report_id) >= 11:
#                     parts = [
#                         report_id[:3],    # Kunden-Code
#                         report_id[3:7],   # Monats-Code
#                         report_id[7:10],  # IP-Code
#                         report_id[10:]    # Tag-Code
#                     ]

#                     assert parts == test["expected_parts"], (
#                         f"{test['name']}:\n"
#                         f"  Erwartet: {''.join(test['expected_parts'])} ({test['expected_parts']})\n"
#                         f"  Erhalten: {report_id} ({parts})"
#                     )

#                 results.append(report_id)

#             # Prüfe Eindeutigkeit
#             assert len(set(results)) == len(results), f"IDs nicht eindeutig: {results}"

#     def test_report_id_customer_code(self):
#         """Teste dass Kunden-Code korrekt extrahiert wird."""
#         test_cases = [
#             ("CHINANET HUBEI", "CHI"),
#             ("Test Company", "TES"),
#             ("A&B Corporation", "ABC"),
#             ("123 GmbH", "GMB"),
#             ("", "CST"),
#             ("ABC", "ABC"),
#             ("A B C D E", "ABC"),
#         ]

#         fixed_date = datetime(2026, 1, 12)
#         with patch('shodan_report.pdf.sections.header.datetime') as mock_datetime:
#             mock_datetime.now.return_value = fixed_date
#             mock_datetime.strptime = datetime.strptime
#             mock_datetime.strftime = datetime.strftime

#             for customer, expected_prefix in test_cases:
#                 report_id = _generate_compact_report_id(customer, "2025-01", "192.168.1.1")
#                 assert report_id.startswith(expected_prefix), f"Für {customer}: erwartet Prefix {expected_prefix}, got {report_id[:3]}"

#     def test_assets_counting(self):
#         """Teste Asset-Zählung in Metadaten-Zeile."""
#         elements = []
#         styles = {}

#         additional_assets = ["domain1.com", "domain2.com", "host1.example.com"]

#         create_header_section(
#             elements=elements,
#             styles=styles,
#             customer_name="Testkunde",
#             month="2025-01",
#             ip="192.168.1.1",
#             config={},
#             additional_assets=additional_assets
#         )

#         # Extrahiere Text aus Paragraphs
#         texts = []
#         for elem in elements:
#             if isinstance(elem, Paragraph):
#                 # Versuche Text zu extrahieren
#                 if hasattr(elem, 'text'):
#                     texts.append(elem.text)
#                 elif hasattr(elem, 'getPlainText'):
#                     texts.append(elem.getPlainText())

#         combined_text = ' '.join(texts)

#         # Prüfe ob Asset-Zahl irgendwo im Text vorkommt
#         # Entweder " +3" oder " +3 assets"
#         assert " +3" in combined_text or "+3" in combined_text

#     def test_month_formatting(self):
#         """Teste verschiedene Monatsformate."""
#         test_cases = [
#             ("2025-01", "Jan 2025"),
#             ("2025-12", "Dec 2025"),
#             ("invalid-month", "invalid-month"),  # Fallback
#             ("2025-13", "2025-13"),  # Ungültiger Monat
#         ]

#         for month_input, expected_in_text in test_cases:
#             elements = []
#             styles = {}

#             create_header_section(
#                 elements=elements,
#                 styles=styles,
#                 customer_name="Test",
#                 month=month_input,
#                 ip="192.168.1.1",
#                 config={}
#             )

#             assert len(elements) > 0

#     def test_config_without_styling_key(self):
#         """Teste Config ohne 'styling' Key."""
#         elements = []
#         styles = {}

#         config = {
#             "customer": {
#                 "name": "Testkunde",
#                 "contact": "test@example.com"
#             },
#             "report": {
#                 "include_trend_analysis": True
#             }
#         }

#         create_header_section(
#             elements=elements,
#             styles=styles,
#             customer_name="Testkunde",
#             month="2025-01",
#             ip="192.168.1.1",
#             config=config
#         )

#         assert len(elements) > 0

#     def test_legacy_function_compatibility(self):
#         """Teste dass die Legacy-Funktion noch funktioniert."""
#         elements = []
#         styles = {}

#         _create_header(
#             elements=elements,
#             styles=styles,
#             customer_name="Testkunde",
#             month="2025-01",
#             ip="192.168.1.1",
#             config={}
#         )

#         assert len(elements) > 0

#     def test_extract_assets_from_technical_data(self):
#         """Teste Asset-Extraktion aus technischen Daten."""
#         technical_json = {
#             "domains": ["example.com", "test.de"],
#             "hostnames": ["server1.example.com", "server2.example.com"],
#             "org": "Test ISP GmbH"
#         }

#         assets = extract_assets_from_technical_data(technical_json)

#         assert len(assets) == 5
#         assert "example.com (Domain)" in assets
#         assert "server1.example.com (Hostname)" in assets
#         assert "Test ISP GmbH (Organisation)" in assets

#     def test_extract_assets_empty(self):
#         """Teste Asset-Extraktion mit leeren Daten."""
#         technical_json = {}
#         assets = extract_assets_from_technical_data(technical_json)

#         assert assets == []

#     def test_extract_assets_limits(self):
#         """Teste dass Limits eingehalten werden."""
#         technical_json = {
#             "domains": ["d1.com", "d2.com", "d3.com", "d4.com"],
#             "hostnames": ["h1.com", "h2.com", "h3.com"],
#             "org": "Test Org"
#         }

#         assets = extract_assets_from_technical_data(technical_json)

#         domains = [a for a in assets if "(Domain)" in a]
#         hostnames = [a for a in assets if "(Hostname)" in a]

#         assert len(domains) == 3
#         assert len(hostnames) == 2
#         assert len(assets) == 6


# # Weitere Tests aus der ursprünglichen Datei (unverändert)
# # ...


# if __name__ == "__main__":
#     pytest.main([__file__, "-v", "--tb=short"])
