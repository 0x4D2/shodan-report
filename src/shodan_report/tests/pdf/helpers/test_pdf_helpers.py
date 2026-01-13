# src/shodan_report/tests/pdf/helpers/test_pdf_helpers.py
import pytest
from reportlab.graphics.shapes import Drawing, Circle
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.colors import HexColor

from shodan_report.pdf.helpers.pdf_helpers import (
    build_horizontal_exposure_ampel,
    clone_style_with_color
)


class TestBuildHorizontalExposureAmpel:
    """Tests für build_horizontal_exposure_ampel Funktion."""
    
    def test_ampel_level_1_green(self):
        """Testet Ampel für Level 1 (nur grün leuchtend)."""
        drawing = build_horizontal_exposure_ampel(level=1)
        
        # Typ prüfen
        assert isinstance(drawing, Drawing)
        
        # Anzahl der Kreise prüfen (sollte 3 sein)
        circles = [obj for obj in drawing.contents if isinstance(obj, Circle)]
        assert len(circles) == 3
        
        # Farben prüfen: Nur erster Kreis sollte grün sein
        assert circles[0].fillColor == colors.HexColor("#22c55e")  # Green
        assert circles[1].fillColor == colors.HexColor("#d1d5db")  # Inactive
        assert circles[2].fillColor == colors.HexColor("#d1d5db")  # Inactive
    
    def test_ampel_level_2_green(self):
        """Testet Ampel für Level 2 (nur grün leuchtend)."""
        drawing = build_horizontal_exposure_ampel(level=2)
        circles = [obj for obj in drawing.contents if isinstance(obj, Circle)]
        
        assert circles[0].fillColor == colors.HexColor("#22c55e")  # Green
        assert circles[1].fillColor == colors.HexColor("#d1d5db")  # Inactive
        assert circles[2].fillColor == colors.HexColor("#d1d5db")  # Inactive
    
    def test_ampel_level_3_yellow(self):
        """Testet Ampel für Level 3 (nur gelb leuchtend)."""
        drawing = build_horizontal_exposure_ampel(level=3)
        circles = [obj for obj in drawing.contents if isinstance(obj, Circle)]
        
        assert circles[0].fillColor == colors.HexColor("#d1d5db")  # Inactive
        assert circles[1].fillColor == colors.HexColor("#f97316")  # Yellow
        assert circles[2].fillColor == colors.HexColor("#d1d5db")  # Inactive
    
    def test_ampel_level_4_red(self):
        """Testet Ampel für Level 4 (nur rot leuchtend)."""
        drawing = build_horizontal_exposure_ampel(level=4)
        circles = [obj for obj in drawing.contents if isinstance(obj, Circle)]
        
        assert circles[0].fillColor == colors.HexColor("#d1d5db")  # Inactive
        assert circles[1].fillColor == colors.HexColor("#d1d5db")  # Inactive
        assert circles[2].fillColor == colors.HexColor("#dc2626")  # Red
    
    def test_ampel_level_5_red(self):
        """Testet Ampel für Level 5 (nur rot leuchtend)."""
        drawing = build_horizontal_exposure_ampel(level=5)
        circles = [obj for obj in drawing.contents if isinstance(obj, Circle)]
        
        assert circles[0].fillColor == colors.HexColor("#d1d5db")  # Inactive
        assert circles[1].fillColor == colors.HexColor("#d1d5db")  # Inactive
        assert circles[2].fillColor == colors.HexColor("#dc2626")  # Red
    
    @pytest.mark.parametrize("level", [0, -1, 6, 100])
    def test_ampel_out_of_range_levels(self, level):
        """Testet Ampel mit Level außerhalb 1-5."""
        drawing = build_horizontal_exposure_ampel(level=level)
        circles = [obj for obj in drawing.contents if isinstance(obj, Circle)]
        
        # Prüfe je nach Level
        if level < 1:
            # Sollte wie Level 1 sein (grün)
            assert circles[0].fillColor == colors.HexColor("#22c55e")
            assert circles[1].fillColor == colors.HexColor("#d1d5db")
            assert circles[2].fillColor == colors.HexColor("#d1d5db")
        elif level > 5:
            # Sollte wie Level 5 sein (rot)
            assert circles[0].fillColor == colors.HexColor("#d1d5db")
            assert circles[1].fillColor == colors.HexColor("#d1d5db")
            assert circles[2].fillColor == colors.HexColor("#dc2626")
    
    def test_ampel_custom_dot_size(self):
        """Testet Ampel mit angepasster Dot-Größe."""
        custom_size = 5.0  # mm
        drawing = build_horizontal_exposure_ampel(level=3, dot_size_mm=custom_size)
        
        # Größe sollte proportional zur Dot-Größe sein
        expected_width = (custom_size * 3 + 1.8 * 2) * mm  # 3 Dots + 2 Abstände
        expected_height = custom_size * mm
        
        assert abs(drawing.width - expected_width) < 0.1 * mm
        assert abs(drawing.height - expected_height) < 0.1 * mm
    
    def test_ampel_custom_spacing(self):
        """Testet Ampel mit angepasstem Abstand."""
        custom_spacing = 3.0  # mm
        drawing = build_horizontal_exposure_ampel(level=2, spacing_mm=custom_spacing)
        
        # Breite sollte größer sein mit mehr Abstand
        assert drawing.width > 0
    
    def test_ampel_circle_positions(self):
        """Testet Positionierung der Kreise."""
        dot_size = 3.2
        spacing = 1.8
        drawing = build_horizontal_exposure_ampel(level=1, dot_size_mm=dot_size, spacing_mm=spacing)
        circles = [obj for obj in drawing.contents if isinstance(obj, Circle)]
        
        # Prüfe, dass wir 3 Kreise haben
        assert len(circles) == 3


class TestCloneStyleWithColor:
    """Tests für clone_style_with_color Funktion."""
    
    @pytest.fixture
    def base_style(self):
        """Erstellt einen Basis-Style für Tests."""
        base = getSampleStyleSheet()["Normal"]
        return ParagraphStyle(
            name="TestStyle",
            parent=base,
            fontSize=12,
            leading=14,
            textColor=HexColor("#000000"),
            spaceBefore=10,
            spaceAfter=10
        )
    
    def test_clone_style_basic(self, base_style):
        """Testet grundlegendes Klonen eines Styles."""
        new_color = "#FF5733"
        cloned_style = clone_style_with_color(base_style, new_color)
        
        # Name sollte geändert sein
        assert cloned_style.name == "TestStyle_colored"
        
        # TextColor sollte geändert sein
        assert cloned_style.textColor == HexColor(new_color)
        
        # Andere Attribute sollten gleich bleiben
        assert cloned_style.fontSize == base_style.fontSize
        assert cloned_style.leading == base_style.leading
        assert cloned_style.spaceBefore == base_style.spaceBefore
        assert cloned_style.spaceAfter == base_style.spaceAfter
    
    def test_clone_style_custom_suffix(self, base_style):
        """Testet Klonen mit benutzerdefiniertem Suffix."""
        new_color = "#33FF57"
        cloned_style = clone_style_with_color(base_style, new_color, "_custom")
        
        assert cloned_style.name == "TestStyle_custom"
        assert cloned_style.textColor == HexColor(new_color)
    
    def test_clone_style_no_suffix(self, base_style):
        """Testet Klonen ohne Suffix."""
        new_color = "#3357FF"
        cloned_style = clone_style_with_color(base_style, new_color, "")
        
        assert cloned_style.name == "TestStyle"
        assert cloned_style.textColor == HexColor(new_color)
    
    def test_clone_style_invalid_color(self, base_style):
        """Testet Klonen mit ungültiger Farbe."""
        invalid_color = "NOT_A_COLOR"
        
        # Sollte ValueError werfen
        with pytest.raises(ValueError):
            clone_style_with_color(base_style, invalid_color)
    
    def test_clone_style_empty_color(self, base_style):
        """Testet Klonen mit leerer Farbangabe."""
        # HexColor wirft ValueError bei leerem String
        with pytest.raises(ValueError):
            clone_style_with_color(base_style, "")
    
    def test_clone_style_hex_with_hash(self, base_style):
        """Testet Hex-Farben - nur mit # funktioniert."""
        color_with_hash = "#FF5733"
        
        # Mit # sollte funktionieren
        style = clone_style_with_color(base_style, color_with_hash)
        assert style.textColor == HexColor(color_with_hash)
        
        # Ohne # sollte ValueError werfen
        color_without_hash = "FF5733"
        with pytest.raises(ValueError):
            clone_style_with_color(base_style, color_without_hash)
    
    def test_clone_style_multiple_clones(self, base_style):
        """Testet mehrfaches Klonen vom gleichen Basis-Style."""
        colors = ["#FF0000", "#00FF00", "#0000FF"]
        cloned_styles = []
        
        for i, color in enumerate(colors):
            suffix = f"_clone{i}"
            cloned = clone_style_with_color(base_style, color, suffix)
            cloned_styles.append(cloned)
        
        # Alle Styles sollten unterschiedliche Namen haben
        names = [style.name for style in cloned_styles]
        assert len(set(names)) == len(names)
        
        # Alle sollten unterschiedliche Farben haben
        for i, style in enumerate(cloned_styles):
            assert style.textColor == HexColor(colors[i])
    
    def test_clone_style_uses_base_as_parent(self, base_style):
        """Testet, dass geklonter Style den Basis-Style als Parent verwendet."""
        cloned_style = clone_style_with_color(base_style, "#FF5733")
        
        # Der geklonte Style sollte den Basis-Style als Parent haben
        assert cloned_style.parent is base_style
        
        # Die Hierarchie ist:
        # cloned_style (TestStyle_colored) → base_style (TestStyle) → Normal
        assert cloned_style.name == "TestStyle_colored"
        assert cloned_style.parent.name == "TestStyle"
        assert cloned_style.parent.parent.name == "Normal"


# Integration Tests
class TestPDFHelpersIntegration:
    """Integrationstests für PDF-Helpers."""
    
    def test_ampel_and_style_together(self):
        """Testet kombinierte Verwendung von Ampel und Style-Klonen."""
        # Erstelle Ampel
        ampel = build_horizontal_exposure_ampel(level=3)
        
        # Erstelle Style
        base_style = ParagraphStyle(
            name="Base",
            fontSize=10,
            textColor=HexColor("#000000")
        )
        
        # Klone Style mit passender Farbe
        color_for_level_3 = "#f97316"  # Gelb für Level 3
        warning_style = clone_style_with_color(base_style, color_for_level_3, "_warning")
        
        # Validierung
        assert isinstance(ampel, Drawing)
        assert isinstance(warning_style, ParagraphStyle)
        assert warning_style.textColor == HexColor(color_for_level_3)