# src/shodan_report/tests/pdf/helpers/test_pdf_helpers.py
import pytest
from reportlab.graphics.shapes import Drawing, Circle
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.colors import HexColor

from shodan_report.pdf.helpers.pdf_helpers import (
    build_horizontal_exposure_ampel,
    clone_style_with_color,
)


class TestBuildHorizontalExposureAmpel:
    """Tests für build_horizontal_exposure_ampel Funktion."""

    def _circles(self, drawing):
        return [obj for obj in drawing.contents if isinstance(obj, Circle)]

    def test_ampel_returns_drawing(self):
        assert isinstance(build_horizontal_exposure_ampel(level=1), Drawing)

    def test_ampel_has_five_dots(self):
        """5 Dots insgesamt."""
        circles = self._circles(build_horizontal_exposure_ampel(level=3))
        assert len(circles) == 5

    def test_ampel_level_1(self):
        """Level 1: erster Dot grün, Rest grau."""
        c = self._circles(build_horizontal_exposure_ampel(level=1))
        assert c[0].fillColor == colors.HexColor("#22c55e")
        assert all(ci.fillColor == colors.HexColor("#d1d5db") for ci in c[1:])

    def test_ampel_level_2(self):
        """Level 2: zwei grüne Dots, Rest grau."""
        c = self._circles(build_horizontal_exposure_ampel(level=2))
        assert c[0].fillColor == colors.HexColor("#22c55e")
        assert c[1].fillColor == colors.HexColor("#22c55e")
        assert all(ci.fillColor == colors.HexColor("#d1d5db") for ci in c[2:])

    def test_ampel_level_3(self):
        """Level 3: ●●● (grün, grün, orange) + ○○ grau."""
        c = self._circles(build_horizontal_exposure_ampel(level=3))
        assert c[0].fillColor == colors.HexColor("#22c55e")
        assert c[1].fillColor == colors.HexColor("#22c55e")
        assert c[2].fillColor == colors.HexColor("#f97316")
        assert c[3].fillColor == colors.HexColor("#d1d5db")
        assert c[4].fillColor == colors.HexColor("#d1d5db")

    def test_ampel_level_4(self):
        """Level 4: ●●●● (grün, grün, orange, rot) + ○ grau."""
        c = self._circles(build_horizontal_exposure_ampel(level=4))
        assert c[0].fillColor == colors.HexColor("#22c55e")
        assert c[1].fillColor == colors.HexColor("#22c55e")
        assert c[2].fillColor == colors.HexColor("#f97316")
        assert c[3].fillColor == colors.HexColor("#dc2626")
        assert c[4].fillColor == colors.HexColor("#d1d5db")

    def test_ampel_level_5(self):
        """Level 5: alle 5 Dots aktiv."""
        c = self._circles(build_horizontal_exposure_ampel(level=5))
        assert c[0].fillColor == colors.HexColor("#22c55e")
        assert c[1].fillColor == colors.HexColor("#22c55e")
        assert c[2].fillColor == colors.HexColor("#f97316")
        assert c[3].fillColor == colors.HexColor("#dc2626")
        assert c[4].fillColor == colors.HexColor("#dc2626")

    @pytest.mark.parametrize("level", [0, -1, 6, 100])
    def test_ampel_out_of_range_levels(self, level):
        """Werte außerhalb 1–5 werden auf 1 bzw. 5 geclampt."""
        drawing = build_horizontal_exposure_ampel(level=level)
        circles = self._circles(drawing)
        assert len(circles) == 5
        if level < 1:
            assert circles[0].fillColor == colors.HexColor("#22c55e")
            assert all(ci.fillColor == colors.HexColor("#d1d5db") for ci in circles[1:])
        else:
            assert all(ci.fillColor != colors.HexColor("#d1d5db") for ci in circles)

    def test_ampel_custom_dot_size(self):
        """Breite skaliert mit Dot-Größe."""
        custom_size = 5.0
        drawing = build_horizontal_exposure_ampel(level=3, dot_size_mm=custom_size)
        expected_width = (custom_size * 5 + 1.8 * 4) * mm
        assert abs(drawing.width - expected_width) < 0.1 * mm
        assert abs(drawing.height - custom_size * mm) < 0.1 * mm

    def test_ampel_custom_spacing(self):
        """Größerer Abstand → größere Gesamtbreite."""
        d_small = build_horizontal_exposure_ampel(level=2, spacing_mm=1.0)
        d_large = build_horizontal_exposure_ampel(level=2, spacing_mm=4.0)
        assert d_large.width > d_small.width

    def test_ampel_circle_positions(self):
        """5 Kreise vorhanden."""
        circles = self._circles(build_horizontal_exposure_ampel(level=1))
        assert len(circles) == 5


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
            spaceAfter=10,
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
            name="Base", fontSize=10, textColor=HexColor("#000000")
        )

        # Klone Style mit passender Farbe
        color_for_level_3 = "#f97316"  # Gelb für Level 3
        warning_style = clone_style_with_color(
            base_style, color_for_level_3, "_warning"
        )

        # Validierung
        assert isinstance(ampel, Drawing)
        assert isinstance(warning_style, ParagraphStyle)
        assert warning_style.textColor == HexColor(color_for_level_3)
