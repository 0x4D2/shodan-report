# src/shodan_report/utils/text_cleaner.py
"""
Text-Bereinigung für lesbare Reports.
Entfernt HTML, kürzt technische Details und formatiert für Management-Reports.
"""
import re
from typing import Optional, List


class ReportTextCleaner:
    """Klasse zur Bereinigung von technischen Texten für Reports."""

    @staticmethod
    def clean_html(text: str) -> str:
        """Entfernt HTML-Tags aus Text."""
        if not text:
            return ""
        return re.sub(r"<[^>]+>", "", text)

    @staticmethod
    def remove_http_headers(text: str) -> str:
        """Entfernt HTTP-Header-Zeilen."""
        if not text:
            return ""

        lines = text.split("\n")
        cleaned_lines = []

        http_header_prefixes = [
            "Date:",
            "Server:",
            "Content-Type:",
            "Content-Length:",
            "Connection:",
            "ETag:",
            "X-Powered-By:",
            "Vary:",
            "Last-Modified:",
            "Accept-Ranges:",
            "Transfer-Encoding:",
            "Location:",
            "Set-Cookie:",
            "Cache-Control:",
        ]

        for line in lines:
            line_stripped = line.strip()
            # Überspringe HTTP-Header
            if any(line_stripped.startswith(prefix) for prefix in http_header_prefixes):
                continue
            # Überspringe leere Zeilen
            if not line_stripped:
                continue
            cleaned_lines.append(line_stripped)

        return "\n".join(cleaned_lines)

    @staticmethod
    def extract_key_information(text: str) -> List[str]:
        """Extrahiert wichtige Informationen aus technischem Text."""
        if not text:
            return []

        important_parts = []

        # 1. Versionsnummern finden (v1.2.3, Version 1.0, Release 2024)
        version_patterns = [
            r"version[\s:]*([\d\.]+)",
            r"v[\s:]*([\d\.]+)",
            r"release[\s:]*([\d\.]+)",
            r"(\d+\.\d+(?:\.\d+)*)(?:\s+\(|$)",
        ]

        for pattern in version_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                version = match.group(1)
                if version not in important_parts:
                    important_parts.append(f"Version {version}")

        # 2. Port-Nummern finden (Port 9000, on port 8123)
        port_matches = re.finditer(r"port[\s:]*(\d{2,5})", text, re.IGNORECASE)
        for match in port_matches:
            port = match.group(1)
            if f"Port {port}" not in important_parts:
                important_parts.append(f"Port {port}")

        # 3. Wichtige Schlüsselwörter (Login, Error, Vulnerable, etc.)
        keywords = {
            "login": "Login erforderlich",
            "error": "Fehler",
            "vulnerable": "Anfällig",
            "insecure": "Unsicher",
            "deprecated": "Veraltet",
            "bad request": "Ungültige Anfrage",
            "required": "Erforderlich",
        }

        for keyword, translation in keywords.items():
            if re.search(rf"\b{keyword}\b", text, re.IGNORECASE):
                if translation not in important_parts:
                    important_parts.append(translation)

        # 4. Kurze, informative Ausschnitte (< 60 Zeichen)
        sentences = re.split(r"[.!?]+", text)
        for sentence in sentences:
            sentence = sentence.strip()
            if 10 < len(sentence) < 60:
                # Prüfe, ob es kein reiner Header oder Code ist
                if not any(
                    sentence.startswith(prefix)
                    for prefix in ["HTTP/", "GET ", "POST ", "{", "*"]
                ):
                    if sentence not in important_parts:
                        important_parts.append(sentence)

        return important_parts

    @classmethod
    def clean_banner_for_report(
        cls, banner_text: str, product_name: Optional[str] = None
    ) -> str:
        """
        Bereinigt Banner-Text für Management-Report.

        Args:
            banner_text: Roher Banner-Text von Shodan
            product_name: Optionaler Produktname (z.B. "ClickHouse")

        Returns:
            Bereinigter, lesbarer Text für Report
        """
        if not banner_text:
            return product_name or "Unbekannter Dienst"

        # Schritt 1: HTML entfernen
        cleaned = cls.clean_html(banner_text)

        # Schritt 2: HTTP-Header entfernen
        cleaned = cls.remove_http_headers(cleaned)

        # Schritt 3: Wichtige Informationen extrahieren
        important_info = cls.extract_key_information(cleaned)

        # Schritt 4: Ergebnis zusammenbauen
        if important_info:
            # Maximal 3 Informationen anzeigen
            display_info = important_info[:3]
            info_text = ", ".join(display_info)

            if product_name:
                return f"{product_name}: {info_text}"
            return info_text
        elif product_name:
            return product_name
        else:
            # Fallback: Erste Zeile kürzen
            first_line = cleaned.split("\n")[0] if "\n" in cleaned else cleaned
            if len(first_line) > 80:
                return first_line[:77] + "..."
            return first_line

    @classmethod
    def clean_critical_point(cls, point: str) -> str:
        """
        Bereinigt einen kritischen Punkt aus der Evaluation.

        Args:
            point: Kritischer Punkt z.B. "Veraltete/anfällige Version: ..."

        Returns:
            Bereinigter Text
        """
        if not point:
            return ""

        # Entferne Präfix "Veraltete/anfällige Version: " falls vorhanden
        cleaned = re.sub(r"^[^:]+:\s*", "", point)

        # Suche nach Produktnamen am Anfang
        product_match = re.match(
            r"^([A-Za-z0-9\.\s]+?)(?:\s+Version|\s+v\d|\s+on|\s+Port|$)", cleaned
        )
        product_name = product_match.group(1).strip() if product_match else None

        # Bereinige den Rest
        return cls.clean_banner_for_report(cleaned, product_name)


# Einfache Funktion für schnellen Zugriff
def clean_for_report(text: str, product: Optional[str] = None) -> str:
    """Einfache Wrapper-Funktion für schnelle Nutzung."""
    return ReportTextCleaner.clean_banner_for_report(text, product)
