import re
import unicodedata


def create_slug(text: str, max_length: int = 50) -> str:

    if not text:
        return "unknown"

    text = unicodedata.normalize("NFKD", text)

    text = text.encode("ASCII", "ignore").decode("ASCII")

    text = re.sub(r"[^\w\s-]", "", text)

    text = text.lower()

    text = re.sub(r"[-\s]+", "_", text)

    text = text.strip("_")

    if max_length and len(text) > max_length:
        # Versuche bei Wortgrenzen zu schneiden (Unterstriche)
        if "_" in text:
            parts = text.split("_")
            result = parts[0]
            for part in parts[1:]:
                if len(result) + len(part) + 1 <= max_length:
                    result += "_" + part
                else:
                    break
            text = result
        else:
            # Auch für einzelne Wörter: bei Bindestrich oder Leerzeichen suchen
            # ODER wenigstens konsistent sein
            text = text[:max_length].rstrip("_-")  # Sauberer cut

    return text or "unknown"
