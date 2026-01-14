from pathlib import Path
from typing import Optional
from .pdf_manager import prepare_pdf_elements
from .pdf_renderer import render_pdf

OUTPUT_DIR = Path("./reports")


def generate_pdf(
    customer_name: str,
    month: str,
    ip: str,
    management_text: str,
    trend_text: str,
    technical_json: dict,
    evaluation: dict,
    business_risk: str,
    output_dir: Path = OUTPUT_DIR,
    config: Optional[dict] = None,
    compare_month: Optional[str] = None,
) -> Path:

    config = config or {}

    output_dir.mkdir(parents=True, exist_ok=True)
    customer_dir = output_dir / customer_name.replace(" ", "_")
    customer_dir.mkdir(parents=True, exist_ok=True)

    safe_ip = ip.replace("/", "_").replace(":", "_")
    filename = f"{month}_{safe_ip}.pdf"
    pdf_path = customer_dir / filename

    # Call `prepare_pdf_elements` with positional args to remain compatible with tests.
    if compare_month is None:
        elements = prepare_pdf_elements(
            customer_name,
            month,
            ip,
            management_text,
            trend_text,
            technical_json,
            evaluation,
            business_risk,
            config,
        )
    else:
        # pass compare_month as keyword-only parameter
        elements = prepare_pdf_elements(
            customer_name,
            month,
            ip,
            management_text,
            trend_text,
            technical_json,
            evaluation,
            business_risk,
            config,
            compare_month=compare_month,
        )
    render_pdf(pdf_path, elements)

    return pdf_path
