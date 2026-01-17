from pathlib import Path
from typing import Optional
import json
from .pdf_manager import prepare_pdf_elements
from .pdf_renderer import render_pdf
from .sections.data.management_data import prepare_management_data
from .sections.data.cve_enricher import enrich_cves
import re

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
        # build a structured trend_table from available technical/evaluation data
        try:
            # import locally to avoid circular-import issues
            from shodan_report.reporting.trend import _derive_trend_table

            trend_table = _derive_trend_table(technical_json or {}, evaluation)
        except Exception:
            trend_table = None

        # pass compare_month and trend_table as keyword-only parameters
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
            trend_table=trend_table,
        )
    render_pdf(pdf_path, elements)

    # --- Debug: dump canonical management data used for rendering ---
    try:
        mdata = prepare_management_data(technical_json, evaluation)
        enriched = enrich_cves(mdata.get("unique_cves", []), technical_json, lookup_nvd=False)
        # Build a compact `services` snapshot for sidecar; sanitize sensitive fields
        services_for_sidecar = []
        def _sanitize_sidecar_field(v, max_len=200):
            try:
                if v is None:
                    return None
                s_val = str(v).strip()
                s_val = s_val.replace("\n", " ").replace("\r", " ")
                s_val = re.sub(r"\s+", " ", s_val)
                # redact long base64-like sequences (SSH keys)
                if re.search(r"[A-Za-z0-9+/]{40,}=*", s_val):
                    return "[SSH-Key entfernt]"
                # remove IPv4-mapped IPv6 tokens like '::ffff:1.2.3.4'
                s_val = re.sub(r"::ffff:\d{1,3}(?:\.\d{1,3}){3}\s*", "", s_val)
                # compact typical FTP banner fragments to 'FTP'
                if "ftp" in s_val.lower():
                    return "FTP"
                if len(s_val) > max_len:
                    return s_val[: max_len - 3] + "..."
                return s_val
            except Exception:
                return None

        for s in (technical_json.get("services") or technical_json.get("open_ports") or []):
            try:
                if isinstance(s, dict):
                    services_for_sidecar.append({
                        "port": s.get("port"),
                        "product": _sanitize_sidecar_field(s.get("product") or s.get("service")),
                        "version": _sanitize_sidecar_field(s.get("version")),
                        "raw_banner": _sanitize_sidecar_field(s.get("banner") or s.get("extra_info")),
                    })
                else:
                    # object-like entries
                    services_for_sidecar.append({
                        "port": getattr(s, "port", None),
                        "raw_banner": _sanitize_sidecar_field(getattr(s, "banner", None)),
                    })
            except Exception:
                continue

        debug = {
            "pdf": str(pdf_path),
            "cve_count": mdata.get("cve_count"),
            "total_ports": mdata.get("total_ports"),
            "risk_level": mdata.get("risk_level"),
            "unique_cves_sample": mdata.get("unique_cves", [])[:200],
            "cve_enriched_sample": enriched[:200],
            "services": services_for_sidecar,
        }
        debug_json = json.dumps(debug, ensure_ascii=False, indent=2)
        print("[DEBUG-MANAGEMENT-DATA]", debug_json)

        # write debug JSON next to the PDF for offline inspection
        try:
            dbg_path = pdf_path.with_suffix("")
            dbg_file = pdf_path.parent / (pdf_path.stem + ".mdata.json")
            dbg_file.write_text(debug_json, encoding="utf-8")
        except Exception:
            # non-fatal: ignore file write errors but preserve console output
            pass
    except Exception as e:
        print(f"[DEBUG-MANAGEMENT-DATA] failed to prepare mdata: {e}")

    return pdf_path
