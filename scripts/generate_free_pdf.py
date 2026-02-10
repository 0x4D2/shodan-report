import sys
from pathlib import Path
import json

root = Path(__file__).resolve().parents[1]
src_dir = root / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from shodan_report.pdf.pdf_manager import prepare_pdf_elements
from shodan_report.pdf.pdf_renderer import render_pdf
from shodan_report.pdf.sections.management import create_management_section
from shodan_report.pdf.sections.header import _create_header
from reportlab.platypus import Flowable


class BoxPlaceholder(Flowable):
    """Module-level placeholder used in skeleton view to indicate
    where non-heading content was located."""

    def __init__(self, width_pct=0.95, height=18):
        super().__init__()
        self.width_pct = width_pct
        self.height = height

    def wrap(self, availWidth, availHeight):
        return availWidth, self.height

    def draw(self):
        c = self.canv
        w = c._pagesize[0]
        box_w = w * self.width_pct
        x = (w - box_w) / 2.0
        y = 0
        c.saveState()
        c.setFillColorRGB(0.9, 0.9, 0.9)
        c.rect(x, y, box_w, self.height, fill=1, stroke=0)
        c.restoreState()


def header_wrapper(elements, styles, theme, context=None, **kwargs):
    # prepare_pdf_elements calls section callables with keyword args
    # including a `context` object — forward the needed values to the
    # existing header helper to avoid changing the PDF codebase.
    try:
        _create_header(
            elements=elements,
            styles=styles,
            theme=theme,
            customer_name=getattr(context, "customer_name", ""),
            month=getattr(context, "month", ""),
            ip=getattr(context, "ip", ""),
            config=getattr(context, "config", None),
        )
    except Exception:
        # best-effort: if header fails, continue so management still renders
        return


def main(snapshot_path: Path, hide_management: bool = False, show_kpi: str | None = None):
    snap = Path(snapshot_path)
    if not snap.exists():
        print('Snapshot not found:', snap)
        raise SystemExit(1)

    technical_json = json.loads(snap.read_text(encoding='utf-8'))

    customer = technical_json.get('customer', 'FREE')
    # allow overriding customer via top-level field commonly used in scripts
    customer = customer or 'FREE'
    month = technical_json.get('month', 'unknown')
    ip = technical_json.get('ip', 'unknown')
    management_text = 'Kostenlose Management-Variante: Kurzfassung der Kernaussage.'
    trend_text = ''
    business_risk = 'low'
    config = {}

    # Output path: reports/Free/<customer>/<month>_<ip>.pdf
    output_dir = Path('reports') / 'Free'
    output_dir.mkdir(parents=True, exist_ok=True)
    customer_dir = output_dir / customer.replace(' ', '_')
    customer_dir.mkdir(parents=True, exist_ok=True)
    safe_ip = ip.replace('/', '_').replace(':', '_')
    filename = f"{month}_{safe_ip}.pdf"
    pdf_path = customer_dir / filename

    # Build the full document elements, then redact all sections after the
    # first (management) chunk by replacing them with a short placeholder.
    elements = prepare_pdf_elements(
        customer,
        month,
        ip,
        management_text,
        trend_text,
        technical_json,
        {},
        business_risk,
        config=config,
    )

    # Post-process `elements`: keep the first section chunk (header+management
    # and the immediate following recommendations if present) intact; for all
    # later chunks replace with a short censored placeholder so the PDF layout
    # and page numbering remain unchanged. Optionally hide management text while
    # keeping headings/tables, and optionally surface a single KPI.
    from reportlab.platypus import Paragraph, Spacer, PageBreak, Flowable
    from reportlab.lib.pagesizes import A4
    from shodan_report.pdf.styles import create_styles, create_theme
    # create styles for replacement paragraphs
    theme = create_theme("#1a365d", "#2d3748")
    styles = create_styles(theme)

    # optionally compute management data (for KPI extraction)
    try:
        from shodan_report.pdf.sections.data.management_data import prepare_management_data
        mdata = prepare_management_data(technical_json, {})
    except Exception:
        mdata = {}


    class RedactionFlowable(Flowable):
        """Flowable that overlays most of the PDF page with a semi-opaque
        cover while leaving the top area (header) readable. Uses canvas alpha
        when available; falls back to a hatch-style overlay otherwise.
        """

        def __init__(self, text="ZENSIERT", top_clear_pt: int = 140):
            super().__init__()
            self.text = text
            # height in points to keep clear at the top of the page
            self.top_clear = top_clear_pt

        def wrap(self, availWidth, availHeight):
            return availWidth, availHeight

        def draw(self):
            c = self.canv
            try:
                w, h = c._pagesize
            except Exception:
                w, h = A4

            cover_y = 0
            cover_h = max(0, h - self.top_clear)

            c.saveState()
            # Try alpha fill first (modern ReportLab / PDF 1.4)
            try:
                if hasattr(c, "setFillAlpha"):
                    c.setFillColorRGB(1, 1, 1)
                    c.setFillAlpha(0.6)
                    c.rect(0, cover_y, w, cover_h, fill=1, stroke=0)
                    c.setFillAlpha(1)
                else:
                    raise AttributeError("no alpha")
            except Exception:
                # Fallback: draw a light gray rectangle and add hatch lines
                c.setFillColorRGB(0.95, 0.95, 0.95)
                c.rect(0, cover_y, w, cover_h, fill=1, stroke=0)
                c.setStrokeColorRGB(0.85, 0.85, 0.85)
                # draw diagonal hatch lines to reduce legibility
                step = 12
                x = -int(cover_h)
                while x < w + cover_h:
                    c.line(x, cover_y, x + cover_h, cover_y + cover_h)
                    x += step

            # watermark text repeated faintly over the covered area
            try:
                c.setFont("Helvetica-Bold", 48)
                c.setFillColorRGB(0.5, 0.0, 0.0)
                # multiple instances vertically
                y = cover_y + cover_h * 0.15
                while y < cover_y + cover_h:
                    c.saveState()
                    c.translate(w / 2.0, y)
                    c.rotate(20)
                    try:
                        if hasattr(c, "setFillAlpha"):
                            c.setFillAlpha(0.25)
                    except Exception:
                        pass
                    c.drawCentredString(0, 0, self.text)
                    try:
                        if hasattr(c, "setFillAlpha"):
                            c.setFillAlpha(1)
                    except Exception:
                        pass
                    c.restoreState()
                    y += 140
            except Exception:
                pass

            c.restoreState()


    redacted_elements = []
    seen_first_chunk = False
    i = 0
    while i < len(elements):
        el = elements[i]
        # _SectionMarker objects are lightweight markers (inner class)
        if type(el).__name__ == "_SectionMarker":
            # Always preserve the marker
            redacted_elements.append(el)
            i += 1
            # collect chunk until next marker
            chunk = []
            while i < len(elements) and type(elements[i]).__name__ != "_SectionMarker":
                chunk.append(elements[i])
                i += 1

            if not seen_first_chunk:
                # first chunk: optionally hide management paragraphs but keep
                # headings and tables so the page looks professional.
                if hide_management:
                    proc_chunk = []
                    for item in chunk:
                        try:
                            style_name = getattr(getattr(item, 'style', None), 'name', '') or ''
                            sname = style_name.lower()
                        except Exception:
                            sname = ''

                        # Keep headings, titles, meta and tables; redact ordinary paragraphs
                        if type(item).__name__ == '_SectionMarker':
                            proc_chunk.append(item)
                        elif getattr(item, '__class__', None) and item.__class__.__name__ == 'Table':
                            proc_chunk.append(item)
                        elif getattr(item, '__class__', None) and item.__class__.__name__ == 'KeepTogether':
                            # keep grouped headings intact
                            proc_chunk.append(item)
                        elif hasattr(item, 'getPlainText') and (('heading' in sname) or ('title' in sname) or ('meta' in sname)):
                            proc_chunk.append(item)
                        else:
                            # replace with small censored line to keep layout
                            proc_chunk.append(Paragraph('ZENSIERT', styles['normal']))

                    # If requested, append a KPI line (e.g., exposure)
                    if show_kpi:
                        kp = None
                        try:
                            if show_kpi.lower() == 'exposure':
                                kp = mdata.get('exposure_display') or mdata.get('exposure_score')
                            elif show_kpi.lower() == 'assets':
                                kp = max(1, len(mdata.get('assets', []) or []))
                            elif show_kpi.lower() == 'ports':
                                kp = mdata.get('total_ports')
                            elif show_kpi.lower() == 'cves':
                                kp = mdata.get('cve_count')
                        except Exception:
                            kp = None
                        if kp is not None:
                            proc_chunk.append(Paragraph(f"{show_kpi.capitalize()}: {kp}", styles['normal']))

                    redacted_elements.extend(proc_chunk)
                else:
                    # keep first chunk as-is
                    redacted_elements.extend(chunk)
                seen_first_chunk = True
            else:
                # replace later chunks with a redaction overlay page so the
                # first page remains attractive while details are hidden.
                try:
                    redacted_elements.append(RedactionFlowable(text="ZENSIERT — Vollversion auf Anfrage"))
                    # ensure each redacted section occupies its own page
                    redacted_elements.append(PageBreak())
                except Exception:
                    continue
        else:
            # Non-marker element before any markers — preserve
            redacted_elements.append(el)
            i += 1

    elements = redacted_elements

    render_pdf(pdf_path, elements)
    print('Wrote censored (management-only) PDF:', pdf_path)


if __name__ == '__main__':
    import argparse

    p = argparse.ArgumentParser(description='Generate a management-only (free) PDF from snapshot')
    p.add_argument('snapshot', nargs='?', default='snapshots/Test/2025-01_1.2.3.4.json', help='Path to snapshot .json')
    p.add_argument('--skeleton', action='store_true', help='Produce skeleton PDF showing headings and placeholders')
    p.add_argument('--hide-management', action='store_true', help='Hide management text on first page (replace with ZENSIERT)')
    p.add_argument('--show-kpi', choices=['exposure', 'assets', 'ports', 'cves'], help='Expose a single KPI on the first page')
    args = p.parse_args()
    if args.skeleton:
        # generate full elements first, then convert to skeleton before rendering
        def main_skel(snapshot_path: Path):
            snap = Path(snapshot_path)
            if not snap.exists():
                print('Snapshot not found:', snap)
                raise SystemExit(1)

            technical_json = json.loads(snap.read_text(encoding='utf-8'))

            customer = technical_json.get('org') or technical_json.get('customer') or 'FREE'
            month = technical_json.get('month', 'unknown')
            ip = technical_json.get('ip', 'unknown')
            management_text = 'Kostenlose Management-Variante: Kurzfassung der Kernaussage.'
            trend_text = ''
            business_risk = 'low'
            config = {}

            output_dir = Path('reports') / 'Free'
            output_dir.mkdir(parents=True, exist_ok=True)
            customer_dir = output_dir / customer.replace(' ', '_')
            customer_dir.mkdir(parents=True, exist_ok=True)
            safe_ip = ip.replace('/', '_').replace(':', '_')
            filename = f"{month}_{safe_ip}_skeleton.pdf"
            pdf_path = customer_dir / filename

            elements = prepare_pdf_elements(
                customer,
                month,
                ip,
                management_text,
                trend_text,
                technical_json,
                {},
                business_risk,
                config=config,
            )

            # build skeleton: keep heading flowables, replace others with BoxPlaceholder
            from reportlab.platypus import Paragraph
            skeleton = []
            for el in elements:
                try:
                    style = getattr(el, 'style', None)
                    name = getattr(style, 'name', '') if style else ''
                    if isinstance(el, Paragraph) and (('heading' in name.lower()) or ('title' in name.lower()) or ('meta' in name.lower())):
                        skeleton.append(el)
                    elif type(el).__name__ == '_SectionMarker':
                        skeleton.append(el)
                    elif type(el).__name__ == 'PageBreak':
                        skeleton.append(el)
                    else:
                        # replace with compact placeholder
                        skeleton.append(BoxPlaceholder(width_pct=0.9, height=18))
                except Exception:
                    skeleton.append(BoxPlaceholder(width_pct=0.9, height=18))

            render_pdf(pdf_path, skeleton)
            print('Wrote skeleton PDF:', pdf_path)

        main_skel(Path(args.snapshot))
    else:
        main(Path(args.snapshot), hide_management=args.hide_management, show_kpi=args.show_kpi)
