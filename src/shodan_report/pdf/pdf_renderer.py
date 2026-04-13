from reportlab.platypus import SimpleDocTemplate, PageBreak
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.utils import simpleSplit
from pathlib import Path
from typing import Optional, Dict, Any
from .layout import keep_section
from reportlab.pdfgen import canvas as pdfcanvas


def render_pdf(output_path: Path, elements: list, page_meta: Optional[Dict[str, Any]] = None):

    try:
        # Pre-process `elements`: transform ranges starting at a lightweight
        # `_SectionMarker` (created by `prepare_pdf_elements`) into `KeepTogether`
        # blocks so sections are not split across pages. Also insert explicit
        # `PageBreak` flowables when a whole section would not fit the
        # remaining space on the current page. If a section is larger than a
        # single page, it is inserted element-by-element (no KeepTogether).

        FOOTER_RESERVE = 2 * cm

        def _estimate_height(flowable, availW, availH):
            try:
                w, h = flowable.wrap(availW, availH)
                return h or 0
            except Exception:
                # If wrap fails, conservatively assume it needs a full page.
                return availH

        proc_elements = []
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )

        remaining = doc.height
        i = 0
        while i < len(elements):
            el = elements[i]
            if type(el).__name__ == "_SectionMarker":
                # collect until next marker
                j = i + 1
                chunk = []
                while j < len(elements) and type(elements[j]).__name__ != "_SectionMarker":
                    chunk.append(elements[j])
                    j += 1

                if chunk:
                    kt = keep_section(chunk)
                    chunk_h = _estimate_height(kt, doc.width, remaining)

                    # Detect if this chunk contains a footer/disclaimer paragraph
                    # so we can reserve space for it when testing fit.
                    has_footer = False
                    for f in chunk:
                        if hasattr(f, "style") and getattr(f.style, "name", "").lower() in (
                            "footer",
                            "disclaimer",
                        ):
                            has_footer = True
                            break

                    compare_remaining = remaining
                    if has_footer:
                        compare_remaining = max(0, remaining - FOOTER_RESERVE)

                    # If the chunk is larger than a full page, we cannot keep it
                    # together — insert its elements individually instead.
                    if chunk_h > doc.height:
                        for sub in chunk:
                            if type(sub).__name__ == "PageBreak":
                                proc_elements.append(sub)
                                remaining = doc.height
                                continue

                            # If the sub-element is footer/disclaimer, ensure the
                            # reserve is considered when fitting it.
                            sub_avail = remaining
                            if hasattr(sub, "style") and getattr(sub.style, "name", "").lower() in (
                                "footer",
                                "disclaimer",
                            ):
                                sub_avail = max(0, remaining - FOOTER_RESERVE)

                            sub_h = _estimate_height(sub, doc.width, sub_avail)
                            if sub_h > sub_avail:
                                proc_elements.append(PageBreak())
                                remaining = doc.height
                            proc_elements.append(sub)
                            remaining -= min(sub_h, sub_avail)
                    else:
                        if chunk_h > compare_remaining:
                            proc_elements.append(PageBreak())
                            remaining = doc.height
                        proc_elements.append(kt)
                        remaining -= chunk_h

                i = j
            else:
                # Non-section element: try to fit, otherwise page-break first.
                if type(el).__name__ == 'PageBreak':
                    proc_elements.append(el)
                    remaining = doc.height
                    i += 1
                    continue

                # Heading-widow fix: if this element appears to be a heading
                # (style name contains 'heading'), try to keep it with the
                # following paragraph.
                try:
                    style_name = getattr(el, "style", None)
                    style_name = getattr(style_name, "name", "").lower() if style_name else ""
                except Exception:
                    style_name = ""

                if style_name and "heading" in style_name and i + 1 < len(elements):
                    nxt = elements[i + 1]
                    if hasattr(nxt, "style"):
                        kt = keep_section([el, nxt])
                        kt_h = _estimate_height(kt, doc.width, remaining)
                        if kt_h > remaining:
                            proc_elements.append(PageBreak())
                            remaining = doc.height
                        proc_elements.append(kt)
                        remaining -= kt_h
                        i += 2
                        continue

                el_h = _estimate_height(el, doc.width, remaining)
                if el_h > remaining:
                    proc_elements.append(PageBreak())
                    remaining = doc.height
                proc_elements.append(el)
                remaining -= min(el_h, remaining)
                i += 1

        class NumberedCanvas(pdfcanvas.Canvas):
            """Canvas that draws page numbers and corner metadata on every page."""

            _meta: Dict[str, Any] = page_meta or {}

            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._saved_page_states = []

            def showPage(self):
                self._saved_page_states.append(dict(self.__dict__))
                self._startPage()

            def save(self):
                num_pages = len(self._saved_page_states)
                for state in self._saved_page_states:
                    self.__dict__.update(state)
                    self._draw_page_decorations(num_pages)
                    super().showPage()
                super().save()

            def _draw_page_decorations(self, page_count):
                try:
                    page = self._pageNumber
                except Exception:
                    page = 0

                meta = self.__class__._meta
                domain = "ichwillsicherheit.de"
                month_display = meta.get("month_display") or ""
                sha256 = meta.get("sha256") or ""
                confidentiality = meta.get("confidentiality") or "Vertraulich"

                page_label = f"Seite {page} von {page_count}"
                gray = 0.45  # mid-gray for all corner texts

                left_x = 2 * cm
                right_x = A4[0] - 2 * cm
                line_h = 8.5  # pt between lines in top-right block

                # ── Top right: domain / Vertraulich / Seite X von Y ──────────
                self.saveState()
                self.setFont("Helvetica", 7.5)
                self.setFillGray(gray)
                top_y = A4[1] - 1.05 * cm
                lines_top = [l for l in [domain, confidentiality, page_label] if l]
                for i, line in enumerate(lines_top):
                    self.drawRightString(right_x, top_y - i * line_h, line)
                self.restoreState()

                # ── Bottom left: Seite X / Vertraulich / Stand ───────────────
                self.saveState()
                self.setFont("Helvetica", 7)
                self.setFillGray(gray)
                parts = [page_label, confidentiality]
                if month_display:
                    parts.append(f"Stand: {month_display}")
                self.drawString(left_x, 1.1 * cm, " · ".join(parts))
                self.restoreState()

                # ── Bottom right: SHA256 ─────────────────────────────────────
                if sha256:
                    self.saveState()
                    self.setFont("Helvetica", 6.5)
                    self.setFillGray(gray)
                    self.drawRightString(right_x, 1.1 * cm, f"SHA256: {sha256}")
                    self.restoreState()

                # ── Haftungsausschluss — nur auf Seite 1 ────────────────────
                if page == 1:
                    disclaimer = meta.get("disclaimer_text")
                    if disclaimer:
                        self.saveState()
                        font_name = "Helvetica-Oblique"
                        font_size = 6.5
                        self.setFont(font_name, font_size)
                        self.setFillGray(0.60)
                        max_w = A4[0] - 4 * cm  # linker + rechter Rand
                        lines = simpleSplit(disclaimer, font_name, font_size, max_w)
                        line_h = font_size * 1.35
                        # Startposition: oberhalb der Fußzeile, von unten
                        base_y = 1.9 * cm + len(lines) * line_h
                        for i, line in enumerate(lines):
                            self.drawString(left_x, base_y - i * line_h, line)
                        self.restoreState()

        doc.build(proc_elements, canvasmaker=NumberedCanvas)
        print(f"PDF erfolgreich erstellt: {output_path}")
    except Exception as e:
        print(f"Fehler beim Erstellen der PDF: {e}")
        raise
