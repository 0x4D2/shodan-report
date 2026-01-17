from typing import List
from reportlab.platypus import KeepTogether, Table, Flowable
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm


def keep_section(flowables: List[Flowable]) -> KeepTogether:
    """Wrap a list of flowables in a KeepTogether to avoid page breaks inside."""
    return KeepTogether(flowables)


def set_table_repeat(tbl: Table, rows: int = 1) -> None:
    """Set table header rows to repeat on page breaks.

    ReportLab's Table supports a `repeatRows` attribute.
    """
    try:
        tbl.repeatRows = int(rows)
    except Exception:
        # best-effort: ignore if not supported
        pass


def set_table_no_split(tbl: Table) -> None:
    """Prevent ReportLab from splitting a table across pages.

    This sets Table attributes that discourage automatic splitting. If the
    table is larger than a page, ReportLab may still overflow; callers should
    ensure tables are reasonably sized or render an alternative view.
    """
    try:
        # Estimate available page area using the same margins as pdf_renderer
        page_w, page_h = A4
        avail_w = page_w - (2 * cm) - (2 * cm)
        avail_h = page_h - (2 * cm) - (2 * cm)
        try:
            w, h = tbl.wrap(avail_w, avail_h)
            # Only disable splitting if table height fits on a single page
            if h <= avail_h:
                tbl.splitByRow = False
        except Exception:
            # Fallback: don't change splitting behavior
            pass
    except Exception:
        pass


def keep_paragraphs(elements: List[Flowable], n: int):
    """Group next `n` flowables from `elements` into a KeepTogether and
    replace them in the list with a single KeepTogether flowable.
    """
    if n <= 0 or not elements:
        return
    head = elements[:n]
    kt = KeepTogether(head)
    # replace
    del elements[:n]
    elements.insert(0, kt)


def keep_last(elements: List[Flowable], n: int):
    """Group the last `n` flowables in `elements` into a KeepTogether and
    replace them with the KeepTogether flowable.
    """
    if n <= 0 or not elements:
        return
    last = elements[-n:]
    kt = KeepTogether(last)
    del elements[-n:]
    elements.append(kt)
