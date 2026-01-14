from typing import List
from reportlab.platypus import KeepTogether, Table, Flowable


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
