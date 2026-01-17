import sys
from pathlib import Path

PDF_PATH = Path("reports/demo/CHINANET_DEMO/CHINANET_DEMO/2026-01_111.170.152.60.pdf")
OUT_DIR = PDF_PATH.parent / "pages_png"
MAX_PAGES = 3

try:
    import fitz
except Exception as e:
    print("ERROR: PyMuPDF (fitz) not available. Install with: pip install pymupdf")
    sys.exit(2)

if not PDF_PATH.exists():
    print(f"ERROR: PDF not found: {PDF_PATH}")
    sys.exit(3)

OUT_DIR.mkdir(parents=True, exist_ok=True)

doc = fitz.open(str(PDF_PATH))
count = min(MAX_PAGES, doc.page_count)
for i in range(count):
    page = doc.load_page(i)
    pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))
    out_path = OUT_DIR / f"page_{i+1}.png"
    pix.save(str(out_path))
    print(f"SAVED {out_path}")

print(f"Done: {count} pages saved to {OUT_DIR}")
