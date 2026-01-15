import sys
from pathlib import Path
try:
    from PyPDF2 import PdfReader
except Exception as e:
    print('ERROR: PyPDF2 not available:', e)
    sys.exit(2)

def extract(path):
    p = Path(path)
    if not p.exists():
        print(f'ERROR: file not found: {path}')
        return 3
    try:
        r = PdfReader(str(p))
        out = []
        for i, page in enumerate(r.pages):
            text = page.extract_text() or ''
            out.append(f'--- PAGE {i+1} ---')
            out.append(text)
        print('\n'.join(out))
        return 0
    except Exception as e:
        print('ERROR: exception reading PDF:', e)
        return 4

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: _extract_pdf_text_short.py <pdf-path>')
        sys.exit(1)
    sys.exit(extract(sys.argv[1]))
