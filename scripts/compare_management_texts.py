"""
Script: compare_management_texts.py
- Loads two snapshot JSONs
- Builds PDF elements via prepare_pdf_elements
- Extracts management-related Paragraph texts and insights
- Prints a simple diff/report of differences and potential issues
"""
import sys
from pathlib import Path
import json

repo = Path(__file__).resolve().parents[1]
src_path = repo / 'src'
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from shodan_report.pdf.pdf_manager import prepare_pdf_elements

SNAP1 = Path('snapshots/CHINANET/2026-01_111.170.152.60.json')
SNAP2 = Path('snapshots/MG_Solutions/2026-01_217.154.224.104.json')

def load_snapshot(path: Path):
    with path.open('r', encoding='utf8') as f:
        return json.load(f)


def extract_texts(elements):
    texts = []
    for el in elements:
        # Paragraph objects have a .text attribute; fallback to repr
        t = getattr(el, 'text', None)
        if t:
            texts.append(t)
        else:
            # simple str for other elements
            texts.append(repr(el))
    return texts


if __name__ == '__main__':
    s1 = load_snapshot(SNAP1)
    s2 = load_snapshot(SNAP2)

    # minimal evaluation placeholders
    eval1 = {'ip': s1.get('ip', '111.170.152.60'), 'risk': 'HIGH', 'critical_points': s1.get('critical_points', [])}
    eval2 = {'ip': s2.get('ip', '217.154.224.104'), 'risk': 'MEDIUM', 'critical_points': s2.get('critical_points', [])}

    def normalize_technical(t):
        t = dict(t)
        ops = t.get('open_ports') or t.get('services') or []
        normalized = []
        for item in ops:
            if isinstance(item, int):
                normalized.append({'port': item})
            elif isinstance(item, dict):
                # already dict-like
                normalized.append(item)
            else:
                # try to extract attributes
                try:
                    normalized.append({'port': getattr(item, 'port', None) or item.get('port')})
                except Exception:
                    normalized.append({'port': None})
        t['open_ports'] = normalized
        return t

    elems1 = prepare_pdf_elements(customer_name='CHINANET', month='2026-01', ip=eval1['ip'], management_text='', trend_text='', technical_json=normalize_technical(s1), evaluation=eval1, business_risk='HIGH')
    elems2 = prepare_pdf_elements(customer_name='MG_Solutions', month='2026-01', ip=eval2['ip'], management_text='', trend_text='', technical_json=normalize_technical(s2), evaluation=eval2, business_risk='MEDIUM')

    texts1 = extract_texts(elems1)
    texts2 = extract_texts(elems2)

    # Find indices of Management section heading and following paragraphs
    def section_slice(texts):
        try:
            i = next(idx for idx,t in enumerate(texts) if '1. Management-Zusammenfassung' in t)
        except StopIteration:
            return []
        # take next 20 entries as management area
        return texts[i:i+20]

    m1 = section_slice(texts1)
    m2 = section_slice(texts2)

    print('--- Management CHINANET ---')
    print('\n'.join(m1))
    print('\n--- Management MG_Solutions ---')
    print('\n'.join(m2))

    # Basic comparisons
    set1 = set(m1)
    set2 = set(m2)
    only1 = set1 - set2
    only2 = set2 - set1

    print('\n--- Only in CHINANET ---')
    for line in only1:
        print('-', line)
    print('\n--- Only in MG_Solutions ---')
    for line in only2:
        print('-', line)

    # Simple heuristics for issues
    issues = []
    for t in m1 + m2:
        if 'Port 3' in t:
            issues.append('Found stray "Port 3" artifact')
        if 'kritische Risikopunkte' in t and 'critical_points' not in t:
            issues.append('Alarming phrase without matching critical points')
    if issues:
        print('\n--- Potential Issues Detected ---')
        for it in set(issues):
            print('- ', it)
    else:
        print('\nNo immediate issues detected by heuristics.')
