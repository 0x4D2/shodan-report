import importlib, traceback
try:
    m = importlib.import_module('shodan_report.pdf.sections.data.cve_enricher')
    print('OK, module loaded')
    print('has_enrich_cves_with_local=', hasattr(m, 'enrich_cves_with_local'))
    print('symbols=', [n for n in dir(m) if not n.startswith('_')])
except Exception:
    traceback.print_exc()
