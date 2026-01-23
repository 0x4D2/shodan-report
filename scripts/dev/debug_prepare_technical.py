import json
import pprint
from shodan_report.pdf.sections.data.technical_data import prepare_technical_detail
p='snapshots/google/2026-01_8.8.8.8.json'
with open(p,'r',encoding='utf-8') as f:
    t=json.load(f)
res=prepare_technical_detail(t,None)
pp=pprint.pformat(res['services'])
print(pp)
print('\nmeta:',res['meta'])
