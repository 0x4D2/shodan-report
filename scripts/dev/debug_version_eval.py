import sys
from pathlib import Path

# ensure project src is on path when run from scripts/
repo = Path(__file__).resolve().parents[1]
src = repo / 'src'
sys.path.insert(0, str(src))

from shodan_report.evaluation.evaluators.version_evaluator import VersionEvaluator
from shodan_report.evaluation.config import EvaluationConfig
from shodan_report.models.service import Service

config = EvaluationConfig()
evalr = VersionEvaluator(config)

s = Service(port=3306, transport='tcp', product='MySQL', version='5.7.33')
print('service:', s)
print('applies_to:', evalr.applies_to(s))
res = evalr.evaluate(s)
print('result:', res)
print('risk_score:', res.risk_score)
print('message:', res.message)
