# # test_mysql_critical.py
# def test_mysql_with_cves_is_critical():
#     """Testet dass MySQL mit CVEs als kritisch bewertet wird."""
#     service = Service(
#         port=3306, product="MySQL", version="5.7.33",
#         vulnerabilities=[{"id": "CVE-TEST", "cvss": 9.8}]
#     )
    
#     engine = EvaluationEngine()
#     snapshot = AssetSnapshot(ip="test", services=[service])
#     result = engine.evaluate(snapshot)
    
#     assert result.risk == RiskLevel.CRITICAL
#     assert result.exposure_score == 5
#     assert len(result.critical_points) >= 2