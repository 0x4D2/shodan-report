from src.shodan_report.clients.helpers.cpe import determine_service_indicator_from_nvd


def test_determine_service_indicator_from_nvd_extracts_products():
    nvd_parsed = {
        'cpe_uris': [
            'cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*',
            'cpe:2.3:a:netapp:oncommand_insight:-:*:*:*:*:*:*:*',
        ],
        'cvss': 4.9,
    }

    res = determine_service_indicator_from_nvd(nvd_parsed)

    assert res['status'] == 'inferred'
    assert 'mysql' in [s.lower() for s in res['services_display']]
    assert any('oncommand' in s.lower() for s in res['services_display'])
    assert res['matched_by'] == 'nvd_cpe'
    assert res['confidence'] == 'low'
    assert res['evidence']
