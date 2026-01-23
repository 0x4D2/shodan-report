import pytest

from shodan_report.pdf.sections.management import should_show_rdp_warning, get_management_risk_and_tech_note


def test_rdp_specific_warning_logic():
    # Case 1: only RDP open -> trigger
    scan_result = {
        'open_ports_count': 1,
        'detected_ports': [3389],
        'primary_service': 'rdp'
    }
    assert should_show_rdp_warning(scan_result) is True

    # Case 2: RDP + other services -> no specific RDP-only warning
    scan_result = {
        'open_ports_count': 3,
        'detected_ports': [80, 443, 3389],
        'primary_service': 'http'
    }
    assert should_show_rdp_warning(scan_result) is False

    # Case 3: no RDP
    scan_result = {
        'open_ports_count': 2,
        'detected_ports': [22, 80],
        'primary_service': 'ssh'
    }
    assert should_show_rdp_warning(scan_result) is False


def test_rdp_edge_cases():
    # RDP on non-standard port (simulate detection via product label)
    tech = {'services': [{'port': 3390, 'product': 'RDP'}]}
    assert should_show_rdp_warning(tech) is True

    # Banner indicating Microsoft Terminal Services should trigger
    tech = {'services': [{'port': 3389, 'product': 'Microsoft Terminal Services'}]}
    assert should_show_rdp_warning(tech) is True

    # False positive: other service on 3389
    tech = {'services': [{'port': 3389, 'product': 'custom_app'}]}
    # without explicit 'rdp' product or single-port-only, this is considered non-RDP
    # (should not trigger)
    assert should_show_rdp_warning(tech) is False


def test_get_management_text_for_rdp():
    tech = {'services': [{'port': 3389, 'product': 'rdp'}]}
    risk, tech_note = get_management_risk_and_tech_note(tech, {})
    assert "Remote Desktop (RDP)" in risk
    assert "häufig genutzter Angriffsvektor" in risk
    assert "können zusätzliche Zugriffskontrollen" in risk
