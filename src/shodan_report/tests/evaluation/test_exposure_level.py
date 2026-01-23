# src/shodan_report/tests/evaluation/test_exposure_level.py
import pytest
from shodan_report.models import Service
from shodan_report.pdf.helpers.evaluation_helpers import (
    calculate_exposure_level,
    is_service_secure,
)


def make_service(
    port: int,
    product: str = None,
    ssl: bool = False,
    vpn: bool = False,
):
    return Service(
        port=port,
        transport="tcp",
        product=product,
        ssl_info={"cert": "x"} if ssl else None,
        vpn_protected=vpn,
    )


def test_exposure_baseline_no_services_medium_risk():

    exposure = calculate_exposure_level(
        risk="MEDIUM", critical_points_count=0, open_ports=[]
    )

    assert exposure in (2, 3)


def test_exposure_increases_with_insecure_services():

    services = [
        make_service(22, product="OpenSSH"),  # unsicher
        make_service(80, product="nginx"),  # unsicher
        make_service(443, product="nginx", ssl=True),  # sicher
    ]

    exposure = calculate_exposure_level(
        risk="MEDIUM", critical_points_count=0, open_ports=services
    )

    assert exposure >= 3


def test_exposure_lower_when_ssh_is_vpn_protected():

    services_no_vpn = [
        make_service(22, product="OpenSSH"),
    ]

    services_with_vpn = [
        make_service(22, product="OpenSSH", vpn=True),
    ]

    exposure_no_vpn = calculate_exposure_level(
        risk="MEDIUM", critical_points_count=0, open_ports=services_no_vpn
    )

    exposure_with_vpn = calculate_exposure_level(
        risk="MEDIUM", critical_points_count=0, open_ports=services_with_vpn
    )

    print(f"DEBUG: No VPN - Exposure: {exposure_no_vpn}")
    print(f"DEBUG: With VPN - Exposure: {exposure_with_vpn}")
    print(
        f"DEBUG: SSH ohne VPN - secure: {is_service_secure(services_no_vpn[0], ['ssh', 'https'])}"
    )
    print(
        f"DEBUG: SSH mit VPN - secure: {is_service_secure(services_with_vpn[0], ['ssh', 'https'])}"
    )

    assert exposure_with_vpn < exposure_no_vpn


def test_exposure_increases_with_critical_points():
    services = [
        make_service(443, product="nginx", ssl=True),
    ]

    exposure_low = calculate_exposure_level(
        risk="LOW", critical_points_count=0, open_ports=services
    )

    exposure_high = calculate_exposure_level(
        risk="LOW", critical_points_count=3, open_ports=services
    )

    assert exposure_high > exposure_low


def test_exposure_is_capped_at_five():
    """
    Exposure darf niemals >5 werden.
    """
    services = [
        make_service(22, product="telnet"),
        make_service(23, product="telnet"),
        make_service(3389, product="rdp"),
    ]

    exposure = calculate_exposure_level(
        risk="HIGH", critical_points_count=10, open_ports=services
    )

    assert exposure == 5


def test_edge_case_no_risk_but_many_insecure_services():
    services = [
        make_service(22, product="OpenSSH"),
        make_service(23, product="telnet"),
        make_service(80, product="nginx"),
        make_service(3389, product="rdp"),
    ]

    exposure = calculate_exposure_level(
        risk="LOW", critical_points_count=0, open_ports=services
    )

    # 4 unsichere Dienste = 2.0 Punkte → Level 3
    # + LOW risk (0 Boost) = 3
    assert exposure == 3


def test_mixed_secure_insecure_services():
    services = [
        make_service(22, product="OpenSSH", vpn=True),  # sicher (VPN)
        make_service(80, product="nginx"),  # unsicher
        make_service(443, product="nginx", ssl=True),  # sicher (SSL)
        make_service(3389, product="rdp"),  # unsicher (kein VPN)
    ]

    exposure = calculate_exposure_level(
        risk="MEDIUM", critical_points_count=0, open_ports=services
    )

    # 2 unsichere = 1.0 Punkte → Level 2
    # + MEDIUM boost (+1) = 3
    assert exposure == 3


def test_empty_risk_string():
    exposure = calculate_exposure_level(
        risk="UNKNOWN", critical_points_count=0, open_ports=[]  # nicht in risk_boost
    )

    # Sollte default auf 0 Boost gehen
    assert exposure in [1, 2]  # baseline


def test_is_service_secure_edge_cases():

    # Test 1: Service mit SSL ist immer sicher
    ssl_service = make_service(443, ssl=True)
    assert is_service_secure(ssl_service, []) == True

    # Test 2: RDP ohne VPN ist unsicher
    rdp_service = make_service(3389, product="Windows RDP")
    assert is_service_secure(rdp_service, ["ssh"]) == False

    # Test 3: RDP mit VPN ist sicher
    rdp_vpn_service = make_service(3389, product="Windows RDP", vpn=True)
    assert is_service_secure(rdp_vpn_service, ["ssh"]) == True
