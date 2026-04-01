import pytest
from pathlib import Path
from shodan_report.cli import parse_args, validate_args


def test_cli_parse_config_arg():
    # Teste das Parsen des --config Arguments
    args = parse_args(
        [
            "--customer",
            "Test",
            "--ip",
            "1.2.3.4",
            "--month",
            "2025-01",
            "--config",
            "config/customers/test.yaml",
        ]
    )
    assert args.customer == "Test"
    assert args.ip == "1.2.3.4"
    assert args.month == "2025-01"
    assert args.config == Path("config/customers/test.yaml")


# ─── --domain Tests ──────────────────────────────────────────────────────────

def test_cli_parse_domain_arg():
    args = parse_args(["--customer", "Test", "--domain", "example.com", "--month", "2026-04"])
    assert args.domain == "example.com"
    assert args.ip is None


def test_cli_parse_domain_short_flag():
    args = parse_args(["--customer", "Test", "-d", "example.com", "--month", "2026-04"])
    assert args.domain == "example.com"


def test_cli_parse_domain_and_ip_together():
    """Beide angegeben ist erlaubt — IP überschreibt die automatisch gewählte."""
    args = parse_args([
        "--customer", "Test",
        "--domain", "example.com",
        "--ip", "1.2.3.4",
        "--month", "2026-04",
    ])
    assert args.domain == "example.com"
    assert args.ip == "1.2.3.4"


def test_cli_parse_ip_is_optional_when_domain_given():
    """--ip darf fehlen wenn --domain gesetzt ist."""
    args = parse_args(["--customer", "Test", "--domain", "example.com", "--month", "2026-04"])
    assert args.ip is None
    assert args.domain == "example.com"


def test_cli_parse_ip_default_is_none():
    """Ohne --ip und --domain ist ip=None (Validation fängt es ab, nicht Parser)."""
    args = parse_args(["--customer", "Test", "--month", "2026-04"])
    assert args.ip is None
    assert args.domain is None


# ─── validate_args Tests ─────────────────────────────────────────────────────

def test_validate_requires_ip_or_domain(tmp_path):
    args = parse_args(["--customer", "Test", "--month", "2026-04"])
    args.output_dir = tmp_path
    assert validate_args(args) is False


def test_validate_passes_with_ip_only(tmp_path):
    args = parse_args(["--customer", "Test", "--ip", "1.2.3.4", "--month", "2026-04"])
    args.output_dir = tmp_path
    assert validate_args(args) is True


def test_validate_passes_with_domain_only(tmp_path):
    args = parse_args(["--customer", "Test", "--domain", "example.com", "--month", "2026-04"])
    args.output_dir = tmp_path
    assert validate_args(args) is True


def test_validate_passes_with_both(tmp_path):
    args = parse_args([
        "--customer", "Test",
        "--ip", "1.2.3.4",
        "--domain", "example.com",
        "--month", "2026-04",
    ])
    args.output_dir = tmp_path
    assert validate_args(args) is True


def test_validate_rejects_invalid_month(tmp_path):
    args = parse_args(["--customer", "Test", "--ip", "1.2.3.4", "--month", "2026-13"])
    args.output_dir = tmp_path
    assert validate_args(args) is False


def test_validate_rejects_invalid_compare(tmp_path):
    args = parse_args([
        "--customer", "Test", "--ip", "1.2.3.4",
        "--month", "2026-04", "--compare", "not-a-month",
    ])
    args.output_dir = tmp_path
    assert validate_args(args) is False
