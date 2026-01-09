import pytest
from pathlib  import Path
from shodan_report.cli import parse_args

def test_cli_parse_config_arg():
    # Teste das Parsen des --config Arguments
    args = parse_args([
        '--customer', 'Test',
        '--ip', '1.2.3.4',
        '--month', '2025-01',
        '--config', 'config/customers/test.yaml'
    ])
    assert args.customer == 'Test'
    assert args.ip == '1.2.3.4'
    assert args.month == '2025-01'
    assert args.config == Path('config/customers/test.yaml')