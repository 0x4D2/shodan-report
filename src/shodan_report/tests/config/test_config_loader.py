import pytest
from pathlib import Path
from shodan_report.core.runner import load_customer_config


def test_load_customer_config_valid_yaml(tmp_path):
    yaml_content = """
    customer:
      name: "Test GmbH"
      language: "de"
    """
    config_file = tmp_path / "test.yaml"
    config_file.write_text(yaml_content, encoding="utf-8")

    config = load_customer_config(config_file)
    assert config["customer"]["name"] == "Test GmbH"
    assert config["customer"]["language"] == "de"


def test_load_customer_config_nonexistent():
    config = load_customer_config(Path("/nonexistent.yaml"))
    assert config == {}
