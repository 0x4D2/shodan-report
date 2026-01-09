import pytest
from unittest.mock import Mock, patch
from shodan_report.core.runner import generate_report_pipeline

def test_runner_with_config(tmp_path):
    with patch('shodan_report.core.runner.ShodanClient') as mock_client, \
         patch('shodan_report.core.runner.generate_pdf') as mock_pdf:
        
        mock_client.return_value.get_host.return_value = {'ip_str': '1.2.3.4'}
        mock_pdf.return_value = tmp_path / 'test.pdf'
        
        result = generate_report_pipeline(
            customer_name='Test',
            ip='1.2.3.4',
            month='2025-01',
            config_path=tmp_path / 'config.yaml',
            output_dir=tmp_path,
            archive=False,
            verbose=False
        )
        
        assert result["success"] is True
        # PDF sollte mit config aufgerufen werden
        mock_pdf.assert_called_once()
        call_args = mock_pdf.call_args[1]
        assert "config" in call_args  