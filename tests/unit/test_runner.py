import pytest
from unittest.mock import patch, MagicMock
from src.python.orchestrator.core.runner import run_scanner
from src.python.orchestrator.core.normalizer import TargetResource, CloudProvider

@pytest.fixture
def mock_targets():
    return [
        TargetResource(
            id="test.com",
            ip_address="1.2.3.4",
            provider=CloudProvider.AWS,
            resource_type="EC2",
            region="us-east-1"
        )
    ]

@patch("subprocess.Popen")
def test_run_scanner_success(mock_popen, mock_targets):
    # Mock subprocess output
    mock_process = MagicMock()
    mock_process.communicate.return_value = ('{"ip": "1.2.3.4", "port": 80}\n{"ip": "1.2.3.4", "port": 443}', "")
    mock_process.returncode = 0
    mock_popen.return_value = mock_process

    results = run_scanner(mock_targets, binary_path="/bin/echo")
    
    assert len(results) == 1
    asset = results[0]
    assert 80 in asset.open_ports
    assert 443 in asset.open_ports

@patch("subprocess.Popen")
def test_run_scanner_failure(mock_popen, mock_targets):
    # Mock subprocess failure
    mock_process = MagicMock()
    mock_process.communicate.return_value = ("", "Error executing binary")
    mock_process.returncode = 1
    mock_popen.return_value = mock_process

    results = run_scanner(mock_targets, binary_path="/bin/error")
    
    # Should return original targets without modification
    assert len(results) == 1
    assert results[0].open_ports == []
