import os
import pytest
from src.python.orchestrator.core.config import Settings, CLOUD_TOP_PORTS

def test_settings_defaults():
    settings = Settings()
    assert settings.app_name == "CloudSurfaceDetector"
    assert settings.max_concurrency == 1000
    assert settings.timeout_ms == 2000
    assert settings.aws_default_region == "us-east-1"

def test_cloud_top_ports():
    assert len(CLOUD_TOP_PORTS) > 0
    assert 80 in CLOUD_TOP_PORTS
    assert 443 in CLOUD_TOP_PORTS
    assert 22 in CLOUD_TOP_PORTS
