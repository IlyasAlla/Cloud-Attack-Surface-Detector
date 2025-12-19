from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Union, Any
from enum import Enum
from enum import Enum

class CloudProvider(str, Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    NETWORK = "NETWORK"

class TargetResource(BaseModel):
    """Normalized representation of a cloud asset."""
    id: str
    ip_address: str  # Kept as string for easier JSON serialization
    hostname: Optional[str] = None
    provider: CloudProvider
    region: str
    resource_type: str # e.g., "EC2", "LoadBalancer", "PublicIP"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Fields populated after scanning
    open_ports: List[int] = Field(default_factory=list)
    banners: Dict[int, str] = Field(default_factory=dict)
    http_headers: Dict[int, Dict[str, str]] = Field(default_factory=dict)
    vulnerabilities: Dict[Union[int, str], List[str]] = Field(default_factory=dict)
    ssl_info: Dict[int, Dict[str, str]] = Field(default_factory=dict)
    paths: List[str] = Field(default_factory=list)
    verification_status: Dict[str, str] = Field(default_factory=dict)
    detected_services: List[str] = Field(default_factory=list)
