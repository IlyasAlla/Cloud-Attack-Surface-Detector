from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class UnifiedAsset(BaseModel):
    asset_type: str = Field(..., description="Type of asset (e.g., 'External', 'Internal')")
    ip: Optional[str] = Field(None, description="IP address of the asset")
    domain: Optional[str] = Field(None, description="Domain name of the asset")
    provider: Optional[str] = Field(None, description="Cloud provider (AWS, AZURE, GCP)")
    ports: List[int] = Field(default_factory=list, description="List of open ports")
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list, description="List of vulnerabilities found")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
