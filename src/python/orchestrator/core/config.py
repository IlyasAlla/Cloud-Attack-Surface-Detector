from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional

# Default scan ports for cloud environments
CLOUD_TOP_PORTS: List[int] = [
    80, 443, 8080, 8443,  # Web
    22, 2222,  # SSH
    3389,  # RDP
    21,  # FTP
    23,  # Telnet (Legacy)
    25, 587,  # SMTP
    53,  # DNS
    3306, 5432, 1433, 27017, 6379, 11211,  # Databases (MySQL, Postgres, MSSQL, Mongo, Redis, Memcached)
    9200, 9300,  # Elasticsearch
    5601,  # Kibana
    2375, 2376, 10250, 10255, 6443,  # Docker / Kubernetes
    5000, 8000, 8008, 8888, 9000, 9090,  # Common App Ports
    445, 139,  # SMB
    5900,  # VNC
    8081, 8088, 8090, 8161, 9042, 2181  # Misc Cloud/Apache/Kafka
]

class Settings(BaseSettings):
    # Application Config
    app_name: str = "CloudSurfaceDetector"
    max_concurrency: int = 1000
    timeout_ms: int = 2000
    
    # Cloud Credentials (loaded from ENV)
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_default_region: Optional[str] = "us-east-1"
    aws_endpoint_url: Optional[str] = None
    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[str] = None
    azure_tenant_id: Optional[str] = None
    azure_subscription_id: Optional[str] = None
    google_application_credentials: Optional[str] = None
    gemini_api_key: Optional[str] = None
    
    # Target Ports
    scan_ports: List[int] = []

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
