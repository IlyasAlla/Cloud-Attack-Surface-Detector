from typing import List, Dict, Any
from rich.console import Console

console = Console()

class ServiceDiscoverer:
    """
    Identifies cloud services based on open ports and banners.
    """
    def __init__(self):
        self.port_map = {
            5432: "PostgreSQL (RDS/CloudSQL)",
            3306: "MySQL (RDS/CloudSQL)",
            1433: "MSSQL (RDS/AzureSQL)",
            27017: "MongoDB (CosmosDB/DocumentDB)",
            6379: "Redis (ElastiCache/MemoryStore)",
            9200: "Elasticsearch (OpenSearch)",
            5601: "Kibana",
            443: "HTTPS (Web/API)",
            80: "HTTP (Web)",
            22: "SSH (EC2/GCE/VM)",
            3389: "RDP (Windows VM)"
        }

    def identify_services(self, assets: List[Any]) -> List[Any]:
        console.print("[cyan]Running Service Discovery on Open Ports...[/cyan]")
        
        for asset in assets:
            # Handle Dict vs Object
            if isinstance(asset, dict):
                ports = asset.get('open_ports', []) or asset.get('ports', [])
                target_attr = asset
            else:
                ports = getattr(asset, 'open_ports', []) or getattr(asset, 'ports', [])
                target_attr = asset # usage: getattr(asset, 'detected_services', []) but we want to set it.
                # If it's a Pydantic model or class, we might need to set attribute.
                if not hasattr(asset, 'detected_services'):
                    setattr(asset, 'detected_services', [])
            
            detected = []
            if ports:
                # Handle simplified list of ints or strings
                if isinstance(ports[0], (int, str)):
                     for p in ports:
                        try:
                            port_num = int(p)
                            if port_num in self.port_map:
                                service = self.port_map[port_num]
                                detected.append(f"{port_num}: {service}")
                                # console.print(f"[green]  [+] Identified {getattr(asset, 'ip_address', 'N/A')}:{port_num} as {service}[/green]")
                        except ValueError:
                            pass
            
            # Set results
            if isinstance(asset, dict):
                asset['detected_services'] = detected
            else:
                setattr(asset, 'detected_services', detected)
            
        return assets
