from typing import List, Dict, Any
from datetime import datetime, timedelta, timezone
from ..core.normalizer import TargetResource

class PersistenceAnalyzer:
    """
    Analyzes assets for potential C2 and Persistence mechanisms.
    """

    SUSPICIOUS_PORTS = {
        4444: "Metasploit Meterpreter",
        1337: "Leet/Backdoor",
        6667: "IRC (Botnet)",
        8080: "Alternative HTTP (Common C2)",
        44444: "Metasploit",
        31337: "Back Orifice"
    }

    def analyze(self, assets: List[TargetResource]) -> List[Dict[str, Any]]:
        """
        Returns a list of persistence findings.
        """
        findings = []
        now = datetime.now(timezone.utc)
        
        for asset in assets:
            # 1. Recent IAM Users (Persistence)
            if "IAM" in asset.resource_type:
                create_date_str = asset.metadata.get("CreateDate")
                if create_date_str:
                    try:
                        # Parse AWS datetime format (e.g., "2023-10-27 10:00:00+00:00")
                        # It might be a string representation of datetime object
                        # Let's try flexible parsing
                        if "+" in create_date_str:
                            create_date = datetime.fromisoformat(create_date_str)
                        else:
                            create_date = datetime.strptime(create_date_str, "%Y-%m-%d %H:%M:%S")
                            create_date = create_date.replace(tzinfo=timezone.utc)
                        
                        if now - create_date < timedelta(hours=24):
                            findings.append({
                                "asset_id": asset.id,
                                "type": "Persistence",
                                "description": "Recently Created Identity (< 24h)",
                                "severity": "MEDIUM"
                            })
                    except Exception:
                        pass # Ignore parsing errors

            # 2. Suspicious Ports (C2)
            if asset.open_ports:
                for port in asset.open_ports:
                    if port in self.SUSPICIOUS_PORTS:
                        findings.append({
                            "asset_id": asset.id,
                            "type": "C2",
                            "description": f"Suspicious Port Open: {port} ({self.SUSPICIOUS_PORTS[port]})",
                            "severity": "HIGH"
                        })

        return findings
