from typing import List, Dict, Any, Set
from ..core.normalizer import TargetResource

class AttackPathAnalyzer:
    """
    Analyzes assets to identify complete attack chains (Kill Chains).
    """

    def analyze(self, assets: List[TargetResource]) -> List[Dict[str, Any]]:
        """
        Returns a list of identified kill chains.
        Each chain has a 'name', 'description', and 'assets' (list of IDs).
        """
        chains = []
        
        # Index assets for quick lookup
        asset_map = {a.id: a for a in assets}
        
        # 1. "The Golden Ticket": Public EC2 -> Admin Role
        # Logic: EC2 has open ports AND attached Role has AdministratorAccess
        for asset in assets:
            if asset.resource_type == "EC2 Instance" and asset.open_ports:
                # Check for attached role (we need to link EC2 to Role first)
                # In our current model, EC2 metadata might have "IamInstanceProfile"
                # For now, we'll assume we can find the role by naming convention or metadata
                # Let's look for a Role that trusts this EC2 (simulated for now as we don't have full trust mapping)
                
                # Simpler approach: Check if EC2 metadata has "Role" or if we can link it
                # In aws.py, we didn't explicitly link EC2 to Role yet, but let's assume we add that or mock it.
                # For this MVP, let's look for "Shadow Admin" pattern which is clearer:
                # Public EC2 -> Metadata contains "Role: <name>" -> Role is Admin
                pass

        # Let's iterate through "Identity" assets to find their sources
        # But we don't have "Source" in Identity.
        
        # Better Approach: Iterate all assets and look for combinations
        
        # Scenario 1: Public EC2 -> Admin Role (The Golden Ticket)
        # We need to know which Role is attached to which EC2.
        # Let's assume we update aws.py to store "IamInstanceProfile" in EC2 metadata.
        
        for asset in assets:
            if asset.resource_type == "EC2 Instance" and asset.open_ports:
                role_name = asset.metadata.get("IamInstanceProfile")
                if role_name:
                    # Find the role asset
                    role = asset_map.get(role_name)
                    if role:
                        # Check if role is Admin
                        if any("AdministratorAccess" in v for v in role.vulnerabilities.get("Identity", [])):
                            chains.append({
                                "name": "The Golden Ticket",
                                "description": "Publicly exposed EC2 instance with full Administrator privileges.",
                                "assets": [asset.id, role.id],
                                "severity": "CRITICAL"
                            })

        # Scenario 2: Leaky Secrets (Public S3 -> Secrets)
        for asset in assets:
            if asset.resource_type == "S3 Bucket":
                # Check if Public
                is_public = any("Public" in v for v in asset.vulnerabilities.get(443, []))
                # Check if Secrets
                has_secrets = "Secrets" in asset.vulnerabilities
                
                if is_public and has_secrets:
                     chains.append({
                        "name": "Leaky Secrets",
                        "description": "Public S3 bucket exposing hardcoded credentials.",
                        "assets": [asset.id],
                        "severity": "CRITICAL"
                    })

        # Scenario 3: Shadow Admin (Public EC2 -> PassRole)
        for asset in assets:
            if asset.resource_type == "EC2 Instance" and asset.open_ports:
                role_name = asset.metadata.get("IamInstanceProfile")
                if role_name:
                    role = asset_map.get(role_name)
                    if role:
                        # Check for PassRole escalation
                        if any("PassRole + RunInstances" in v for v in role.vulnerabilities.get("Identity", [])):
                             chains.append({
                                "name": "Shadow Admin",
                                "description": "Public EC2 can escalate to Admin via PassRole.",
                                "assets": [asset.id, role.id],
                                "severity": "HIGH"
                            })

        return chains
