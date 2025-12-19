import requests
from typing import Dict, Any, Optional

class MetadataScanner:
    """
    Internal scanner to check for Instance Metadata Service (IMDS) exposure.
    Designed to be run FROM within a cloud instance (or via SSRF).
    """

    def __init__(self):
        self.imds_ip = "169.254.169.254"
        self.timeout = 2

    def scan(self) -> Dict[str, Any]:
        findings = {
            "exposed": False,
            "provider": None,
            "imds_v2_required": False,
            "credentials": None,
            "user_data": None
        }

        # 1. AWS Check
        try:
            # Try IMDSv2 Token
            token_headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
            token_resp = requests.put(f"http://{self.imds_ip}/latest/api/token", headers=token_headers, timeout=self.timeout)
            
            if token_resp.status_code == 200:
                findings["exposed"] = True
                findings["provider"] = "AWS"
                token = token_resp.text
                
                # Get Credentials with Token
                creds = self._get_aws_creds(token=token)
                if creds:
                    findings["credentials"] = creds
                
                # Check User Data
                user_data = self._get_aws_user_data(token=token)
                if user_data:
                    findings["user_data"] = "Found (Hidden for safety)"

            else:
                # Fallback to IMDSv1
                # Check for instance-id as a probe
                v1_resp = requests.get(f"http://{self.imds_ip}/latest/meta-data/instance-id", timeout=self.timeout)
                if v1_resp.status_code == 200:
                    findings["exposed"] = True
                    findings["provider"] = "AWS"
                    findings["imds_v2_required"] = False # Critical risk
                    
                    creds = self._get_aws_creds(token=None)
                    if creds:
                        findings["credentials"] = creds
                        
                    user_data = self._get_aws_user_data(token=None)
                    if user_data:
                        findings["user_data"] = "Found (Hidden for safety)"

        except requests.exceptions.RequestException:
            pass # Not AWS or not accessible

        # 2. Azure Check (if not AWS)
        if not findings["provider"]:
            try:
                headers = {"Metadata": "true"}
                resp = requests.get(f"http://{self.imds_ip}/metadata/instance?api-version=2021-02-01", headers=headers, timeout=self.timeout)
                if resp.status_code == 200:
                    findings["exposed"] = True
                    findings["provider"] = "Azure"
                    # Extract info...
            except requests.exceptions.RequestException:
                pass

        # 3. GCP Check
        if not findings["provider"]:
            try:
                headers = {"Metadata-Flavor": "Google"}
                resp = requests.get(f"http://{self.imds_ip}/computeMetadata/v1/instance/id", headers=headers, timeout=self.timeout)
                if resp.status_code == 200:
                    findings["exposed"] = True
                    findings["provider"] = "GCP"
            except requests.exceptions.RequestException:
                pass
                
        return findings

    def _get_aws_creds(self, token: Optional[str]) -> Optional[Dict[str, str]]:
        headers = {}
        if token:
            headers["X-aws-ec2-metadata-token"] = token
            
        try:
            # 1. Get Role Name
            resp = requests.get(f"http://{self.imds_ip}/latest/meta-data/iam/security-credentials/", headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                role = resp.text.strip()
                # 2. Get Creds
                c_resp = requests.get(f"http://{self.imds_ip}/latest/meta-data/iam/security-credentials/{role}", headers=headers, timeout=self.timeout)
                if c_resp.status_code == 200:
                    return c_resp.json()
        except Exception:
            pass
        return None

    def _get_aws_user_data(self, token: Optional[str]) -> Optional[str]:
        headers = {}
        if token:
            headers["X-aws-ec2-metadata-token"] = token
        try:
            resp = requests.get(f"http://{self.imds_ip}/latest/user-data", headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return None
