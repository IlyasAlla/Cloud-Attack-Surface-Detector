import os
import json
from netaddr import IPNetwork, IPSet, IPAddress
from typing import Optional

class CloudMatcher:
    def __init__(self, data_dir: str = None):
        if data_dir is None:
            # Default to ../cloud_data relative to this file
            # src/python/orchestrator/core/cloud_matcher.py -> ../cloud_data
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.data_dir = os.path.join(base_dir, "../cloud_data")
        else:
            self.data_dir = data_dir

        self.aws_ipset = IPSet()
        self.gcp_ipset = IPSet()
        self.azure_ipset = IPSet()

        self._load_data()

    def _load_data(self):
        self._load_aws()
        self._load_gcp()
        self._load_azure()

    def _load_aws(self):
        file_path = os.path.join(self.data_dir, "aws_cloud.json")
        if not os.path.exists(file_path):
            print(f"[-] AWS data not found at {file_path}")
            return
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                # AWS uses 'ip_prefix' and 'ipv6_prefix'
                prefixes = [p['ip_prefix'] for p in data.get('prefixes', [])]
                ipv6_prefixes = [p['ipv6_prefix'] for p in data.get('ipv6_prefixes', [])]
                self.aws_ipset.update(prefixes)
                self.aws_ipset.update(ipv6_prefixes)
            print(f"[+] Loaded AWS ranges from {file_path}")
        except Exception as e:
            print(f"[!] Error loading AWS ranges: {e}")

    def _load_gcp(self):
        file_path = os.path.join(self.data_dir, "gcp_cloud.json")
        if not os.path.exists(file_path):
            print(f"[-] GCP data not found at {file_path}")
            return
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                # GCP uses 'ipv4Prefix' and 'ipv6Prefix'
                prefixes = [p.get('ipv4Prefix') for p in data.get('prefixes', []) if 'ipv4Prefix' in p]
                ipv6_prefixes = [p.get('ipv6Prefix') for p in data.get('prefixes', []) if 'ipv6Prefix' in p]
                self.gcp_ipset.update(prefixes)
                self.gcp_ipset.update(ipv6_prefixes)
            print(f"[+] Loaded GCP ranges from {file_path}")
        except Exception as e:
            print(f"[!] Error loading GCP ranges: {e}")

    def _load_azure(self):
        file_path = os.path.join(self.data_dir, "azure_cloud.json")
        if not os.path.exists(file_path):
            print(f"[-] Azure data not found at {file_path}")
            return
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                # Azure uses 'addressPrefixes' inside 'properties'
                if 'values' in data:
                    for item in data['values']:
                        prefixes = item.get('properties', {}).get('addressPrefixes', [])
                        self.azure_ipset.update(prefixes)
                else:
                    print(f"[!] Unexpected Azure JSON structure in {file_path}")
            print(f"[+] Loaded Azure ranges from {file_path}")
        except Exception as e:
            print(f"[!] Error loading Azure ranges: {e}")

    def get_provider(self, ip_address: str) -> Optional[str]:
        try:
            ip = IPAddress(ip_address)
            if ip in self.aws_ipset:
                return "AWS"
            if ip in self.gcp_ipset:
                return "GCP"
            if ip in self.azure_ipset:
                return "AZURE"
        except Exception as e:
            # Invalid IP format
            pass
        return None
