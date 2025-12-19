import boto3
import requests
import socket
import logging
from botocore.exceptions import ClientError
from botocore import UNSIGNED
from botocore.config import Config

logger = logging.getLogger(__name__)

class Verifier:
    """
    Active verification engine to confirm exploitability of detected vulnerabilities.
    """

    def verify_s3_public_access(self, bucket_name: str) -> str:
        """
        Attempts to list objects in an S3 bucket anonymously.
        Returns a status string.
        """
        try:
            # Create anonymous client
            s3 = boto3.client('s3', config=Config(signature_version=UNSIGNED))
            
            # Attempt ListObjectsV2
            s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
            
            return "Confirmed: Publicly Listable (Anonymous Access Allowed)"
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code')
            if error_code == 'AccessDenied':
                return "Safe: Access Denied (Anonymous Access Blocked)"
            elif error_code == 'NoSuchBucket':
                return "Error: Bucket Not Found"
            else:
                return f"Error: {error_code}"
        except Exception as e:
            return f"Error: {str(e)}"

    def verify_port_access(self, ip: str, port: int) -> str:
        """
        Checks if a port is actually reachable and responding.
        """
        try:
            # 1. Socket Connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result != 0:
                return "Safe: Port Closed/Filtered"
            
            # 2. HTTP Check (if applicable)
            if port in [80, 443, 8080, 8443]:
                protocol = "https" if port in [443, 8443] else "http"
                try:
                    requests.get(f"{protocol}://{ip}:{port}", timeout=2, verify=False)
                    return f"Confirmed: Reachable & Responding ({protocol})"
                except requests.RequestException:
                    return "Confirmed: TCP Open (No HTTP Response)"
            
            return "Confirmed: TCP Open"
            
        except Exception as e:
            return f"Error: {str(e)}"
