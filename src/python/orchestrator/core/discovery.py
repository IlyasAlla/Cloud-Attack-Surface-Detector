import requests
import logging
from typing import List

logger = logging.getLogger(__name__)

def enumerate_subdomains(domain: str) -> List[str]:
    """
    Enumerate subdomains using crt.sh (Certificate Transparency logs).
    """
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    
    try:
        logger.info(f"Querying crt.sh for subdomains of {domain}...")
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get('name_value')
                if name_value:
                    # crt.sh can return multi-line names
                    for sub in name_value.split('\n'):
                        if sub.endswith(domain) and '*' not in sub:
                            subdomains.add(sub)
        else:
            logger.warning(f"crt.sh returned status code {response.status_code}")
            
    except Exception as e:
        logger.error(f"Failed to enumerate subdomains: {e}")
        
    return list(subdomains)
