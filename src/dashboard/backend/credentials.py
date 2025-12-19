import json
import os
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class CredentialsManager:
    def __init__(self, data_dir: str = "src/dashboard/backend/data"):
        self.data_dir = data_dir
        self.credentials_file = os.path.join(self.data_dir, "credentials.json")
        os.makedirs(self.data_dir, exist_ok=True)
        self._ensure_file_exists()

    def _ensure_file_exists(self):
        if not os.path.exists(self.credentials_file):
            with open(self.credentials_file, "w") as f:
                json.dump({}, f)

    def save_credentials(self, data: Dict[str, Optional[str]]):
        """Save credentials to JSON file, merging with existing data."""
        current_creds = self.get_credentials(mask=False)
        
        # Update only provided fields
        for key, value in data.items():
            if value is not None and value != "":
                current_creds[key] = value
        
        try:
            with open(self.credentials_file, "w") as f:
                json.dump(current_creds, f, indent=4)
            logger.info("Credentials saved successfully.")
            return True
        except Exception as e:
            logger.error(f"Failed to save credentials: {e}")
            return False

    def get_credentials(self, mask: bool = False) -> Dict[str, str]:
        """Retrieve credentials, optionally masking secrets."""
        try:
            if not os.path.exists(self.credentials_file):
                return {}
                
            with open(self.credentials_file, "r") as f:
                creds = json.load(f)
            
            if mask:
                return {k: self._mask_value(v) for k, v in creds.items()}
            return creds
        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")
            return {}

    def _mask_value(self, value: str) -> str:
        if not value or len(value) < 8:
            return "********"
        return f"********{value[-4:]}"
