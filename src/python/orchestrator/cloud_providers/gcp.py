from google.cloud import asset_v1
from google.api_core.exceptions import GoogleAPICallError, RetryError
from typing import List
import logging
from ..core.normalizer import TargetResource, CloudProvider
from ..core.config import settings

logger = logging.getLogger(__name__)

class GCPProvider:
    def __init__(self):
        # Auth is handled by GOOGLE_APPLICATION_CREDENTIALS env var automatically by the lib
        self.client = asset_v1.AssetServiceClient()

    def search_assets(self, scope: str) -> List[TargetResource]:
        resources = []
        try:
            # Search for Compute Instances
            # scope should be "projects/PROJECT_ID" or "organizations/ORG_ID"
            request = asset_v1.SearchAllResourcesRequest(
                scope=scope,
                query="resourceType=compute.googleapis.com/Instance",
                read_mask="name,assetType,displayName,location,additionalAttributes"
            )

            for page in self.client.search_all_resources(request=request).pages:
                for result in page.results:
                    # Extract IP from additional_attributes (this varies by resource)
                    # For Compute Instances, it's often in networkInterfaces
                    # This is a simplification; robust parsing needed for real-world
                    ip_addr = "N/A"
                    if "networkInterfaces" in result.additional_attributes:
                        # Logic to parse nested dicts would go here
                        pass
                    
                    resources.append(TargetResource(
                        id=result.name,
                        ip_address=ip_addr, 
                        hostname=result.display_name,
                        provider=CloudProvider.GCP,
                        region=result.location,
                        resource_type="Compute Instance",
                        metadata={"AssetType": result.asset_type}
                    ))
        except (GoogleAPICallError, RetryError) as e:
            logger.error(f"GCP API Error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error scanning GCP Assets: {e}")
        return resources

    def discover_assets(self) -> List[TargetResource]:
        logger.info("Starting GCP Discovery...")
        # We need a project ID. Assuming it's passed or we can derive it.
        # For now, we'll use a placeholder or config.
        project_id = "projects/my-project" # Needs to be configured
        if settings.google_application_credentials:
             # Try to infer project from creds or config
             pass
        
        assets = self.search_assets(project_id)
        logger.info(f"GCP Discovery complete. Found {len(assets)} assets.")
        return assets
