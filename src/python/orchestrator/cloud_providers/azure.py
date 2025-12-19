from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import HttpResponseError
from typing import List
import logging
from ..core.normalizer import TargetResource, CloudProvider
from ..core.config import settings

logger = logging.getLogger(__name__)

class AzureProvider:
    def __init__(self):
        self.credential = DefaultAzureCredential()
        self.subscription_id = settings.azure_subscription_id
        
        if not self.subscription_id:
             logger.warning("AZURE_SUBSCRIPTION_ID not set. Azure scan may fail or be limited.")

    def scan_public_ips(self, subscription_id: str) -> List[TargetResource]:
        resources = []
        try:
            network_client = NetworkManagementClient(self.credential, subscription_id)
            # List all public IPs
            for ip in network_client.public_ip_addresses.list_all():
                if ip.ip_address:
                    resources.append(TargetResource(
                        id=ip.id,
                        ip_address=ip.ip_address,
                        hostname=ip.dns_settings.fqdn if ip.dns_settings else None,
                        provider=CloudProvider.AZURE,
                        region=ip.location,
                        resource_type="PublicIP",
                        metadata={
                            "ProvisioningState": ip.provisioning_state,
                            "Orphaned": "True" if ip.ip_configuration is None else "False"
                        }
                    ))
        except HttpResponseError as e:
            logger.error(f"Azure API Error (Public IPs): {e.message}")
        except Exception as e:
            logger.error(f"Unexpected error scanning Azure Public IPs: {e}")
        return resources

    def scan_disks(self, subscription_id: str) -> List[TargetResource]:
        resources = []
        try:
            compute_client = ComputeManagementClient(self.credential, subscription_id)
            for disk in compute_client.disks.list():
                # We are looking for unattached disks primarily, but we'll list all
                resources.append(TargetResource(
                    id=disk.id,
                    ip_address="N/A",
                    provider=CloudProvider.AZURE,
                    region=disk.location,
                    resource_type="ManagedDisk",
                    metadata={
                        "DiskSizeGB": str(disk.disk_size_gb),
                        "Orphaned": "True" if disk.managed_by is None else "False"
                    }
                ))
        except HttpResponseError as e:
            logger.error(f"Azure API Error (Disks): {e.message}")
        except Exception as e:
            logger.error(f"Unexpected error scanning Azure Disks: {e}")
        return resources

    def discover_assets(self) -> List[TargetResource]:
        logger.info("Starting Azure Discovery...")
        assets = []
        
        sub_id = settings.azure_subscription_id
        if not sub_id:
             logger.warning("No Azure Subscription ID provided. Skipping Azure scan.")
             return []

        assets.extend(self.scan_public_ips(sub_id))
        assets.extend(self.scan_disks(sub_id))
        logger.info(f"Azure Discovery complete. Found {len(assets)} assets.")
        return assets
