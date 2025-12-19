import boto3
from botocore.exceptions import ClientError
from typing import List
import logging
from ..core.normalizer import TargetResource, CloudProvider
from ..core.config import Settings # Import Class
import base64
from ..analysis.secrets_scanner import SecretsScanner
from ..analysis.oidc_analyzer import OIDCAnalyzer

logger = logging.getLogger(__name__)

class AWSProvider:
    def __init__(self, scan_secrets: bool = True, scan_oidc: bool = True):
        # Reload settings to pick up any changes from Dashboard
        self.settings = Settings()
        
        self.session = boto3.Session(
            aws_access_key_id=self.settings.aws_access_key_id,
            aws_secret_access_key=self.settings.aws_secret_access_key,
            region_name="us-east-1" # Default, but we will iterate regions
        )
        self.scan_secrets_enabled = scan_secrets
        self.scan_oidc_enabled = scan_oidc
        
        self.secrets_scanner = SecretsScanner()
        self.oidc_analyzer = OIDCAnalyzer()

    def get_available_regions(self, service_name: str) -> List[str]:
        try:
            return self.session.get_available_regions(service_name)
        except ClientError as e:
            logger.error(f"Failed to get regions: {e}")
            return ["us-east-1"]

    def scan_ec2(self) -> List[TargetResource]:
        resources = []
        regions = self.get_available_regions('ec2')
        
        for region in regions:
            try:
                ec2 = self.session.client('ec2', region_name=region, endpoint_url=self.settings.aws_endpoint_url)
                
                # 1. Instances
                paginator = ec2.get_paginator('describe_instances')
                for page in paginator.paginate():
                    for reservation in page['Reservations']:
                        for instance in reservation['Instances']:
                            # Extract details
                            public_ip = instance.get('PublicIpAddress')
                            mac = instance['NetworkInterfaces'][0]['MacAddress'] if instance.get('NetworkInterfaces') else "N/A"
                            
                            # Get OS from Tags
                            os_info = "Unknown"
                            tags_text = ""
                            for tag in instance.get('Tags', []):
                                if tag['Key'] == 'OS':
                                    os_info = tag['Value']
                                tags_text += f"{tag['Key']}={tag['Value']} "
                            
                            vulns = {}
                            
                            # Secrets Scanning (UserData & Tags)
                            if self.scan_secrets_enabled:
                                try:
                                    # 1. Scan Tags
                                    tag_secrets = self.secrets_scanner.scan_text(tags_text)
                                    if tag_secrets:
                                        vulns['Secrets'] = vulns.get('Secrets', []) + tag_secrets

                                    # 2. Scan UserData
                                    user_data_resp = ec2.describe_instance_attribute(
                                        InstanceId=instance['InstanceId'], 
                                        Attribute='userData'
                                    )
                                    if 'UserData' in user_data_resp and 'Value' in user_data_resp['UserData']:
                                        user_data_b64 = user_data_resp['UserData']['Value']
                                        user_data_decoded = base64.b64decode(user_data_b64).decode('utf-8', errors='ignore')
                                        
                                        ud_secrets = self.secrets_scanner.scan_text(user_data_decoded)
                                        if ud_secrets:
                                            vulns['Secrets'] = vulns.get('Secrets', []) + ud_secrets
                                            
                                except Exception as e:
                                    logger.warning(f"Failed to scan secrets for {instance['InstanceId']}: {e}")

                            resources.append(TargetResource(
                                id=instance['InstanceId'],
                                ip_address=public_ip if public_ip else "Private IP",
                                hostname=instance.get('PublicDnsName'),
                                provider=CloudProvider.AWS,
                                region=region,
                                resource_type="EC2 Instance",
                                metadata={
                                    "State": instance['State']['Name'],
                                    "ImageId": instance['ImageId'],
                                    "MAC": mac,
                                    "OS": os_info,
                                    "IamInstanceProfile": instance.get('IamInstanceProfile', {}).get('Arn', '').split('/')[-1] if instance.get('IamInstanceProfile') else None
                                },
                                vulnerabilities=vulns
                            ))

                # 2. Shadow Assets (Unattached Volumes)
                volumes = ec2.describe_volumes().get('Volumes', [])
                for vol in volumes:
                    if vol['State'] == 'available': # Not attached
                        vulns = {"Storage": ["Shadow Asset: Unattached Volume"]}
                        if not vol.get('Encrypted'):
                            vulns['Storage'].append("Unencrypted Volume")
                        
                        resources.append(TargetResource(
                            id=vol['VolumeId'],
                            ip_address="N/A",
                            hostname="N/A",
                            provider=CloudProvider.AWS,
                            region=region,
                            resource_type="EBS Volume",
                            metadata={"Size": f"{vol['Size']} GB", "Type": vol['VolumeType']},
                            vulnerabilities=vulns
                        ))

                # 3. Shadow Assets (Unattached EIPs)
                addresses = ec2.describe_addresses().get('Addresses', [])
                for addr in addresses:
                    if 'InstanceId' not in addr:
                        resources.append(TargetResource(
                            id=addr['AllocationId'],
                            ip_address=addr['PublicIp'],
                            hostname="N/A",
                            provider=CloudProvider.AWS,
                            region=region,
                            resource_type="Elastic IP",
                            metadata={"Domain": addr['Domain']},
                            vulnerabilities={"Network": ["Shadow Asset: Unattached IP"]}
                        ))

            except ClientError as e:
                logger.warning(f"Failed to scan EC2 in {region}: {e}")
                continue
        return resources

    def scan_s3(self) -> List[TargetResource]:
        # S3 is global, but buckets have regions
        resources = []
        logger.info("Starting S3 Scan...")
        try:
            s3 = self.session.client('s3', endpoint_url=self.settings.aws_endpoint_url)
            response = s3.list_buckets()
            buckets = response.get('Buckets', [])
            logger.info(f"Found {len(buckets)} buckets.")
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                vulnerabilities = {}
                
                # Check Public Access Block
                try:
                    pab = s3.get_public_access_block(Bucket=bucket_name)
                    conf = pab.get('PublicAccessBlockConfiguration', {})
                    # logger.debug(f"Bucket {bucket_name} PAB: {conf}")
                    if not conf.get('BlockPublicAcls') or not conf.get('BlockPublicPolicy'):
                        vulnerabilities[443] = vulnerabilities.get(443, []) + ["Public Access Block Missing"]
                except ClientError:
                    # If no PAB exists, it's open by default (unless ACLs restrict it)
                    # logger.debug(f"Bucket {bucket_name} has no PAB")
                    vulnerabilities[443] = vulnerabilities.get(443, []) + ["No Public Access Block Found"]

                # Check ACLs
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    # logger.debug(f"Bucket {bucket_name} ACL: {acl}")
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                            if "Public ACL: AllUsers" not in vulnerabilities.get(443, []):
                                vulnerabilities[443] = vulnerabilities.get(443, []) + ["Public ACL: AllUsers"]
                        if grantee.get('Type') == 'Group' and 'AuthenticatedUsers' in grantee.get('URI', ''):
                            if "Public ACL: AuthenticatedUsers" not in vulnerabilities.get(443, []):
                                vulnerabilities[443] = vulnerabilities.get(443, []) + ["Public ACL: AuthenticatedUsers"]
                except ClientError:
                    pass
                resources.append(TargetResource(
                    id=bucket_name,
                    ip_address="N/A", # S3 doesn't have a single IP
                    hostname=f"{bucket_name}.s3.amazonaws.com",
                    provider=CloudProvider.AWS,
                    region="global", # S3 is global namespace
                    resource_type="S3 Bucket",
                    metadata={"CreationDate": str(bucket['CreationDate'])},
                    vulnerabilities=vulnerabilities
                ))
                    
        except ClientError as e:
            logger.error(f"Failed to scan S3: {e}")
            
        return resources

    def _get_detailed_policies(self, iam_client, name: str, is_role: bool = False) -> List[dict]:
        """Helper to fetch all policy documents (Inline + Attached) for an identity."""
        policy_docs = []
        
        try:
            # 1. Attached Managed Policies
            if is_role:
                attached = iam_client.list_attached_role_policies(RoleName=name).get('AttachedPolicies', [])
            else:
                attached = iam_client.list_attached_user_policies(UserName=name).get('AttachedPolicies', [])

            for p in attached:
                try:
                    # Get Policy Info to find DefaultVersionId
                    policy_info = iam_client.get_policy(PolicyArn=p['PolicyArn'])
                    version_id = policy_info['Policy']['DefaultVersionId']
                    
                    # Get actual document
                    version = iam_client.get_policy_version(
                        PolicyArn=p['PolicyArn'], 
                        VersionId=version_id
                    )
                    policy_docs.append({
                        "Name": p['PolicyName'],
                        "Type": "Managed",
                        "Document": version['PolicyVersion']['Document']
                    })
                except ClientError:
                    continue

            # 2. Inline Policies
            if is_role:
                inline_names = iam_client.list_role_policies(RoleName=name).get('PolicyNames', [])
            else:
                inline_names = iam_client.list_user_policies(UserName=name).get('PolicyNames', [])
                
            for p_name in inline_names:
                try:
                    if is_role:
                        doc = iam_client.get_role_policy(RoleName=name, PolicyName=p_name)
                    else:
                        doc = iam_client.get_user_policy(UserName=name, PolicyName=p_name)
                    
                    policy_docs.append({
                        "Name": p_name,
                        "Type": "Inline",
                        "Document": doc['PolicyDocument']
                    })
                except ClientError:
                    continue
                    
        except ClientError as e:
            logger.warning(f"Failed to fetch policies for {name}: {e}")
            
        return policy_docs

    def scan_iam(self) -> List[TargetResource]:
        resources = []
        logger.info("Starting IAM Scan...")
        try:
            iam = self.session.client('iam', endpoint_url=self.settings.aws_endpoint_url)
            
            # 1. Scan Users
            for user in iam.list_users().get('Users', []):
                vulns = {}
                policies = self._get_detailed_policies(iam, user['UserName'], is_role=False)
                
                # Basic check for Admin
                for p in policies:
                    if 'AdministratorAccess' in p['Name']:
                        vulns['Identity'] = vulns.get('Identity', []) + ["Excessive Privilege: AdministratorAccess"]
                
                resources.append(TargetResource(
                    id=user['UserName'],
                    ip_address="N/A",
                    hostname="N/A",
                    provider=CloudProvider.AWS,
                    region="global",
                    resource_type="IAM User",
                    metadata={
                        "Arn": user['Arn'], 
                        "CreateDate": str(user['CreateDate']),
                        "Policies": policies # Store full policies for analysis
                    },
                    vulnerabilities=vulns
                ))

            # 2. Scan Roles
            for role in iam.list_roles().get('Roles', []):
                vulns = {}
                policies = self._get_detailed_policies(iam, role['RoleName'], is_role=True)
                
                for p in policies:
                    if 'AdministratorAccess' in p['Name']:
                        vulns['Identity'] = vulns.get('Identity', []) + ["Excessive Privilege: AdministratorAccess"]
                
                resources.append(TargetResource(
                    id=role['RoleName'],
                    ip_address="N/A",
                    hostname="N/A",
                    provider=CloudProvider.AWS,
                    region="global",
                    resource_type="IAM Role",
                    metadata={
                        "Arn": role['Arn'], 
                        "CreateDate": str(role['CreateDate']),
                        "Policies": policies,
                        "AssumeRolePolicyDocument": role.get('AssumeRolePolicyDocument', {})
                    },
                    vulnerabilities=vulns
                ))

            # 3. Scan OIDC Providers
            if self.scan_oidc_enabled:
                for oidc in iam.list_open_id_connect_providers().get('OpenIDConnectProviderList', []):
                    arn = oidc['Arn']
                    # Fetch details
                    details = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
                    url = details.get('Url', '')
                    client_ids = details.get('ClientIDList', [])
                    
                    # Analyze Provider
                    provider_name = self.oidc_analyzer.analyze_provider(url)
                    
                    resources.append(TargetResource(
                        id=url, # Use URL as ID for uniqueness
                        ip_address="N/A",
                        hostname=url,
                        provider=CloudProvider.AWS, # Technically external, but managed in AWS
                        region="global",
                        resource_type=f"OIDC Provider ({provider_name})",
                        metadata={
                            "Arn": arn,
                            "ProviderName": provider_name,
                            "ClientIDs": client_ids
                        },
                        vulnerabilities={"Identity": [f"External Trust: {provider_name}"]}
                    ))
        except ClientError as e:
            logger.error(f"Failed to scan IAM: {e}")
        return resources

    def scan_api_gateway(self) -> List[TargetResource]:
        resources = []
        logger.info("Starting API Gateway Scan...")
        regions = self.get_available_regions('apigateway')
        for region in regions:
            try:
                apigw = self.session.client('apigateway', region_name=region, endpoint_url=self.settings.aws_endpoint_url)
                for api in apigw.get_rest_apis().get('items', []):
                    vulns = {}
                    # Simple check: Assume vulnerable if no auth (mock check)
                    vulns['API'] = ["Unauthenticated Endpoint"]
                    
                    resources.append(TargetResource(
                        id=api['name'],
                        ip_address="N/A",
                        hostname=f"{api['id']}.execute-api.{region}.amazonaws.com",
                        provider=CloudProvider.AWS,
                        region=region,
                        resource_type="API Gateway",
                        metadata={"Description": api.get('description', '')},
                        vulnerabilities=vulns
                    ))
            except ClientError:
                continue
        return resources

    def discover_assets(self) -> List[TargetResource]:
        logger.info("Starting AWS Discovery...")
        assets = []
        assets.extend(self.scan_ec2())
        assets.extend(self.scan_s3())
        assets.extend(self.scan_iam())
        assets.extend(self.scan_api_gateway())
        logger.info(f"AWS Discovery complete. Found {len(assets)} assets.")
        return assets
