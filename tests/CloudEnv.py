import boto3
import json
import logging

# Configuration for LocalStack
ENDPOINT_URL = "http://localhost:4566"
REGION = "us-east-1"
DEFAULT_CREDS = {
    "aws_access_key_id": "test",
    "aws_secret_access_key": "test",
    "region_name": REGION
}

# Setup Logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger()

def get_client(service):
    return boto3.client(service, endpoint_url=ENDPOINT_URL, **DEFAULT_CREDS)

def create_s3_assets():
    s3 = get_client('s3')
    
    # 1. Create a Secure Bucket
    secure_bucket = "prod-finance-logs"
    s3.create_bucket(Bucket=secure_bucket)
    logger.info(f" S3: Created secure bucket '{secure_bucket}'")

    # 2. Create a Public/Vulnerable Bucket
    public_bucket = "public-website-assets-leak"
    s3.create_bucket(Bucket=public_bucket)
    
    # Make it public via ACL
    s3.put_bucket_acl(Bucket=public_bucket, ACL='public-read')
    logger.info(f"️  S3: Created PUBLIC bucket '{public_bucket}' (ACL: public-read)")

    # 3. Create a Public Read/Write Bucket (Highly Dangerous)
    rw_bucket = "public-collab-data-leak"
    s3.create_bucket(Bucket=rw_bucket)
    s3.put_bucket_acl(Bucket=rw_bucket, ACL='public-read-write')
    logger.info(f" S3: Created PUBLIC R/W bucket '{rw_bucket}' (ACL: public-read-write)")

def create_network_assets():
    ec2 = get_client('ec2')

    # 1. Create a VPC (to put things in)
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']
    vpc_id = vpc['VpcId']
    
    # 2. Create a Vulnerable Security Group (Firewall)
    sg_name = "launch-wizard-1-OPEN"
    sg = ec2.create_security_group(
        GroupName=sg_name,
        Description="Temporary access for devs - DO NOT USE",
        VpcId=vpc_id
    )
    sg_id = sg['GroupId']

    # Open Port 22 (SSH) to the world
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 22, # SSH
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }
        ]
    )
    logger.info(f"️  EC2: Created Vulnerable Security Group '{sg_name}' ({sg_id}) with Ports 22/3389 OPEN")

    # 2.5 Register a Dummy AMI (LocalStack starts empty)
    try:
        image = ec2.register_image(
            Name='test-ami-linux',
            Description='Test AMI',
            RootDeviceName='/dev/sda1',
            BlockDeviceMappings=[{'DeviceName': '/dev/sda1', 'Ebs': {'VolumeSize': 8}}]
        )
        ami_id = image['ImageId']
        logger.info(f" EC2: Registered dummy AMI '{ami_id}'")
    except Exception:
        # Assuming it might already exist or fail, try to find it
        images = ec2.describe_images(Filters=[{'Name': 'name', 'Values': ['test-ami-linux']}])
        if images['Images']:
            ami_id = images['Images'][0]['ImageId']
            logger.info(f" EC2: Found existing AMI '{ami_id}'")
        else:
            # Fallback if registration failed and not found (shouldn't happen with correct params)
            ami_id = "ami-00000000" 

    # --- Asset A: Vulnerable SSH Host ---
    sg_ssh = ec2.create_security_group(GroupName="sg-ssh-open", Description="SSH Open", VpcId=vpc_id)['GroupId']
    ec2.authorize_security_group_ingress(
        GroupId=sg_ssh,
        IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
    )
    ec2.run_instances(
        ImageId=ami_id, InstanceType='t2.micro', MinCount=1, MaxCount=1, SecurityGroupIds=[sg_ssh],
        TagSpecifications=[{'ResourceType': 'instance', 'Tags': [{'Key': 'OS', 'Value': 'Ubuntu 20.04 LTS'}, {'Key': 'Name', 'Value': 'Bastion-Host'}]}]
    )
    logger.info(f"️  EC2: Launched SSH Host (SG: {sg_ssh})")

    # --- Asset B: Web Server (HTTP/HTTPS) ---
    sg_web = ec2.create_security_group(GroupName="sg-web-open", Description="Web Open", VpcId=vpc_id)['GroupId']
    ec2.authorize_security_group_ingress(
        GroupId=sg_web,
        IpPermissions=[
            {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
        ]
    )
    ec2.run_instances(
        ImageId=ami_id, InstanceType='t2.micro', MinCount=1, MaxCount=1, SecurityGroupIds=[sg_web],
        TagSpecifications=[{'ResourceType': 'instance', 'Tags': [{'Key': 'OS', 'Value': 'Amazon Linux 2'}, {'Key': 'Name', 'Value': 'Web-Frontend'}]}]
    )
    logger.info(f"️  EC2: Launched Web Server (SG: {sg_web})")

    # --- Asset C: Database (Misconfigured) ---
    sg_db = ec2.create_security_group(GroupName="sg-db-open", Description="DB Open", VpcId=vpc_id)['GroupId']
    ec2.authorize_security_group_ingress(
        GroupId=sg_db,
        IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 5432, 'ToPort': 5432, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
    )
    ec2.run_instances(
        ImageId=ami_id, InstanceType='t2.micro', MinCount=1, MaxCount=1, SecurityGroupIds=[sg_db],
        TagSpecifications=[{'ResourceType': 'instance', 'Tags': [{'Key': 'OS', 'Value': 'PostgreSQL 13 on Linux'}, {'Key': 'Name', 'Value': 'Prod-DB'}]}]
    )
    logger.info(f"️  EC2: Launched Database (SG: {sg_db})")

    # 4. Create "Shadow Asset" (Unattached Volume)
    # Create a volume but DO NOT attach it to anything
    vol = ec2.create_volume(
        AvailabilityZone=f"{REGION}a",
        Size=80, # 80 GB wasted
        VolumeType='gp2',
        Encrypted=False, # Vulnerability: Unencrypted
        TagSpecifications=[{'ResourceType': 'volume', 'Tags': [{'Key': 'Name', 'Value': 'Shadow-DB-Backup'}]}]
    )
    logger.info(f"️  EC2: Created Orphaned EBS Volume '{vol['VolumeId']}' (Shadow IT)")

    # 5. Create Unattached Elastic IP (Shadow Asset)
    eip = ec2.allocate_address(Domain='vpc')
    logger.info(f"️  EC2: Created Unattached Elastic IP '{eip['PublicIp']}' (Shadow IT)")

def create_iam_assets():
    iam = get_client('iam')

    # 1. Create a Privileged User
    username = "admin-backup-script"
    try:
        iam.create_user(UserName=username)
        iam.attach_user_policy(UserName=username, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        logger.info(f"️  IAM: Created user '{username}' with AdministratorAccess")
    except iam.exceptions.EntityAlreadyExistsException:
        logger.info(f"IAM User {username} already exists")

    # 2. Create a Risky Role
    rolename = "ec2-admin-role"
    try:
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
        }
        iam.create_role(RoleName=rolename, AssumeRolePolicyDocument=json.dumps(assume_role_policy))
        iam.attach_role_policy(RoleName=rolename, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        logger.info(f"️  IAM: Created Role '{rolename}' with AdministratorAccess")
    except iam.exceptions.EntityAlreadyExistsException:
        logger.info(f"IAM Role {rolename} already exists")

def create_api_gateway():
    apigateway = get_client('apigateway')
    
    name = "vulnerable-legacy-api"
    try:
        api = apigateway.create_rest_api(
            name=name,
            description="Legacy API with no auth",
            endpointConfiguration={'types': ['REGIONAL']}
        )
        logger.info(f"️  API: Created REST API '{name}' (No Auth)")
    except Exception as e:
        logger.info(f"API creation failed (might exist): {e}")

def create_secrets():
    sm = get_client('secretsmanager')
    
    name = "prod/db/password"
    try:
        sm.create_secret(
            Name=name,
            SecretString='{"username":"admin","password":"Password123!"}',
            Description="Production DB credentials"
        )
        logger.info(f" SecretsManager: Created secret '{name}'")
    except sm.exceptions.ResourceExistsException:
        logger.info(f"Secret {name} already exists")

if __name__ == "__main__":
    print("---  STARTING INFRASTRUCTURE POPULATION ---")
    try:
        create_s3_assets()
        create_network_assets()
        create_iam_assets()
        create_api_gateway()
        create_secrets()
        print("---  DONE. LocalStack is now vulnerable. ---")
    except Exception as e:
        logger.error(f"Failed to populate: {e}")