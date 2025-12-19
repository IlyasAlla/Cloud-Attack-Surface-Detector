import boto3
from typing import Dict, Any, List
from rich.console import Console

console = Console()

class AWS_Enumerator:
    def __init__(self, session: boto3.Session):
        self.session = session

    def enumerate_all(self) -> Dict[str, Any]:
        data = {
            "s3": self.enumerate_s3(),
            "iam": self.enumerate_iam(),
            "ec2": self.enumerate_ec2()
        }
        return data

    def enumerate_s3(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            s3 = self.session.client('s3')
            response = s3.list_buckets()
            
            console.print(f"[cyan]Scanning {len(response.get('Buckets', []))} S3 Buckets...[/cyan]")
            
            for bucket in response.get('Buckets', []):
                name = bucket['Name']
                info = {"name": name, "public_access_block": False}
                
                # Check Public Access Block
                try:
                    pab = s3.get_public_access_block(Bucket=name)
                    conf = pab.get('PublicAccessBlockConfiguration', {})
                    if conf.get('BlockPublicAcls') and conf.get('IgnorePublicAcls') and conf.get('BlockPublicPolicy') and conf.get('RestrictPublicBuckets'):
                        info['public_access_block'] = True
                except Exception:
                    pass # Metadata check might fail if not permitted or not set
                
                findings.append(info)
        except Exception as e:
            console.print(f"[red]S3 Enumeration Error: {e}[/red]")
        return findings

    def enumerate_iam(self) -> Dict[str, Any]:
        findings = {"users": [], "roles": [], "mfa_summary": {"users_without_mfa": 0}}
        try:
            iam = self.session.client('iam')
            
            # Users
            users = iam.list_users()
            for user in users.get('Users', []):
                u_info = {"name": user['UserName'], "has_mfa": False}
                
                # Check MFA
                mfa = iam.list_mfa_devices(UserName=user['UserName'])
                if mfa.get('MFADevices'):
                    u_info['has_mfa'] = True
                else:
                    findings['mfa_summary']['users_without_mfa'] += 1
                    
                findings['users'].append(u_info)

            # Roles (Limit to 20 for brevity)
            roles = iam.list_roles()
            for role in roles.get('Roles', [])[:20]:
                findings['roles'].append(role['RoleName'])
                
        except Exception as e:
            console.print(f"[red]IAM Enumeration Error: {e}[/red]")
        return findings

    def enumerate_ec2(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            # EC2 is region specific. We use the session region.
            ec2 = self.session.client('ec2')
            
            # Instances
            instances = ec2.describe_instances()
            for reservation in instances.get('Reservations', []):
                for inst in reservation.get('Instances', []):
                    findings.append({
                        "id": inst['InstanceId'],
                        "state": inst['State']['Name'],
                        "public_ip": inst.get('PublicIpAddress', 'N/A')
                    })
            
            # Security Groups (Check for 0.0.0.0/0 on sensitive ports)
            sgs = ec2.describe_security_groups()
            for sg in sgs.get('SecurityGroups', []):
                for perm in sg.get('IpPermissions', []):
                    from_port = perm.get('FromPort')
                    if from_port in [22, 3389]:
                        for ip_range in perm.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                console.print(f"[bold red]  [!] SG {sg['GroupId']} allows 0.0.0.0/0 on port {from_port}[/bold red]")
                                # Store risk? For now just log
        except Exception as e:
            console.print(f"[red]EC2 Enumeration Error: {e}[/red]")
        return findings
