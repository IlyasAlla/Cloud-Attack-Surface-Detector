from src.python.orchestrator.core.normalizer import TargetResource, CloudProvider
from src.python.orchestrator.reporting.generator import ReportGenerator
import os

def test_cloud_report_generation():
    print("Generating mock assets...")
    assets = []

    # 1. EC2 Instance (Web Server)
    assets.append(TargetResource(
        id="i-0123456789abcdef0",
        ip_address="54.214.247.189",
        hostname="ec2-54-214-247-189.compute-1.amazonaws.com",
        provider=CloudProvider.AWS,
        region="us-east-1",
        resource_type="EC2 Instance",
        open_ports=[80, 443],
        metadata={"OS": "Amazon Linux 2", "MAC": "0a:1b:2c:3d:4e:5f", "State": "running"},
        vulnerabilities={"Web": ["Missing Security Headers"]}
    ))

    # 2. S3 Bucket (Public)
    assets.append(TargetResource(
        id="public-collab-data-leak",
        ip_address="N/A",
        hostname="public-collab-data-leak.s3.amazonaws.com",
        provider=CloudProvider.AWS,
        region="global",
        resource_type="S3 Bucket",
        vulnerabilities={"Storage": ["Public ACL: AllUsers", "Public ACL: AuthenticatedUsers"]}
    ))

    # 3. IAM User (Admin)
    assets.append(TargetResource(
        id="admin-backup-script",
        ip_address="N/A",
        hostname="N/A",
        provider=CloudProvider.AWS,
        region="global",
        resource_type="IAM User",
        metadata={"Arn": "arn:aws:iam::123456789012:user/admin-backup-script"},
        vulnerabilities={"Identity": ["Excessive Privilege: AdministratorAccess"]}
    ))

    # 4. API Gateway (Unauth)
    assets.append(TargetResource(
        id="vulnerable-legacy-api",
        ip_address="N/A",
        hostname="xyz123.execute-api.us-east-1.amazonaws.com",
        provider=CloudProvider.AWS,
        region="us-east-1",
        resource_type="API Gateway",
        vulnerabilities={"API": ["Unauthenticated Endpoint"]}
    ))

    # 5. Shadow Asset (Unattached Volume)
    assets.append(TargetResource(
        id="vol-0abcdef1234567890",
        ip_address="N/A",
        hostname="N/A",
        provider=CloudProvider.AWS,
        region="us-east-1",
        resource_type="EBS Volume",
        metadata={"Size": "80 GB", "Type": "gp2"},
        vulnerabilities={"Storage": ["Shadow Asset: Unattached Volume", "Unencrypted Volume"]}
    ))

    print(f"Created {len(assets)} mock assets.")

    # Generate Report
    gen = ReportGenerator()
    output_file = "cloud_report_test.html"
    gen.generate_html(assets, output_file=output_file, template_name="cloud_report.html")
    
    if os.path.exists(output_file):
        print(f" Report successfully generated: {output_file}")
        # Optional: Print size
        print(f"File size: {os.path.getsize(output_file)} bytes")
    else:
        print(" Failed to generate report.")

if __name__ == "__main__":
    test_cloud_report_generation()
