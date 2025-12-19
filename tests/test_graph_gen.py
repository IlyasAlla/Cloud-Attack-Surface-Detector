from src.python.orchestrator.core.normalizer import TargetResource, CloudProvider
from src.python.orchestrator.reporting.generator import ReportGenerator
import os

def test_graph_report_generation():
    print("Generating mock assets for graph...")
    assets = []

    # 1. EC2 Instance (Vulnerable)
    assets.append(TargetResource(
        id="i-0123456789abcdef0",
        ip_address="203.0.113.10",
        provider=CloudProvider.AWS,
        region="us-east-1",
        resource_type="EC2",
        hostname="web-prod-01",
        open_ports=[80, 443, 22],
        vulnerabilities={22: ["SSH Weak Ciphers"]},
        metadata={"OS": "Ubuntu 20.04", "Type": "t3.medium"}
    ))

    # 2. S3 Bucket (Public)
    assets.append(TargetResource(
        id="company-backups-public",
        ip_address="N/A",
        provider=CloudProvider.AWS,
        region="us-east-1",
        resource_type="S3",
        vulnerabilities={"bucket": ["Public Read Access"]},
        metadata={"Size": "500GB", "Type": "Standard"}
    ))

    # 3. IAM Role (Admin)
    assets.append(TargetResource(
        id="arn:aws:iam::123456789012:role/AdminRole",
        ip_address="N/A",
        provider=CloudProvider.AWS,
        region="global",
        resource_type="IAM",
        metadata={"Type": "Role", "Arn": "arn:aws:iam::123456789012:role/AdminRole"}
    ))

    # 4. Shadow Asset
    assets.append(TargetResource(
        id="dev-test-server",
        ip_address="192.168.1.50",
        provider=CloudProvider.AWS,
        region="us-west-2",
        resource_type="EC2",
        metadata={"Shadow": "True", "Owner": "dev-team"}
    ))

    print(f"Created {len(assets)} mock assets.")

    # Generate Report
    gen = ReportGenerator()
    output_file = "graph_report_test.html"
    gen.generate_html(assets, output_file=output_file, template_name="graph_view.html")
    
    if os.path.exists(output_file):
        print(f" Graph Report successfully generated: {output_file}")
        print(f"File size: {os.path.getsize(output_file)} bytes")
    else:
        print(" Failed to generate report.")

if __name__ == "__main__":
    test_graph_report_generation()
