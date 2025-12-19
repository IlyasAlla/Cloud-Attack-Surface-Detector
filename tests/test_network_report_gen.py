from src.python.orchestrator.core.normalizer import TargetResource, CloudProvider
from src.python.orchestrator.reporting.generator import ReportGenerator
import os

def test_network_report_generation():
    print("Generating mock network assets...")
    assets = []

    # 1. Web Server (Secure)
    assets.append(TargetResource(
        id="web-prod-01",
        ip_address="192.168.1.10",
        provider=CloudProvider.NETWORK,
        region="local",
        resource_type="Server",
        open_ports=[80, 443],
        banners={80: "nginx/1.18.0", 443: "nginx/1.18.0"},
        http_headers={
            443: {
                "Server": "nginx",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'self'"
            }
        },
        ssl_info={
            443: {
                "Subject": "CN=example.com",
                "Issuer": "CN=Let's Encrypt R3",
                "Expires": "2025-01-01",
                "Status": "Valid",
                "DNSNames": "example.com, www.example.com"
            }
        }
    ))

    # 2. Legacy Server (Vulnerable)
    assets.append(TargetResource(
        id="legacy-app-01",
        ip_address="192.168.1.20",
        provider=CloudProvider.NETWORK,
        region="local",
        resource_type="Server",
        open_ports=[80, 8080, 21],
        banners={21: "vsFTPd 2.3.4", 8080: "Apache Tomcat/7.0"},
        http_headers={
            8080: {
                "Server": "Apache-Coyote/1.1"
                # Missing security headers
            }
        },
        vulnerabilities={
            21: ["Anonymous FTP Login Allowed"],
            8080: ["Default Credentials: admin/admin"]
        }
    ))

    # 3. Database Server
    assets.append(TargetResource(
        id="db-internal-01",
        ip_address="192.168.1.30",
        provider=CloudProvider.NETWORK,
        region="local",
        resource_type="Database",
        open_ports=[5432],
        banners={5432: "PostgreSQL 13.3"}
    ))

    print(f"Created {len(assets)} mock assets.")

    # Generate Report
    gen = ReportGenerator()
    output_file = "network_report_test.html"
    # Note: template_name="report.html" is the default, but being explicit
    gen.generate_html(assets, output_file=output_file, template_name="report.html")
    
    if os.path.exists(output_file):
        print(f" Report successfully generated: {output_file}")
        print(f"File size: {os.path.getsize(output_file)} bytes")
    else:
        print(" Failed to generate report.")

if __name__ == "__main__":
    test_network_report_generation()
