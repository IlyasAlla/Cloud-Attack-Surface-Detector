import os
import sys
import json
import asyncio
import typer
from typing import List, Optional, Any
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.panel import Panel

from ..core.cloud_matcher import CloudMatcher
from ..core.types import UnifiedAsset
from .wrappers import ToolWrappers

# Initialize Typer app and Rich console
app = typer.Typer(help="External Cloud Attack Surface Scanner")
console = Console()

class ExternalScanner:
    def __init__(self, concurrency: int = 10):
        # Define paths
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.project_root = os.path.abspath(os.path.join(self.base_dir, "../../../../../cloud-attack-surface-detector"))
        self.bin_dir = os.path.join(self.project_root, "bin")
        
        self.cloud_enum_script = os.path.join(
            self.project_root, 
            "src/python/orchestrator/tools/cloud_enum/cloud_enum.py"
        )
        
        self.cloud_matcher = CloudMatcher()
        self.wrappers = ToolWrappers(self.bin_dir, self.cloud_enum_script)
        
        # Concurrency limit
        self.semaphore = asyncio.Semaphore(concurrency)

    def _check_dependencies(self):
        missing = self.wrappers.check_dependencies()
        if missing:
            console.print(f"[bold red][!] WARNING: The following tools are missing: {', '.join(missing)}[/bold red]")
            console.print("[bold red][!] Scan may be incomplete.[/bold red]")
        else:
            console.print("[bold green][+] All dependencies verified.[/bold green]")

    async def _scan_port_async(self, asset: dict, progress: Progress, task_id: Any) -> dict:
        async with self.semaphore:
            ip = asset['ip']
            ports = await self.wrappers.run_naabu(ip)
            asset['ports'] = ports
            progress.advance(task_id)
            return asset

    async def scan_ips(self, ips: List[str], domain: str = None) -> List[UnifiedAsset]:
        """
        Scan a list of IPs directly.
        Skips Subdomain Discovery (Step A) and Resolution (Step B).
        Starts at Cloud Filtering (Step C).
        """
        console.print(Panel.fit(f"[bold blue]Starting External Cloud Scan for {len(ips)} IPs[/bold blue]"))
        self._check_dependencies()
        
        unified_assets: List[UnifiedAsset] = []

        # Step C: Cloud Filtering
        with console.status("[bold cyan]Step C: Cloud Filtering (CloudMatcher)...[/bold cyan]"):
            valid_targets = []
            for ip in ips:
                # Create a minimal asset dict
                asset = {'ip': ip, 'host': ''}
                provider = self.cloud_matcher.get_provider(ip)
                if provider:
                    asset['provider'] = provider
                    valid_targets.append(asset)
        
        console.print(f"[green][+] Found {len(valid_targets)} Valid Cloud Targets from {len(ips)} IPs.[/green]")
        if not valid_targets:
            console.print("[bold red][-] No valid cloud targets found. Stopping scan.[/bold red]")
            return []

        # Step D: Port Scanning (Parallel)
        console.print("[bold cyan]Step D: Port Scanning (Naabu - Parallel)...[/bold cyan]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task_id = progress.add_task("[cyan]Scanning Ports...", total=len(valid_targets))
            tasks = [self._scan_port_async(asset, progress, task_id) for asset in valid_targets]
            valid_targets = await asyncio.gather(*tasks)

        # Step E: Cloud Enumeration (SkyScan)
        # Only run if we have a domain
        cloud_findings = []
        if domain:
            with console.status("[bold cyan]Step E: Cloud Enumeration (SkyScan - Go)...[/bold cyan]"):
                # Use the keyword from the domain (e.g. "alphastra" from "alphastra.com")
                keyword = domain.split('.')[0]
                cloud_findings = await self.wrappers.run_skyscan(keyword)
        
        # Merge SkyScan findings into valid targets for Nuclei?
        # SkyScan finds buckets/storage, which are URLs.
        # Nuclei can scan URLs.
        for finding in cloud_findings:
            if finding.get('status') == 200:
                url = finding.get('url')
                # Add to nuclei targets
                nuclei_targets.append(url)
                
                # Add to assets list
                asset = {
                    'ip': 'N/A', # It's a URL
                    'host': url,
                    'provider': finding.get('provider'),
                    'ports': [80, 443]
                }
                
                # Check for files
                if finding.get('files'):
                    asset['metadata'] = {'files': finding.get('files')}
                    console.print(f"[bold red]  [!] Found {len(finding.get('files'))} exposed files in {url}[/bold red]")
                
                valid_targets.append(asset)

        # Step E.2: Subdomain Cloud Mapping (CNAME Analysis)
        with console.status("[bold cyan]Step E.2: Mapping Subdomains to Cloud Providers...[/bold cyan]"):
            # We need the dnsx results (typically in a JSON file if -json was used)
            # Or we can re-run dnsx for CNAMEs specifically if we didn't capture them.
            # Wrapper runs dnsx with -json -o dnsx_output.json usually?
            # Let's check wrappers.py _run_command. It returns stdout.
            pass 
            # In current implementation, wrappers.resolve_subdomains returns list of IPs.
            # We need the raw DNS data.
            # For this MVP, let's assume we can't easily get it from the previous step without refactoring wrappers.
            # We will do a quick lookup on the resolved subdomains.
            import dns.resolver

            for ip in valid_targets:
                if ip.get('host'):
                    host = ip.get('host')
                    try:
                        answers = dns.resolver.resolve(host, 'CNAME')
                        for rdata in answers:
                            cname = str(rdata.target).rstrip('.')
                            ip['cname'] = cname
                            
                            # Check for Cloud Providers
                            if "amazonaws.com" in cname:
                                ip['provider'] = "AWS (CNAME)"
                                if "s3" in cname: ip['service'] = "S3"
                                elif "elb" in cname: ip['service'] = "ELB"
                                elif "cloudfront" in cname: ip['service'] = "CloudFront"
                                elif "elasticbeanstalk" in cname: ip['service'] = "ElasticBeanstalk"
                                
                            elif "azure" in cname or "windows.net" in cname:
                                ip['provider'] = "Azure (CNAME)"
                                if "blob" in cname: ip['service'] = "BlobStorage"
                                elif "azurewebsites" in cname: ip['service'] = "AppService"
                                
                            elif "google" in cname or "googleapis" in cname:
                                ip['provider'] = "GCP (CNAME)"
                                
                            if 'provider' in ip:
                                console.print(f"[yellow]  Mapped {host} -> {cname} ({ip['provider']})[/yellow]")
                    except Exception:
                        pass

        # Step F: Vulnerability Scan
        with console.status("[bold cyan]Step F: Vulnerability Scan (Nuclei)...[/bold cyan]"):
            nuclei_targets = []
            for asset in valid_targets:
                ip = asset['ip']
                for port in asset.get('ports', []):
                    nuclei_targets.append(f"{ip}:{port}")
            
            nuclei_findings = await self.wrappers.run_nuclei(nuclei_targets)

        # Data Normalization
        for asset_data in valid_targets:
            ip = asset_data['ip']
            asset_vulns = [v for v in nuclei_findings if ip in v.get('matched_at', '')]
            
            unified_asset = UnifiedAsset(
                asset_type="External",
                ip=ip,
                domain=asset_data.get('host'),
                provider=asset_data.get('provider'),
                ports=asset_data.get('ports', []),
                vulnerabilities=asset_vulns,
                metadata={"scan_mode": "ip_direct"}
            )
            unified_assets.append(unified_asset)

        return unified_assets

    async def run_external_recon(self, domain: str, output_file: Optional[str] = None) -> List[UnifiedAsset]:
        console.print(Panel.fit(f"[bold blue]Starting External Recon for: {domain}[/bold blue]"))
        self._check_dependencies()
        
        unified_assets: List[UnifiedAsset] = []

        # Step A: Subdomain Discovery
        with console.status("[bold cyan]Step A: Subdomain Discovery (Subfinder)...[/bold cyan]"):
            subdomains = await self.wrappers.run_subfinder(domain)
        console.print(f"[green][+] Found {len(subdomains)} subdomains.[/green]")

        # Step B: Resolution
        with console.status("[bold cyan]Step B: Resolution (DNSx)...[/bold cyan]"):
            resolved_assets = await self.wrappers.run_dnsx(subdomains)
        console.print(f"[green][+] Resolved {len(resolved_assets)} IPs.[/green]")

        # Step C: Cloud Filtering
        with console.status("[bold cyan]Step C: Cloud Filtering (CloudMatcher)...[/bold cyan]"):
            valid_targets = []
            for asset in resolved_assets:
                ip = asset['ip']
                provider = self.cloud_matcher.get_provider(ip)
                if provider:
                    asset['provider'] = provider
                    valid_targets.append(asset)
        
        console.print(f"[green][+] Found {len(valid_targets)} Valid Cloud Targets.[/green]")
        if not valid_targets:
            console.print("[bold red][-] No valid cloud targets found. Stopping scan.[/bold red]")
            return []

        # Step D: Port Scanning (Parallel)
        console.print("[bold cyan]Step D: Port Scanning (Naabu - Parallel)...[/bold cyan]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task_id = progress.add_task("[cyan]Scanning Ports...", total=len(valid_targets))
            tasks = [self._scan_port_async(asset, progress, task_id) for asset in valid_targets]
            valid_targets = await asyncio.gather(*tasks)

        # Step E: Cloud Enumeration
        with console.status("[bold cyan]Step E: Cloud Enumeration (Cloud_enum)...[/bold cyan]"):
            keyword = domain.split('.')[0]
            cloud_enum_output_file = os.path.join(self.project_root, f"cloud_enum_{keyword}.json")
            await self.wrappers.run_cloud_enum(keyword, domain, cloud_enum_output_file)
            
            cloud_enum_findings = []
            if os.path.exists(cloud_enum_output_file):
                try:
                    with open(cloud_enum_output_file, 'r') as f:
                        cloud_enum_findings = json.load(f)
                except Exception:
                    pass

        # Step F: Vulnerability Scan
        with console.status("[bold cyan]Step F: Vulnerability Scan (Nuclei)...[/bold cyan]"):
            nuclei_targets = []
            for asset in valid_targets:
                ip = asset['ip']
                for port in asset.get('ports', []):
                    nuclei_targets.append(f"{ip}:{port}")
            
            nuclei_findings = await self.wrappers.run_nuclei(nuclei_targets)

        # Data Normalization
        for asset_data in valid_targets:
            ip = asset_data['ip']
            asset_vulns = [v for v in nuclei_findings if ip in v.get('matched_at', '')]
            
            unified_asset = UnifiedAsset(
                asset_type="External",
                ip=ip,
                domain=asset_data.get('host'),
                provider=asset_data.get('provider'),
                ports=asset_data.get('ports', []),
                vulnerabilities=asset_vulns,
                metadata={"cloud_enum_findings": cloud_enum_findings}
            )
            unified_assets.append(unified_asset)

        # Result Persistence
        if not output_file:
            output_file = os.path.join(self.project_root, f"results_{domain}.json")
            
        with open(output_file, 'w') as f:
            json.dump([asset.dict() for asset in unified_assets], f, indent=4)
        console.print(f"[bold green][+] Results saved to {output_file}[/bold green]")

        return unified_assets

    def print_summary(self, assets: List[UnifiedAsset]):
        table = Table(title="Scan Summary")
        table.add_column("IP", style="cyan")
        table.add_column("Provider", style="magenta")
        table.add_column("Ports", style="green")
        table.add_column("Vulns", style="red")

        for asset in assets:
            table.add_row(
                asset.ip,
                asset.provider,
                str(len(asset.ports)),
                str(len(asset.vulnerabilities))
            )
        console.print(table)

@app.command()
def scan(
    domain: str = typer.Argument(..., help="Target domain to scan"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Path to save JSON results"),
    concurrency: int = typer.Option(10, "--concurrency", "-c", help="Number of concurrent port scans"),
):
    """
    Run the External Cloud Attack Surface Scanner.
    """
    scanner = ExternalScanner(concurrency=concurrency)
    
    try:
        assets = asyncio.run(scanner.run_external_recon(domain, output))
        scanner.print_summary(assets)
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Scan interrupted by user.[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red][!] An error occurred: {e}[/bold red]")

if __name__ == "__main__":
    app()
