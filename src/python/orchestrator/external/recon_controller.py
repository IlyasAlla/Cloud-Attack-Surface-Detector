"""
ReconController - The Master Orchestrator

This module orchestrates all reconnaissance tools (both built and integrated)
to provide a unified attack surface discovery pipeline.
"""

import asyncio
import json
import os
import tempfile
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.panel import Panel

console = Console()


class AssetType(Enum):
    STORAGE_BUCKET = "storage_bucket"
    WEB_ENDPOINT = "web_endpoint"
    API_ENDPOINT = "api_endpoint"
    CLOUD_RESOURCE = "cloud_resource"
    SECRET = "secret"
    VULNERABILITY = "vulnerability"


@dataclass
class DiscoveredAsset:
    """Unified representation of a discovered asset."""
    asset_type: AssetType
    url: str
    provider: Optional[str]
    permissions: Optional[str]
    severity: str
    metadata: Dict[str, Any]
    source: str  # Which tool discovered this


class ReconController:
    """
    Master orchestrator for the Cloud Attack Surface Framework.
    
    Coordinates:
    - OmniStore (Go): Cloud storage enumeration
    - Katana: Headless web crawling
    - Nuclei: Vulnerability scanning
    - TruffleHog: Secret verification
    - NetMapper: IP attribution
    """
    
    def __init__(self, tool_wrappers, cloud_matcher=None):
        """
        Initialize the ReconController.
        
        Args:
            tool_wrappers: ToolWrappers instance with access to all binaries
            cloud_matcher: CloudMatcher instance for IP attribution
        """
        self.wrappers = tool_wrappers
        self.cloud_matcher = cloud_matcher
        self.discovered_assets: List[DiscoveredAsset] = []
    
    async def run_full_recon(
        self,
        target: str,
        enable_storage_enum: bool = True,
        enable_web_crawl: bool = True,
        enable_vuln_scan: bool = True,
        enable_secret_scan: bool = True,
        headless: bool = True,
        output_file: Optional[str] = None
    ) -> List[DiscoveredAsset]:
        """
        Execute the full reconnaissance pipeline.
        
        Args:
            target: Target domain or keyword
            enable_storage_enum: Enable cloud storage enumeration
            enable_web_crawl: Enable web crawling (Katana)
            enable_vuln_scan: Enable vulnerability scanning (Nuclei)
            enable_secret_scan: Enable secret scanning (TruffleHog)
            headless: Use headless browser for crawling
            output_file: Path to save results
            
        Returns:
            List of all discovered assets
        """
        console.print(Panel.fit(
            f"[bold cyan] Starting Full Reconnaissance on {target}[/bold cyan]",
            border_style="cyan"
        ))
        
        self.discovered_assets = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            
            # Phase 1: Storage Enumeration
            if enable_storage_enum:
                task = progress.add_task("[cyan]Phase 1: Cloud Storage Enumeration...", total=100)
                storage_assets = await self._run_storage_enum(target)
                self.discovered_assets.extend(storage_assets)
                progress.update(task, completed=100)
                console.print(f"[green]   Found {len(storage_assets)} storage assets[/green]")
            
            # Phase 2: Web Crawling
            if enable_web_crawl:
                task = progress.add_task("[cyan]Phase 2: Web Crawling (Katana)...", total=100)
                web_assets = await self._run_web_crawl(target, headless)
                self.discovered_assets.extend(web_assets)
                progress.update(task, completed=100)
                console.print(f"[green]   Found {len(web_assets)} web endpoints[/green]")
            
            # Phase 3: Vulnerability Scanning
            if enable_vuln_scan:
                task = progress.add_task("[cyan]Phase 3: Vulnerability Scanning (Nuclei)...", total=100)
                vuln_assets = await self._run_vuln_scan()
                self.discovered_assets.extend(vuln_assets)
                progress.update(task, completed=100)
                console.print(f"[green]   Found {len(vuln_assets)} vulnerabilities[/green]")
            
            # Phase 4: Secret Scanning
            if enable_secret_scan:
                task = progress.add_task("[cyan]Phase 4: Secret Scanning (TruffleHog)...", total=100)
                secret_assets = await self._run_secret_scan(target)
                self.discovered_assets.extend(secret_assets)
                progress.update(task, completed=100)
                console.print(f"[green]   Found {len(secret_assets)} secrets[/green]")
        
        # Save results
        if output_file:
            self._save_results(output_file)
        
        # Print summary
        self._print_summary()
        
        return self.discovered_assets
    
    async def _run_storage_enum(self, keyword: str) -> List[DiscoveredAsset]:
        """Run cloud storage enumeration using SkyScan/OmniStore."""
        assets = []
        
        try:
            # Use SkyScan for now (OmniStore when built)
            results = await self.wrappers.run_skyscan(keyword)
            
            for result in results:
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.STORAGE_BUCKET,
                    url=result.get('url', ''),
                    provider=result.get('provider', 'Unknown'),
                    permissions=result.get('permissions', 'Unknown'),
                    severity=self._classify_storage_severity(result),
                    metadata={
                        'files': result.get('files', []),
                        'status': result.get('status'),
                        'size': result.get('size')
                    },
                    source='skyscan'
                ))
        except Exception as e:
            console.print(f"[yellow]   Storage enum error: {e}[/yellow]")
        
        return assets
    
    async def _run_web_crawl(self, target: str, headless: bool) -> List[DiscoveredAsset]:
        """Run web crawling using Katana."""
        assets = []
        
        try:
            # Ensure target has protocol
            if not target.startswith('http'):
                target = f"https://{target}"
            
            endpoints = await self.wrappers.run_katana(
                target=target,
                headless=headless,
                depth=3,
                js_crawl=True
            )
            
            for endpoint in endpoints:
                url = endpoint.get('url', '')
                if not url:
                    continue
                    
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.WEB_ENDPOINT,
                    url=url,
                    provider=None,
                    permissions=None,
                    severity='INFO',
                    metadata={
                        'method': endpoint.get('method', 'GET'),
                        'source': endpoint.get('source', ''),
                        'tag': endpoint.get('tag', '')
                    },
                    source='katana'
                ))
        except Exception as e:
            console.print(f"[yellow]   Web crawl error: {e}[/yellow]")
        
        return assets
    
    async def _run_vuln_scan(self) -> List[DiscoveredAsset]:
        """Run vulnerability scanning using Nuclei on discovered assets."""
        assets = []
        
        # Get URLs from discovered web endpoints
        web_urls = [
            a.url for a in self.discovered_assets 
            if a.asset_type == AssetType.WEB_ENDPOINT
        ]
        
        if not web_urls:
            return assets
        
        try:
            vulns = await self.wrappers.run_nuclei(web_urls[:100])  # Limit for performance
            
            for vuln in vulns:
                severity = vuln.get('severity', 'info').upper()
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.VULNERABILITY,
                    url=vuln.get('matched_at', ''),
                    provider=None,
                    permissions=None,
                    severity=severity,
                    metadata={
                        'name': vuln.get('name'),
                        'template_id': vuln.get('template_id')
                    },
                    source='nuclei'
                ))
        except Exception as e:
            console.print(f"[yellow]   Vuln scan error: {e}[/yellow]")
        
        return assets
    
    async def _run_secret_scan(self, target: str) -> List[DiscoveredAsset]:
        """Run secret scanning using TruffleHog."""
        assets = []
        
        # Scan any discovered public storage buckets
        storage_buckets = [
            a for a in self.discovered_assets 
            if a.asset_type == AssetType.STORAGE_BUCKET 
            and a.permissions in ['PUBLIC_READ', 'PUBLIC_LIST', 'PUBLIC']
        ]
        
        for bucket in storage_buckets:
            try:
                # Extract bucket name for S3 scanning
                if 's3.amazonaws.com' in bucket.url:
                    secrets = await self.wrappers.run_trufflehog_s3(
                        bucket_name=bucket.url.split('.')[0].replace('http://', ''),
                        verify=True
                    )
                    
                    for secret in secrets:
                        assets.append(DiscoveredAsset(
                            asset_type=AssetType.SECRET,
                            url=bucket.url,
                            provider=bucket.provider,
                            permissions=None,
                            severity='CRITICAL' if secret.get('verified') else 'HIGH',
                            metadata={
                                'detector': secret.get('detector'),
                                'verified': secret.get('verified'),
                                'file': secret.get('file')
                            },
                            source='trufflehog'
                        ))
            except Exception as e:
                console.print(f"[yellow]   Secret scan error for {bucket.url}: {e}[/yellow]")
        
        return assets
    
    def _classify_storage_severity(self, result: Dict) -> str:
        """Classify the severity of a storage finding."""
        perms = result.get('permissions', '').upper()
        
        if 'WRITE' in perms:
            return 'CRITICAL'
        elif perms in ['PUBLIC_READ', 'PUBLIC_LIST', 'PUBLIC']:
            return 'HIGH'
        elif perms in ['AUTHENTICATED', 'PROTECTED']:
            return 'MEDIUM'
        else:
            return 'INFO'
    
    def _save_results(self, output_file: str):
        """Save results to JSON file."""
        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        
        results = []
        for asset in self.discovered_assets:
            asset_dict = {
                'asset_type': asset.asset_type.value,
                'url': asset.url,
                'provider': asset.provider,
                'permissions': asset.permissions,
                'severity': asset.severity,
                'metadata': asset.metadata,
                'source': asset.source
            }
            results.append(asset_dict)
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        console.print(f"[green]   Results saved to {output_file}[/green]")
    
    def _print_summary(self):
        """Print a summary table of discovered assets."""
        console.print("\n")
        
        # Count by type
        type_counts = {}
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        
        for asset in self.discovered_assets:
            type_name = asset.asset_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
            severity_counts[asset.severity] = severity_counts.get(asset.severity, 0) + 1
        
        # Summary table
        table = Table(title=" Reconnaissance Summary", show_header=True)
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="green")
        
        for asset_type, count in type_counts.items():
            table.add_row(asset_type, str(count))
        
        table.add_row("─" * 20, "─" * 10)
        table.add_row("[bold]Total[/bold]", f"[bold]{len(self.discovered_assets)}[/bold]")
        
        console.print(table)
        
        # Severity breakdown
        severity_table = Table(title="️ Severity Breakdown", show_header=True)
        severity_table.add_column("Severity", style="bold")
        severity_table.add_column("Count")
        
        severity_colors = {
            'CRITICAL': 'red',
            'HIGH': 'orange1',
            'MEDIUM': 'yellow',
            'LOW': 'blue',
            'INFO': 'dim'
        }
        
        for sev, count in severity_counts.items():
            if count > 0:
                color = severity_colors.get(sev, 'white')
                severity_table.add_row(f"[{color}]{sev}[/{color}]", str(count))
        
        console.print(severity_table)
        
        # Top critical findings
        critical_assets = [a for a in self.discovered_assets if a.severity in ['CRITICAL', 'HIGH']]
        if critical_assets:
            console.print(f"\n[red] Top Critical Findings ({len(critical_assets)} total):[/red]")
            for i, asset in enumerate(critical_assets[:5]):
                console.print(f"  [{asset.severity}] {asset.asset_type.value}: {asset.url}")
    
    async def quick_storage_scan(self, keyword: str) -> List[DiscoveredAsset]:
        """Quick storage-only scan for fast enumeration."""
        return await self._run_storage_enum(keyword)
    
    async def quick_web_scan(self, target: str) -> List[DiscoveredAsset]:
        """Quick web crawl only."""
        return await self._run_web_crawl(target, headless=False)
