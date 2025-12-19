#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ██████╗██╗      ██████╗ ██╗   ██╗██████╗      █████╗ ███████╗███████╗       ║
║  ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗    ██╔══██╗██╔════╝██╔════╝       ║
║  ██║     ██║     ██║   ██║██║   ██║██║  ██║    ███████║███████╗█████╗         ║
║  ██║     ██║     ██║   ██║██║   ██║██║  ██║    ██╔══██║╚════██║██╔══╝         ║
║  ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝    ██║  ██║███████║██║            ║
║   ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝     ╚═╝  ╚═╝╚══════╝╚═╝            ║
║                                                                               ║
║                  Cloud Attack Surface Framework v2.0                          ║
║           The Most Powerful Cloud Pentesting Tool in the World                ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Professional cloud attack surface discovery and analysis framework.
Supports AWS, Azure, GCP, DigitalOcean, Heroku, Cloudflare, and 10+ more providers.
"""

import typer
import asyncio
import logging
import os
import json
import sys
from typing import Optional, List
from enum import Enum
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich import box

# Configure Logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

console = Console()

# ASCII Banner
BANNER = """
[bold cyan]
   ██████╗██╗      ██████╗ ██╗   ██╗██████╗ 
  ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗
  ██║     ██║     ██║   ██║██║   ██║██║  ██║
  ██║     ██║     ██║   ██║██║   ██║██║  ██║
  ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝
   ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ 
[/bold cyan]
[bold white]       Attack Surface Framework v2.0 [/bold white]
[dim]  AWS • Azure • GCP • 100+ Cloud Services[/dim]
"""

# Create main app and subcommands
app = typer.Typer(
    name="cloud-asf",
    help="️ Cloud Attack Surface Framework - Ultimate Cloud Pentesting Tool",
    add_completion=False,
    rich_markup_mode="rich"
)

# Subcommand groups
recon_app = typer.Typer(help=" External reconnaissance commands")
storage_app = typer.Typer(help=" Cloud storage enumeration")
secrets_app = typer.Typer(help=" Secret detection and scanning")
audit_app = typer.Typer(help=" Authenticated cloud auditing")

app.add_typer(recon_app, name="recon")
app.add_typer(storage_app, name="storage")
app.add_typer(secrets_app, name="secrets")
app.add_typer(audit_app, name="audit")


class OutputFormat(str, Enum):
    json = "json"
    table = "table"
    csv = "csv"
    html = "html"


class ScanMode(str, Enum):
    fast = "fast"
    normal = "normal"
    deep = "deep"
    stealth = "stealth"


def print_banner():
    """Print the professional CLI banner."""
    console.print(BANNER)


def get_output_path(output: Optional[str], prefix: str) -> str:
    """Generate output path with timestamp if not specified."""
    if output:
        return output
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs("reports", exist_ok=True)
    return f"reports/{prefix}_{timestamp}.json"


# ============================================================================
#                          MAIN SCAN COMMAND
# ============================================================================

@app.command(name="scan")
def full_scan(
    target: str = typer.Argument(..., help="Target keyword, domain, or CIDR range"),
    
    # Scan options
    mode: ScanMode = typer.Option(ScanMode.normal, "--mode", "-m", help="Scan mode"),
    threads: int = typer.Option(50, "--threads", "-t", help="Number of concurrent threads"),
    timeout: int = typer.Option(10, "--timeout", help="Request timeout in seconds"),
    
    # Module toggles
    storage: bool = typer.Option(True, "--storage/--no-storage", help="Enable storage enumeration"),
    services: bool = typer.Option(True, "--services/--no-services", help="Enable cloud service discovery"),
    subdomains: bool = typer.Option(True, "--subdomains/--no-subdomains", help="Enable subdomain enumeration"),
    crawl: bool = typer.Option(False, "--crawl", "-c", help="Enable web crawling (Katana)"),
    secrets: bool = typer.Option(True, "--secrets/--no-secrets", help="Enable secret scanning"),
    vulns: bool = typer.Option(True, "--vulns/--no-vulns", help="Enable vulnerability scanning"),
    
    # Output
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: OutputFormat = typer.Option(OutputFormat.table, "--format", "-f", help="Output format"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode (minimal output)"),
    
    # Advanced
    mutations: Optional[str] = typer.Option(None, "--mutations", help="Custom mutations (comma-separated)"),
    resolvers: Optional[str] = typer.Option(None, "--resolvers", "-r", help="Custom DNS resolvers"),
    headless: bool = typer.Option(True, "--headless/--no-headless", help="Use headless browser for crawling"),
):
    """
     [bold]Full Cloud Attack Surface Scan[/bold]
    
    Comprehensive reconnaissance combining all modules:
    storage enumeration, service discovery, subdomain scanning,
    web crawling, secret detection, and vulnerability scanning.
    
    [bold cyan]Examples:[/bold cyan]
    
      [dim]# Quick scan on a company[/dim]
      $ cloud-asf scan acme-corp
      
      [dim]# Deep scan with web crawling[/dim]
      $ cloud-asf scan acme-corp --mode deep --crawl
      
      [dim]# Stealth scan (DNS-only, minimal footprint)[/dim]
      $ cloud-asf scan acme-corp --mode stealth
      
      [dim]# Fast scan with custom output[/dim]
      $ cloud-asf scan acme-corp --mode fast -o results.json -f json
    """
    if not quiet:
        print_banner()
        console.print(f"\n[bold green] Target:[/bold green] {target}")
        console.print(f"[bold blue] Mode:[/bold blue] {mode.value}")
    
    # Configure scan based on mode
    if mode == ScanMode.fast:
        threads = min(threads, 100)
        timeout = 5
    elif mode == ScanMode.deep:
        threads = max(threads, 75)
        crawl = True
        secrets = True
    elif mode == ScanMode.stealth:
        threads = min(threads, 20)
        crawl = False
        vulns = False
    
    # Print enabled modules
    if not quiet:
        _print_enabled_modules(storage, services, subdomains, crawl, secrets, vulns)
    
    # Run the scan
    asyncio.run(_run_full_scan(
        target=target,
        threads=threads,
        timeout=timeout,
        enable_storage=storage,
        enable_services=services,
        enable_subdomains=subdomains,
        enable_crawl=crawl,
        enable_secrets=secrets,
        enable_vulns=vulns,
        output=output,
        format=format,
        quiet=quiet,
        mutations=mutations.split(",") if mutations else None,
        resolvers=resolvers.split(",") if resolvers else None,
        headless=headless
    ))


def _print_enabled_modules(storage, services, subdomains, crawl, secrets, vulns):
    """Print enabled scan modules."""
    console.print("\n[bold] Enabled Modules:[/bold]")
    modules = [
        (" Storage Enumeration", storage),
        ("️ Cloud Services (100+)", services),
        (" Subdomain Discovery", subdomains),
        ("️ Web Crawling (Katana)", crawl),
        (" Secret Scanning", secrets),
        ("️ Vulnerability Scan", vulns),
    ]
    for name, enabled in modules:
        status = "[green][/green]" if enabled else "[dim][/dim]"
        console.print(f"  {status} {name}")
    console.print()


async def _run_full_scan(**kwargs):
    """Execute the full scan pipeline."""
    from .external.wrappers import ToolWrappers
    from .core.cloud_matcher import CloudMatcher
    from .external.recon_controller import ReconController
    from .external.cloud_service_detector import CloudServiceDetector
    from .analysis.secrets_scanner import EnhancedSecretsScanner
    
    target = kwargs["target"]
    output = kwargs.get("output")
    format = kwargs.get("format", OutputFormat.table)
    quiet = kwargs.get("quiet", False)
    
    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "assets": [],
        "storage": [],
        "services": [],
        "secrets": [],
        "vulnerabilities": []
    }
    
    try:
        wrappers = ToolWrappers()
        cloud_matcher = CloudMatcher()
        detector = CloudServiceDetector()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            disable=quiet
        ) as progress:
            
            # Phase 1: Storage Enumeration
            if kwargs.get("enable_storage"):
                task = progress.add_task("[cyan]Phase 1: Storage Enumeration...", total=100)
                try:
                    storage_results = await wrappers.run_skyscan(target)
                    results["storage"] = storage_results
                    progress.update(task, completed=100)
                    if not quiet:
                        console.print(f"  [green] Found {len(storage_results)} storage assets[/green]")
                except Exception as e:
                    progress.update(task, completed=100)
                    if not quiet:
                        console.print(f"  [yellow] Storage scan: {e}[/yellow]")
            
            # Phase 2: Subdomain Enumeration
            if kwargs.get("enable_subdomains"):
                task = progress.add_task("[cyan]Phase 2: Subdomain Discovery...", total=100)
                try:
                    subs = await wrappers.run_subfinder(target)
                    results["assets"].extend([{"type": "subdomain", "value": s} for s in subs])
                    progress.update(task, completed=100)
                    if not quiet:
                        console.print(f"  [green] Found {len(subs)} subdomains[/green]")
                except Exception as e:
                    progress.update(task, completed=100)
                    if not quiet:
                        console.print(f"  [yellow] Subdomain scan: {e}[/yellow]")
            
            # Phase 3: Cloud Service Detection
            if kwargs.get("enable_services"):
                task = progress.add_task("[cyan]Phase 3: Cloud Services (100+)...", total=100)
                try:
                    targets = detector.generate_targets_for_keyword(target)
                    # Check which exist
                    for url in targets[:50]:  # Limit for speed
                        result = detector.detect_from_domain(url)
                        if result:
                            results["services"].append({
                                "url": url,
                                "provider": result.provider,
                                "service": result.service_name,
                                "category": result.category,
                                "severity": result.severity
                            })
                    progress.update(task, completed=100)
                    if not quiet:
                        console.print(f"  [green] Detected {len(results['services'])} cloud services[/green]")
                except Exception as e:
                    progress.update(task, completed=100)
                    if not quiet:
                        console.print(f"  [yellow] Service detection: {e}[/yellow]")
            
            # Phase 4: Web Crawling
            if kwargs.get("enable_crawl"):
                task = progress.add_task("[cyan]Phase 4: Web Crawling (Katana)...", total=100)
                try:
                    endpoints = await wrappers.run_katana(
                        target=f"https://{target}",
                        headless=kwargs.get("headless", True),
                        depth=3
                    )
                    results["assets"].extend([{"type": "endpoint", "value": e.get("url")} for e in endpoints])
                    progress.update(task, completed=100)
                    if not quiet:
                        console.print(f"  [green] Crawled {len(endpoints)} endpoints[/green]")
                except Exception as e:
                    progress.update(task, completed=100)
                    if not quiet:
                        console.print(f"  [yellow] Web crawl: {e}[/yellow]")
            
            # Phase 5: Secret Scanning
            if kwargs.get("enable_secrets"):
                task = progress.add_task("[cyan]Phase 5: Secret Scanning...", total=100)
                try:
                    scanner = EnhancedSecretsScanner(wrappers)
                    # Scan public storage
                    for storage in results.get("storage", []):
                        if storage.get("permissions") in ["PUBLIC", "PUBLIC_READ", "PUBLIC_LIST"]:
                            secrets = await scanner.scan_with_trufflehog(
                                target=storage.get("url", ""),
                                scan_type="s3" if "s3" in storage.get("url", "") else "filesystem",
                                verify=True
                            )
                            formatted = scanner.format_findings(secrets)
                            results["secrets"].extend(formatted)
                    progress.update(task, completed=100)
                    if not quiet:
                        console.print(f"  [green] Found {len(results['secrets'])} secrets[/green]")
                except Exception as e:
                    progress.update(task, completed=100)
                    if not quiet:
                        console.print(f"  [yellow] Secret scan: {e}[/yellow]")
            
            # Phase 6: Vulnerability Scanning
            if kwargs.get("enable_vulns"):
                task = progress.add_task("[cyan]Phase 6: Vulnerability Scanning...", total=100)
                try:
                    targets_to_scan = [a["value"] for a in results.get("assets", []) if a.get("type") == "endpoint"][:50]
                    if targets_to_scan:
                        vulns = await wrappers.run_nuclei(targets_to_scan)
                        results["vulnerabilities"] = vulns
                    progress.update(task, completed=100)
                    if not quiet:
                        console.print(f"  [green] Found {len(results['vulnerabilities'])} vulnerabilities[/green]")
                except Exception as e:
                    progress.update(task, completed=100)
                    if not quiet:
                        console.print(f"  [yellow] Vuln scan: {e}[/yellow]")
        
        # Output results
        if format == OutputFormat.json:
            output_path = get_output_path(output, f"scan_{target}")
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            if not quiet:
                console.print(f"\n[green] Results saved to {output_path}[/green]")
        else:
            _print_scan_results(results, quiet)
            if output:
                with open(output, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                console.print(f"\n[green] Results saved to {output}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


def _print_scan_results(results: dict, quiet: bool = False):
    """Print scan results in a formatted table."""
    if quiet:
        return
    
    console.print("\n" + "=" * 60)
    console.print("[bold cyan] SCAN RESULTS[/bold cyan]")
    console.print("=" * 60)
    
    # Summary
    summary = Table(title="Summary", box=box.ROUNDED)
    summary.add_column("Category", style="cyan")
    summary.add_column("Count", style="green")
    summary.add_row("Storage Assets", str(len(results.get("storage", []))))
    summary.add_row("Cloud Services", str(len(results.get("services", []))))
    summary.add_row("Discovered Assets", str(len(results.get("assets", []))))
    summary.add_row("Secrets Found", str(len(results.get("secrets", []))))
    summary.add_row("Vulnerabilities", str(len(results.get("vulnerabilities", []))))
    console.print(summary)
    
    # Critical findings
    critical = []
    for s in results.get("storage", []):
        if s.get("permissions") in ["PUBLIC", "PUBLIC_READ", "PUBLIC_WRITE"]:
            critical.append(f" Public Storage: {s.get('url', 'Unknown')}")
    for sec in results.get("secrets", []):
        if sec.get("severity") == "CRITICAL":
            critical.append(f" Verified Secret: {sec.get('type', 'Unknown')}")
    for vuln in results.get("vulnerabilities", []):
        if vuln.get("severity", "").upper() in ["CRITICAL", "HIGH"]:
            critical.append(f"️ {vuln.get('severity')}: {vuln.get('name', 'Unknown')}")
    
    if critical:
        console.print("\n[bold red] CRITICAL FINDINGS:[/bold red]")
        for finding in critical[:10]:
            console.print(f"  {finding}")


# ============================================================================
#                        RECON SUBCOMMANDS
# ============================================================================

@recon_app.command(name="full")
def recon_full(
    target: str = typer.Argument(..., help="Target domain or keyword"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file"),
    threads: int = typer.Option(50, "-t", "--threads", help="Threads"),
    headless: bool = typer.Option(True, "--headless/--no-headless", help="Headless browser")
):
    """
     Full reconnaissance pipeline with all tools.
    
    Combines Subfinder, DNSx, Naabu, Nuclei, Katana, and TruffleHog.
    """
    print_banner()
    console.print(f"\n[bold green] Full Recon on:[/bold green] {target}\n")
    
    asyncio.run(_run_recon_full(target, output, threads, headless))


async def _run_recon_full(target: str, output: Optional[str], threads: int, headless: bool):
    """Execute full recon pipeline."""
    from .external.wrappers import ToolWrappers
    from .core.cloud_matcher import CloudMatcher
    from .external.recon_controller import ReconController
    
    # Auto-generate output file if not specified
    if not output:
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("/", "_").replace(":", "_")
        output = f"reports/recon_full_{safe_target}_{timestamp}.json"
    
    wrappers = ToolWrappers()
    cloud_matcher = CloudMatcher()
    controller = ReconController(wrappers, cloud_matcher)
    
    results = await controller.run_full_recon(
        target=target,
        enable_storage_enum=True,
        enable_web_crawl=True,
        enable_vuln_scan=True,
        enable_secret_scan=True,
        headless=headless,
        output_file=output
    )
    
    # Save results
    try:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        console.print(f"\n[green] Results saved to: {output}[/green]")
    except Exception as e:
        console.print(f"[yellow] Could not save results: {e}[/yellow]")
    
    console.print(f"[green] Discovered {len(results)} assets[/green]")


@recon_app.command(name="subdomains")
def recon_subdomains(
    target: str = typer.Argument(..., help="Target domain"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file"),
    resolve: bool = typer.Option(True, "--resolve/--no-resolve", help="Resolve DNS")
):
    """
     Subdomain enumeration using Subfinder + DNSx.
    """
    print_banner()
    console.print(f"\n[bold green] Subdomain Enumeration:[/bold green] {target}\n")
    
    asyncio.run(_run_subdomain_enum(target, output, resolve))


async def _run_subdomain_enum(target: str, output: Optional[str], resolve: bool):
    """Run subdomain enumeration."""
    from .external.wrappers import ToolWrappers
    
    wrappers = ToolWrappers()
    
    with console.status("[bold green]Finding subdomains..."):
        subs = await wrappers.run_subfinder(target)
    
    console.print(f"[green] Found {len(subs)} subdomains[/green]\n")
    
    if resolve:
        with console.status("[bold green]Resolving DNS..."):
            resolved = await wrappers.run_dnsx(subs)
        console.print(f"[green] Resolved {len(resolved)} hosts[/green]")
    
    # Output
    if output:
        with open(output, 'w') as f:
            for sub in subs:
                f.write(f"{sub}\n")
        console.print(f"[green] Saved to {output}[/green]")
    else:
        for sub in subs[:20]:
            console.print(f"  {sub}")
        if len(subs) > 20:
            console.print(f"  [dim]... and {len(subs) - 20} more[/dim]")


@recon_app.command(name="crawl")
def recon_crawl(
    target: str = typer.Argument(..., help="Target URL"),
    depth: int = typer.Option(3, "-d", "--depth", help="Crawl depth"),
    headless: bool = typer.Option(True, "--headless/--no-headless", help="Headless mode"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file")
):
    """
    ️ Web crawling using Katana with headless browser support.
    """
    print_banner()
    console.print(f"\n[bold green]️ Web Crawling:[/bold green] {target}\n")
    
    asyncio.run(_run_crawl(target, depth, headless, output))


async def _run_crawl(target: str, depth: int, headless: bool, output: Optional[str]):
    """Run web crawling."""
    from .external.wrappers import ToolWrappers
    
    wrappers = ToolWrappers()
    
    if not target.startswith("http"):
        target = f"https://{target}"
    
    with console.status("[bold green]Crawling..."):
        endpoints = await wrappers.run_katana(target, headless=headless, depth=depth)
    
    console.print(f"[green] Found {len(endpoints)} endpoints[/green]\n")
    
    if output:
        with open(output, 'w') as f:
            json.dump(endpoints, f, indent=2)
        console.print(f"[green] Saved to {output}[/green]")
    else:
        for ep in endpoints[:15]:
            console.print(f"  {ep.get('url', '')}")
        if len(endpoints) > 15:
            console.print(f"  [dim]... and {len(endpoints) - 15} more[/dim]")


# ============================================================================
#                       STORAGE SUBCOMMANDS
# ============================================================================

@storage_app.command(name="enum")
def storage_enum(
    keyword: str = typer.Argument(..., help="Target keyword for bucket enumeration"),
    provider: Optional[str] = typer.Option(None, "-p", "--provider", help="Specific provider (aws/azure/gcp)"),
    threads: int = typer.Option(50, "-t", "--threads", help="Threads"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file"),
    mutations: Optional[str] = typer.Option(None, "-m", "--mutations", help="Custom mutations")
):
    """
     Cloud storage enumeration (S3, Azure Blob, GCS, DigitalOcean Spaces, etc.)
    
    Uses hybrid DNS+HTTP detection for stealth and speed.
    """
    print_banner()
    console.print(f"\n[bold green] Storage Enumeration:[/bold green] {keyword}\n")
    
    asyncio.run(_run_storage_enum(keyword, provider, threads, output, mutations))


async def _run_storage_enum(keyword: str, provider: Optional[str], threads: int, output: Optional[str], mutations: Optional[str]):
    """Run storage enumeration."""
    from .external.wrappers import ToolWrappers
    
    wrappers = ToolWrappers()
    
    with console.status("[bold green]Enumerating storage buckets..."):
        results = await wrappers.run_skyscan(keyword)
    
    console.print(f"[green] Found {len(results)} storage assets[/green]\n")
    
    # Group by provider
    by_provider = {}
    for r in results:
        prov = r.get("provider", "Unknown")
        if prov not in by_provider:
            by_provider[prov] = []
        by_provider[prov].append(r)
    
    # Display
    table = Table(title="Storage Assets", box=box.ROUNDED)
    table.add_column("Provider", style="cyan")
    table.add_column("URL", style="green")
    table.add_column("Permissions", style="yellow")
    table.add_column("Status", style="magenta")
    
    for r in results[:20]:
        perms = r.get("permissions", "Unknown")
        perm_style = "red bold" if "PUBLIC" in perms else "green"
        table.add_row(
            r.get("provider", "?"),
            r.get("url", "")[:60],
            f"[{perm_style}]{perms}[/{perm_style}]",
            str(r.get("status", ""))
        )
    
    console.print(table)
    
    if len(results) > 20:
        console.print(f"[dim]... and {len(results) - 20} more[/dim]")
    
    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        console.print(f"\n[green] Saved to {output}[/green]")


@storage_app.command(name="check")
def storage_check(
    url: str = typer.Argument(..., help="Storage URL to check"),
    deep: bool = typer.Option(False, "--deep", "-d", help="Deep analysis (ACLs, files)")
):
    """
     Check a specific storage bucket for misconfigurations.
    """
    console.print(f"\n[bold green] Checking:[/bold green] {url}\n")
    
    asyncio.run(_check_storage(url, deep))


async def _check_storage(url: str, deep: bool):
    """Check a specific storage URL."""
    import aiohttp
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.head(url, timeout=10) as resp:
                status = resp.status
                headers = dict(resp.headers)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return
    
    # Analyze
    if status == 200:
        console.print("[red bold]️ PUBLIC ACCESS: Bucket is publicly readable![/red bold]")
    elif status == 403:
        console.print("[green] Access Denied: Bucket requires authentication[/green]")
    elif status == 404:
        console.print("[yellow]? Bucket does not exist[/yellow]")
    else:
        console.print(f"[blue]Status: {status}[/blue]")
    
    # Headers
    if "x-amz-bucket-region" in headers:
        console.print(f"[cyan]Region: {headers['x-amz-bucket-region']}[/cyan]")


# ============================================================================
#                       SECRETS SUBCOMMANDS
# ============================================================================

@secrets_app.command(name="scan")
def secrets_scan(
    target: str = typer.Argument(..., help="Target path, URL, or S3 bucket"),
    scan_type: str = typer.Option("filesystem", "-t", "--type", help="Scan type (filesystem/git/s3)"),
    verify: bool = typer.Option(True, "--verify/--no-verify", help="Verify credentials"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file")
):
    """
     Secret scanning using TruffleHog with live verification.
    
    Detects AWS keys, API tokens, passwords, private keys, and 50+ secret types.
    """
    print_banner()
    console.print(f"\n[bold green] Secret Scanning:[/bold green] {target}\n")
    
    asyncio.run(_run_secrets_scan(target, scan_type, verify, output))


async def _run_secrets_scan(target: str, scan_type: str, verify: bool, output: Optional[str]):
    """Run secrets scan."""
    from .external.wrappers import ToolWrappers
    from .analysis.secrets_scanner import EnhancedSecretsScanner
    
    wrappers = ToolWrappers()
    scanner = EnhancedSecretsScanner(wrappers)
    
    with console.status("[bold green]Scanning for secrets..."):
        results = await wrappers.run_trufflehog(target, scan_type=scan_type, verify=verify)
    
    console.print(f"[green] Found {len(results)} secrets[/green]\n")
    
    # Display
    if results:
        table = Table(title="Secrets Found", box=box.ROUNDED)
        table.add_column("Type", style="cyan")
        table.add_column("Verified", style="green")
        table.add_column("File", style="yellow")
        table.add_column("Severity")
        
        for r in results[:20]:
            verified = " Yes" if r.get("verified") else "No"
            verified_style = "green bold" if r.get("verified") else "dim"
            severity = "CRITICAL" if r.get("verified") else "HIGH"
            sev_style = "red bold" if severity == "CRITICAL" else "yellow"
            
            table.add_row(
                r.get("detector", "Unknown"),
                f"[{verified_style}]{verified}[/{verified_style}]",
                str(r.get("file", ""))[:40],
                f"[{sev_style}]{severity}[/{sev_style}]"
            )
        
        console.print(table)
    
    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        console.print(f"\n[green] Saved to {output}[/green]")


@secrets_app.command(name="regex")
def secrets_regex(
    file: str = typer.Argument(..., help="File to scan"),
    pattern: Optional[str] = typer.Option(None, "-p", "--pattern", help="Custom regex pattern")
):
    """
     Quick regex-based secret scanning (50+ built-in patterns).
    """
    from .analysis.secrets_scanner import EnhancedSecretsScanner
    
    console.print(f"\n[bold green] Regex Scanning:[/bold green] {file}\n")
    
    scanner = EnhancedSecretsScanner()
    
    try:
        with open(file, 'r') as f:
            content = f.read()
    except Exception as e:
        console.print(f"[red]Error reading file: {e}[/red]")
        raise typer.Exit(1)
    
    findings = scanner.scan_text(content, file)
    
    console.print(f"[green] Found {len(findings)} potential secrets[/green]\n")
    
    for finding in findings[:20]:
        sev_color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue"}.get(finding.severity.value, "white")
        console.print(f"  [{sev_color}]{finding.severity.value}[/{sev_color}] {finding.secret_type}: {finding.redacted_value}")


# ============================================================================
#                       AUDIT SUBCOMMANDS
# ============================================================================

@audit_app.command(name="aws")
def audit_aws(
    profile: Optional[str] = typer.Option(None, "-p", "--profile", help="AWS profile"),
    regions: Optional[str] = typer.Option(None, "-r", "--regions", help="Comma-separated regions"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file"),
    compliance: bool = typer.Option(True, "--compliance/--no-compliance", help="Run compliance checks")
):
    """
     Authenticated AWS audit using cloud credentials.
    
    Checks S3 buckets, IAM policies, EC2 instances, and more.
    """
    print_banner()
    console.print(f"\n[bold green] Authenticated AWS Audit[/bold green]\n")
    
    from .authenticated.auth import AuthHandler
    from .authenticated.enumerator import AWS_Enumerator
    from .authenticated.compliance import ComplianceChecker
    
    auth = AuthHandler(profile=profile)
    session = auth.get_session()
    
    if not session:
        console.print("[red]Failed to authenticate. Check credentials.[/red]")
        raise typer.Exit(1)
    
    console.print("[green] Authenticated successfully[/green]\n")
    
    enum = AWS_Enumerator(session)
    data = enum.enumerate_all()
    
    if compliance:
        comp = ComplianceChecker()
        risks = comp.check(data)
        comp.print_report(risks)
    
    if output:
        with open(output, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        console.print(f"\n[green] Saved to {output}[/green]")


# ============================================================================
#                        UTILITY COMMANDS
# ============================================================================

@app.command(name="version")
def version():
    """Show version information."""
    console.print("[bold cyan]Cloud Attack Surface Framework[/bold cyan]")
    console.print("Version: 2.0.0")
    console.print("Author: Security Research Team")


@app.command(name="check-tools")
def check_tools():
    """ Check if all required tools are installed."""
    print_banner()
    console.print("\n[bold] Tool Status:[/bold]\n")
    
    import shutil
    
    bin_dir = Path(__file__).parent.parent.parent.parent / "bin"
    
    tools = [
        ("subfinder", "Subdomain enumeration"),
        ("dnsx", "DNS resolution"),
        ("naabu", "Port scanning"),
        ("nuclei", "Vulnerability scanning"),
        ("katana", "Web crawling"),
        ("trufflehog", "Secret detection"),
        ("skyscan", "Cloud storage enumeration"),
        ("skyscan_v2", "Advanced cloud recon"),
    ]
    
    table = Table(box=box.ROUNDED)
    table.add_column("Tool", style="cyan")
    table.add_column("Status")
    table.add_column("Description", style="dim")
    
    for tool, desc in tools:
        # Check in bin directory first, then PATH
        tool_path = bin_dir / tool
        if tool_path.exists() or shutil.which(tool):
            status = "[green] Installed[/green]"
        else:
            status = "[red] Missing[/red]"
        table.add_row(tool, status, desc)
    
    console.print(table)


@app.command(name="services")
def list_services():
    """ List all supported cloud services."""
    from .external.cloud_service_detector import CLOUD_SERVICE_PATTERNS
    
    print_banner()
    
    # Group by provider
    by_provider = {}
    for pattern in CLOUD_SERVICE_PATTERNS:
        prov = pattern.provider.value
        if prov not in by_provider:
            by_provider[prov] = []
        by_provider[prov].append(pattern)
    
    console.print(f"\n[bold] Supported Cloud Services ({len(CLOUD_SERVICE_PATTERNS)} total)[/bold]\n")
    
    for provider, patterns in sorted(by_provider.items()):
        console.print(f"\n[bold cyan]{provider}[/bold cyan] ({len(patterns)} services)")
        for p in patterns[:10]:
            sev_color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue"}.get(p.severity, "white")
            console.print(f"  [{sev_color}]{p.severity}[/{sev_color}] {p.service_name} - {p.description}")
        if len(patterns) > 10:
            console.print(f"  [dim]... and {len(patterns) - 10} more[/dim]")


# ============================================================================
#                           DASHBOARD COMMAND
# ============================================================================

@app.command(name="dashboard")
def start_dashboard(
    backend_port: int = typer.Option(8000, "--backend-port", "-b", help="Backend API port"),
    frontend_port: int = typer.Option(3000, "--frontend-port", "-f", help="Frontend port"),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="Open browser automatically"),
    dev: bool = typer.Option(False, "--dev", help="Run in development mode with hot reload")
):
    """
    ️ [bold]Start the Web Dashboard[/bold]
    
    Launches both the backend API server and frontend web interface.
    Access the dashboard at http://localhost:3000
    
    [bold cyan]Examples:[/bold cyan]
    
      [dim]# Start dashboard (default ports)[/dim]
      $ cloud-asf dashboard
      
      [dim]# Custom ports[/dim]
      $ cloud-asf dashboard --backend-port 8080 --frontend-port 4000
      
      [dim]# Don't open browser[/dim]
      $ cloud-asf dashboard --no-open
    """
    import subprocess
    import signal
    import webbrowser
    import time
    
    print_banner()
    
    project_root = Path(__file__).parent.parent.parent.parent
    backend_dir = project_root / "src" / "dashboard" / "backend"
    frontend_dir = project_root / "src" / "dashboard" / "frontend"
    
    console.print("\n[bold cyan]️  Starting Cloud ASF Dashboard[/bold cyan]\n")
    
    # Check if directories exist
    if not backend_dir.exists():
        console.print(f"[red]Error: Backend directory not found: {backend_dir}[/red]")
        raise typer.Exit(1)
    
    if not frontend_dir.exists():
        console.print(f"[red]Error: Frontend directory not found: {frontend_dir}[/red]")
        raise typer.Exit(1)
    
    processes = []
    
    try:
        # Start Backend
        console.print(f"[green]▶ Starting Backend API on port {backend_port}...[/green]")
        backend_cmd = [
            sys.executable, "-m", "uvicorn", 
            "src.dashboard.backend.main:app",
            "--host", "0.0.0.0",
            "--port", str(backend_port)
        ]
        if dev:
            backend_cmd.append("--reload")
        
        backend_proc = subprocess.Popen(
            backend_cmd,
            cwd=str(project_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
        processes.append(backend_proc)
        
        # Give backend time to start
        time.sleep(2)
        
        # Check if npm/node is available for frontend
        if subprocess.run(["npm", "--version"], capture_output=True).returncode == 0:
            console.print(f"[green]▶ Starting Frontend on port {frontend_port}...[/green]")
            
            frontend_env = os.environ.copy()
            frontend_env["PORT"] = str(frontend_port)
            frontend_env["NEXT_PUBLIC_API_URL"] = f"http://localhost:{backend_port}"
            
            frontend_cmd = ["npm", "run", "dev"]
            
            frontend_proc = subprocess.Popen(
                frontend_cmd,
                cwd=str(frontend_dir),
                env=frontend_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
            processes.append(frontend_proc)
            
            # Wait for frontend to start
            time.sleep(3)
            
            dashboard_url = f"http://localhost:{frontend_port}"
        else:
            console.print("[yellow] npm not found - running backend only[/yellow]")
            dashboard_url = f"http://localhost:{backend_port}/docs"
        
        console.print(f"\n[bold green] Dashboard is running![/bold green]")
        console.print(f"\n[bold] Dashboard:[/bold] {dashboard_url}")
        console.print(f"[bold] API:[/bold] http://localhost:{backend_port}")
        console.print(f"[bold] API Docs:[/bold] http://localhost:{backend_port}/docs")
        console.print(f"\n[dim]Press Ctrl+C to stop the dashboard[/dim]\n")
        
        # Open browser
        if open_browser:
            time.sleep(1)
            webbrowser.open(dashboard_url)
        
        # Wait for processes
        for proc in processes:
            proc.wait()
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down dashboard...[/yellow]")
    finally:
        # Cleanup
        for proc in processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except:
                proc.kill()
        console.print("[green] Dashboard stopped[/green]")


# ============================================================================
#                           MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
