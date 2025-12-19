import asyncio
import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from rich.console import Console


def get_default_bin_dir() -> str:
    """Get the default bin directory relative to this file.
    
    File location: src/python/orchestrator/external/wrappers.py
    Bin location:  bin/
    So we need: parent (external) -> parent (orchestrator) -> parent (python) -> parent (src) -> parent (project root) -> bin
    """
    project_root = Path(__file__).parent.parent.parent.parent.parent
    return str(project_root / "bin")


class ToolWrappers:
    def __init__(self, bin_dir: Optional[str] = None, cloud_enum_script: Optional[str] = None):
        self.bin_dir = bin_dir or get_default_bin_dir()
        self.subfinder_bin = os.path.join(self.bin_dir, "subfinder")
        self.dnsx_bin = os.path.join(self.bin_dir, "dnsx")
        self.naabu_bin = os.path.join(self.bin_dir, "naabu")
        self.nuclei_bin = os.path.join(self.bin_dir, "nuclei")
        self.katana_bin = os.path.join(self.bin_dir, "katana")
        self.trufflehog_bin = os.path.join(self.bin_dir, "trufflehog")
        self.skyscan_bin = os.path.join(self.bin_dir, "skyscan_v2")
        self.console = Console()

    def check_dependencies(self) -> List[str]:
        missing = []
        for tool in [self.subfinder_bin, self.dnsx_bin, self.naabu_bin, self.nuclei_bin]:
            if not os.path.exists(tool):
                missing.append(tool)
        return missing

    async def _run_command(self, command: List[str], input_data: str = None) -> str:
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate(input=input_data.encode() if input_data else None)
            
            if process.returncode != 0:
                # Log error but don't crash
                # print(f"[!] Command failed: {' '.join(command)}")
                # print(f"[!] Error: {stderr.decode()}")
                return ""
            
            return stdout.decode()
        except FileNotFoundError:
            print(f"[!] Binary/Script not found: {command[0]}")
            return ""
        except Exception as e:
            print(f"[!] Error running command {' '.join(command)}: {e}")
            return ""

    async def run_subfinder(self, domain: str) -> List[str]:
        cmd = [self.subfinder_bin, "-d", domain, "-json", "-silent"]
        output = await self._run_command(cmd)
        subdomains = []
        for line in output.splitlines():
            try:
                data = json.loads(line)
                if 'host' in data:
                    subdomains.append(data['host'])
            except json.JSONDecodeError:
                pass
        return subdomains

    async def run_dnsx(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        if not subdomains:
            return []
        input_data = "\n".join(subdomains)
        cmd = [self.dnsx_bin, "-json", "-silent"]
        output = await self._run_command(cmd, input_data=input_data)
        resolved = []
        for line in output.splitlines():
            try:
                data = json.loads(line)
                if 'host' in data and 'a' in data:
                    for ip in data['a']:
                        resolved.append({'host': data['host'], 'ip': ip})
            except json.JSONDecodeError:
                pass
        return resolved

    async def run_naabu(self, ip: str) -> List[int]:
        cmd = [self.naabu_bin, "-host", ip, "-json", "-silent"] 
        output = await self._run_command(cmd)
        ports = []
        for line in output.splitlines():
            try:
                data = json.loads(line)
                if 'port' in data:
                    ports.append(data['port'])
            except json.JSONDecodeError:
                pass
        return ports

    async def run_cloud_enum(self, keyword: str, domain: str, output_file: str):
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        cmd = [
            "python3", self.cloud_enum_script, 
            "-k", keyword, 
            "-k", domain, 
            "-f", "json", 
            "-l", output_file
        ]
        # print(f"[*] Running Cloud Enum: {' '.join(cmd)}")
        await self._run_command(cmd)

    async def run_nuclei(self, targets: List[str]) -> List[Dict[str, Any]]:
        if not targets:
            return []

        input_data = "\n".join(targets)
        cmd = [self.nuclei_bin, "-t", "technologies", "-t", "cloud", "-json", "-silent"]
        
        # print(f"[*] Running Nuclei on {len(targets)} targets...")
        output = await self._run_command(cmd, input_data=input_data)
        
        vulnerabilities = []
        for line in output.splitlines():
             try:
                data = json.loads(line)
                template_id = data.get('template-id')
                info = data.get('info', {})
                name = info.get('name')
                severity = info.get('severity')
                matched = data.get('matched-at')
                
                vulnerabilities.append({
                    'name': name,
                    'severity': severity,
                    'template_id': template_id,
                    'matched_at': matched
                })
             except json.JSONDecodeError:
                 pass
        return vulnerabilities

    async def run_skyscan(self, keyword: str) -> List[Dict[str, Any]]:
        skyscan_bin = os.path.join(self.bin_dir, "skyscan")
        if not os.path.exists(skyscan_bin):
            print(f"[!] SkyScan binary not found at {skyscan_bin}")
            return []
            
        cmd = [skyscan_bin, "-k", keyword, "--json"]
        # print(f"[*] Running SkyScan for keyword: {keyword}")
        
        output = await self._run_command(cmd)
        findings = []
        
        try:
            # SkyScan outputs a JSON array on success
            findings = json.loads(output)
        except json.JSONDecodeError:
            # Fallback if multiple lines of JSON objects
            for line in output.splitlines():
                try:
                    data = json.loads(line)
                    findings.append(data)
                except json.JSONDecodeError:
                    pass
                    
        return findings

    async def run_katana(
        self, 
        target: str, 
        headless: bool = True,
        depth: int = 3,
        js_crawl: bool = True,
        scope_domain: bool = True,
        timeout: int = 60
    ) -> List[Dict[str, Any]]:
        """
        Run Katana web crawler for comprehensive URL/endpoint discovery.
        
        Args:
            target: Target URL to crawl
            headless: Use headless Chrome for JS rendering (for SPAs)
            depth: Maximum crawl depth
            js_crawl: Enable JavaScript parsing
            scope_domain: Limit crawl to target domain only
            timeout: Request timeout in seconds
            
        Returns:
            List of discovered endpoints with metadata
        """
        if not os.path.exists(self.katana_bin):
            self.console.print(f"[red][!] Katana binary not found at {self.katana_bin}[/red]")
            return []
        
        cmd = [
            self.katana_bin,
            "-u", target,
            "-d", str(depth),
            "-timeout", str(timeout),
            "-jsonl",
            "-silent",
            "-nc"  # No color
        ]
        
        # Headless mode for SPA/JavaScript rendering
        if headless:
            cmd.extend(["-headless"])
            
        # JavaScript crawling
        if js_crawl:
            cmd.extend(["-js-crawl"])
            
        # Scope to target domain only (avoid third-party drift)
        if scope_domain:
            cmd.extend(["-cs", target])
        
        self.console.print(f"[cyan][*] Running Katana crawler on {target}...[/cyan]")
        output = await self._run_command(cmd)
        
        endpoints = []
        for line in output.splitlines():
            try:
                data = json.loads(line)
                endpoints.append({
                    'url': data.get('request', {}).get('endpoint', data.get('endpoint', '')),
                    'method': data.get('request', {}).get('method', 'GET'),
                    'source': data.get('source', ''),
                    'tag': data.get('tag', ''),
                    'attribute': data.get('attribute', ''),
                })
            except json.JSONDecodeError:
                # Raw URL output
                if line.strip():
                    endpoints.append({'url': line.strip(), 'method': 'GET', 'source': 'raw'})
        
        self.console.print(f"[green][+] Katana discovered {len(endpoints)} endpoints[/green]")
        return endpoints

    async def run_trufflehog(
        self,
        target: str,
        scan_type: str = "filesystem",
        verify: bool = True,
        only_verified: bool = False,
        concurrency: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Run TruffleHog for comprehensive secret detection and verification.
        
        Args:
            target: Path, URL, or S3 bucket to scan
            scan_type: One of 'filesystem', 'git', 's3', 'github', 'gitlab'
            verify: Attempt to verify discovered credentials are active
            only_verified: Return only verified (active) secrets
            concurrency: Number of concurrent workers
            
        Returns:
            List of discovered secrets with verification status
        """
        if not os.path.exists(self.trufflehog_bin):
            self.console.print(f"[red][!] TruffleHog binary not found at {self.trufflehog_bin}[/red]")
            return []
        
        cmd = [
            self.trufflehog_bin,
            scan_type,
            target,
            "--json",
            "--concurrency", str(concurrency)
        ]
        
        # Credential verification (active secret detection)
        if verify:
            cmd.append("--verify")
            
        if only_verified:
            cmd.append("--only-verified")
        
        self.console.print(f"[cyan][*] Running TruffleHog {scan_type} scan on {target}...[/cyan]")
        output = await self._run_command(cmd)
        
        secrets = []
        for line in output.splitlines():
            try:
                data = json.loads(line)
                
                # Parse TruffleHog output format
                detector = data.get('DetectorName', data.get('SourceMetadata', {}).get('DetectorName', 'Unknown'))
                verified = data.get('Verified', False)
                raw = data.get('Raw', '')
                
                # Redact for logging
                redacted = f"{raw[:8]}..." if len(raw) > 8 else "***"
                
                secret_info = {
                    'detector': detector,
                    'verified': verified,
                    'redacted': redacted,
                    'source_type': data.get('SourceType', ''),
                    'source_name': data.get('SourceName', ''),
                    'file': data.get('SourceMetadata', {}).get('Filename', ''),
                    'line': data.get('SourceMetadata', {}).get('Line', 0),
                    'severity': 'CRITICAL' if verified else 'HIGH'
                }
                
                # Extra metadata for git sources
                if scan_type == 'git':
                    secret_info['commit'] = data.get('SourceMetadata', {}).get('Commit', '')
                    secret_info['author'] = data.get('SourceMetadata', {}).get('Email', '')
                    
                secrets.append(secret_info)
                
            except json.JSONDecodeError:
                pass
        
        verified_count = sum(1 for s in secrets if s.get('verified'))
        self.console.print(f"[green][+] TruffleHog found {len(secrets)} secrets ({verified_count} verified/active)[/green]")
        return secrets

    async def run_trufflehog_s3(
        self,
        bucket_name: str,
        verify: bool = True,
        only_verified: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Specialized TruffleHog scan for S3 buckets.
        
        Args:
            bucket_name: S3 bucket name (e.g., 'mybucket' or 's3://mybucket')
            verify: Verify discovered credentials
            only_verified: Only return active credentials
            
        Returns:
            List of secrets found in the S3 bucket
        """
        # Normalize bucket name
        if not bucket_name.startswith('s3://'):
            bucket_name = f"s3://{bucket_name}"
            
        return await self.run_trufflehog(
            target=bucket_name,
            scan_type="s3",
            verify=verify,
            only_verified=only_verified
        )

