"""
Enhanced Secrets Scanner with TruffleHog integration and comprehensive pattern detection.
This module combines internal regex scanning with external TruffleHog for verified secrets.
"""

import re
import asyncio
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class SecretSeverity(Enum):
    CRITICAL = "CRITICAL"  # Verified active credential
    HIGH = "HIGH"          # Likely valid secret
    MEDIUM = "MEDIUM"      # Possible secret
    LOW = "LOW"            # Informational

@dataclass
class SecretFinding:
    """Represents a discovered secret with metadata."""
    secret_type: str
    redacted_value: str
    file_path: Optional[str]
    line_number: Optional[int]
    severity: SecretSeverity
    verified: bool
    context: Optional[str]
    detector: str  # Which detector found this

class EnhancedSecretsScanner:
    """
    Comprehensive secrets scanner combining:
    1. High-performance regex patterns for quick scanning
    2. TruffleHog integration for verified credential detection
    3. Entropy analysis for unknown secret detection
    4. Context-aware filtering to reduce false positives
    """
    
    # Comprehensive patterns covering 50+ secret types
    PATTERNS = {
        # AWS
        "AWS Access Key ID": (r"AKIA[0-9A-Z]{16}", SecretSeverity.HIGH),
        "AWS Secret Access Key": (r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])", SecretSeverity.HIGH),
        "AWS Account ID": (r"\b\d{12}\b", SecretSeverity.LOW),
        "AWS ARN": (r"arn:aws:[a-z0-9-]*:[a-z0-9-]*:\d{12}:[a-zA-Z0-9-_/]+", SecretSeverity.MEDIUM),
        
        # Azure
        "Azure Storage Key": (r"[a-zA-Z0-9+/]{86}==", SecretSeverity.HIGH),
        "Azure SAS Token": (r"sv=[\d-]+&s[a-z]=[\w&=%-]+sig=[a-zA-Z0-9%]+", SecretSeverity.HIGH),
        "Azure Connection String": (r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+", SecretSeverity.CRITICAL),
        "Azure Client Secret": (r"[a-zA-Z0-9_~.-]{34}", SecretSeverity.MEDIUM),
        
        # GCP
        "GCP API Key": (r"AIza[0-9A-Za-z_-]{35}", SecretSeverity.HIGH),
        "GCP Service Account": (r'"type":\s*"service_account"', SecretSeverity.HIGH),
        "GCP Project ID": (r"[a-z][a-z0-9-]{4,28}[a-z0-9]", SecretSeverity.LOW),
        
        # Generic Cloud
        "Private Key": (r"-----BEGIN [A-Z]+ PRIVATE KEY-----", SecretSeverity.CRITICAL),
        "RSA Private Key": (r"-----BEGIN RSA PRIVATE KEY-----", SecretSeverity.CRITICAL),
        "SSH Private Key": (r"-----BEGIN OPENSSH PRIVATE KEY-----", SecretSeverity.CRITICAL),
        
        # API Keys
        "Stripe API Key": (r"sk_live_[0-9a-zA-Z]{24}", SecretSeverity.CRITICAL),
        "Stripe Test Key": (r"sk_test_[0-9a-zA-Z]{24}", SecretSeverity.MEDIUM),
        "Stripe Publishable Key": (r"pk_(live|test)_[0-9a-zA-Z]{24}", SecretSeverity.LOW),
        "GitHub Token": (r"ghp_[a-zA-Z0-9]{36}", SecretSeverity.HIGH),
        "GitHub OAuth": (r"gho_[a-zA-Z0-9]{36}", SecretSeverity.HIGH),
        "GitHub App Token": (r"(ghu|ghs)_[a-zA-Z0-9]{36}", SecretSeverity.HIGH),
        "GitHub Personal Access Token": (r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}", SecretSeverity.HIGH),
        "GitLab Token": (r"glpat-[a-zA-Z0-9_-]{20}", SecretSeverity.HIGH),
        "Slack Token": (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", SecretSeverity.HIGH),
        "Slack Webhook": (r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", SecretSeverity.HIGH),
        "Twilio API Key": (r"SK[a-f0-9]{32}", SecretSeverity.HIGH),
        "SendGrid API Key": (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", SecretSeverity.HIGH),
        "Mailchimp API Key": (r"[a-f0-9]{32}-us\d{2}", SecretSeverity.HIGH),
        "Shopify API Key": (r"shpat_[a-fA-F0-9]{32}", SecretSeverity.HIGH),
        "Square Access Token": (r"sq0atp-[0-9A-Za-z_-]{22}", SecretSeverity.HIGH),
        "Square OAuth Secret": (r"sq0csp-[0-9A-Za-z_-]{43}", SecretSeverity.HIGH),
        "PayPal Client ID": (r"A[a-zA-Z0-9_-]{20,}T", SecretSeverity.MEDIUM),
        "Heroku API Key": (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", SecretSeverity.MEDIUM),
        "NPM Token": (r"npm_[a-zA-Z0-9]{36}", SecretSeverity.HIGH),
        "PyPI Token": (r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]+", SecretSeverity.HIGH),
        "Docker Hub Token": (r"dckr_pat_[a-zA-Z0-9_-]{27}", SecretSeverity.HIGH),
        "Datadog API Key": (r"[a-f0-9]{32}", SecretSeverity.MEDIUM),
        "New Relic API Key": (r"NRAK-[A-Z0-9]{27}", SecretSeverity.HIGH),
        "Sentry Auth Token": (r"sntrys_[a-zA-Z0-9]{64}", SecretSeverity.HIGH),
        "Algolia API Key": (r"[a-f0-9]{32}", SecretSeverity.MEDIUM),
        "Cloudflare API Key": (r"[a-f0-9]{37}", SecretSeverity.MEDIUM),
        "Firebase API Key": (r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", SecretSeverity.HIGH),
        "Telegram Bot Token": (r"\d{8,10}:[a-zA-Z0-9_-]{35}", SecretSeverity.HIGH),
        "Discord Bot Token": (r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}", SecretSeverity.HIGH),
        "Discord Webhook": (r"https://discord(app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+", SecretSeverity.HIGH),
        
        # Database
        "PostgreSQL Connection": (r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+", SecretSeverity.CRITICAL),
        "MySQL Connection": (r"mysql://[^:]+:[^@]+@[^/]+/\w+", SecretSeverity.CRITICAL),
        "MongoDB Connection": (r"mongodb(\+srv)?://[^:]+:[^@]+@[^/]+", SecretSeverity.CRITICAL),
        "Redis Connection": (r"redis://[^:]+:[^@]+@[^/]+", SecretSeverity.CRITICAL),
        
        # Generic Patterns
        "Password in URL": (r"://[^:]+:([^@]+)@", SecretSeverity.HIGH),
        "Generic Password": (r"(?i)(password|passwd|pwd|secret|api_key|apikey)\s*[=:]\s*['\"]?([^\s'\"]{8,})", SecretSeverity.MEDIUM),
        "JWT Token": (r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", SecretSeverity.HIGH),
        "Bearer Token": (r"bearer\s+[a-zA-Z0-9_\-\.=]+", SecretSeverity.MEDIUM),
        "Basic Auth": (r"basic\s+[a-zA-Z0-9+/=]+", SecretSeverity.MEDIUM),
        
        # Infrastructure
        "Kubernetes Secret": (r"kubectl create secret", SecretSeverity.MEDIUM),
        "Terraform State": (r'"sensitive_values":', SecretSeverity.HIGH),
        "Ansible Vault": (r"\$ANSIBLE_VAULT;", SecretSeverity.MEDIUM),
    }
    
    # False positive patterns to filter out
    IGNORE_PATTERNS = [
        r"example\.com",
        r"placeholder",
        r"your[_-]?api[_-]?key",
        r"xxx+",
        r"000+",
        r"aaa+",
        r"test[_-]?key",
        r"sample",
        r"dummy",
    ]
    
    def __init__(self, trufflehog_wrapper=None):
        """
        Initialize the enhanced secrets scanner.
        
        Args:
            trufflehog_wrapper: Optional ToolWrappers instance with TruffleHog access
        """
        self.trufflehog_wrapper = trufflehog_wrapper
        self.compiled_patterns = {
            name: (re.compile(pattern, re.IGNORECASE if 'password' in name.lower() else 0), severity)
            for name, (pattern, severity) in self.PATTERNS.items()
        }
        self.ignore_patterns = [re.compile(p, re.IGNORECASE) for p in self.IGNORE_PATTERNS]
    
    def _is_false_positive(self, value: str) -> bool:
        """Check if a potential secret is a known false positive."""
        for pattern in self.ignore_patterns:
            if pattern.search(value):
                return True
        return False
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        import math
        if not text:
            return 0
        
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        
        entropy = 0
        for count in freq.values():
            p = count / len(text)
            entropy -= p * math.log2(p)
        
        return entropy
    
    def scan_text(self, text: str, file_path: Optional[str] = None) -> List[SecretFinding]:
        """
        Scan text for secrets using regex patterns.
        
        Args:
            text: Text content to scan
            file_path: Optional file path for context
            
        Returns:
            List of SecretFinding objects
        """
        findings = []
        
        if not text:
            return findings
        
        lines = text.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for secret_type, (pattern, severity) in self.compiled_patterns.items():
                matches = pattern.findall(line)
                
                for match in matches:
                    # Handle tuple matches (from groups)
                    if isinstance(match, tuple):
                        match = match[-1] if match[-1] else match[0]
                    
                    # Skip false positives
                    if self._is_false_positive(match):
                        continue
                    
                    # Skip low-entropy matches for generic patterns
                    if severity in [SecretSeverity.MEDIUM, SecretSeverity.LOW]:
                        if self._calculate_entropy(match) < 3.0:
                            continue
                    
                    # Redact the secret
                    redacted = f"{match[:6]}..." if len(match) > 6 else "***"
                    
                    findings.append(SecretFinding(
                        secret_type=secret_type,
                        redacted_value=redacted,
                        file_path=file_path,
                        line_number=line_num,
                        severity=severity,
                        verified=False,
                        context=line[:100] if len(line) > 100 else line,
                        detector="regex"
                    ))
        
        # Deduplicate by redacted value and type
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f.secret_type, f.redacted_value)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        
        return unique_findings
    
    async def scan_with_trufflehog(
        self,
        target: str,
        scan_type: str = "filesystem",
        verify: bool = True
    ) -> List[SecretFinding]:
        """
        Scan using TruffleHog for verified secret detection.
        
        Args:
            target: Path, URL, or S3 bucket to scan
            scan_type: One of 'filesystem', 'git', 's3'
            verify: Whether to verify discovered credentials
            
        Returns:
            List of SecretFinding objects
        """
        if not self.trufflehog_wrapper:
            return []
        
        results = await self.trufflehog_wrapper.run_trufflehog(
            target=target,
            scan_type=scan_type,
            verify=verify
        )
        
        findings = []
        for result in results:
            findings.append(SecretFinding(
                secret_type=result.get('detector', 'Unknown'),
                redacted_value=result.get('redacted', '***'),
                file_path=result.get('file'),
                line_number=result.get('line'),
                severity=SecretSeverity.CRITICAL if result.get('verified') else SecretSeverity.HIGH,
                verified=result.get('verified', False),
                context=result.get('source_name'),
                detector="trufflehog"
            ))
        
        return findings
    
    async def comprehensive_scan(
        self,
        text: str = None,
        file_path: str = None,
        use_trufflehog: bool = True
    ) -> List[SecretFinding]:
        """
        Perform comprehensive scanning using both regex and TruffleHog.
        
        Args:
            text: Text content to scan
            file_path: Path to scan with TruffleHog
            use_trufflehog: Whether to use TruffleHog (if available)
            
        Returns:
            Combined and deduplicated list of findings
        """
        findings = []
        
        # Regex scan
        if text:
            findings.extend(self.scan_text(text, file_path))
        
        # TruffleHog scan
        if use_trufflehog and file_path and self.trufflehog_wrapper:
            try:
                th_findings = await self.scan_with_trufflehog(
                    target=file_path,
                    scan_type="filesystem",
                    verify=True
                )
                findings.extend(th_findings)
            except Exception as e:
                print(f"[!] TruffleHog scan failed: {e}")
        
        # Sort by severity
        severity_order = {
            SecretSeverity.CRITICAL: 0,
            SecretSeverity.HIGH: 1,
            SecretSeverity.MEDIUM: 2,
            SecretSeverity.LOW: 3
        }
        findings.sort(key=lambda f: severity_order.get(f.severity, 4))
        
        return findings
    
    def format_findings(self, findings: List[SecretFinding]) -> List[Dict[str, Any]]:
        """Convert findings to dictionary format for JSON serialization."""
        return [
            {
                "type": f.secret_type,
                "redacted": f.redacted_value,
                "file": f.file_path,
                "line": f.line_number,
                "severity": f.severity.value,
                "verified": f.verified,
                "detector": f.detector
            }
            for f in findings
        ]


# Backwards compatibility alias
SecretsScanner = EnhancedSecretsScanner
