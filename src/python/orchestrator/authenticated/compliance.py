from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table

console = Console()

class ComplianceChecker:
    def check(self, data: Dict[str, Any]) -> List[str]:
        risks = []
        
        # 1. S3 Checks
        buckets = data.get('s3', [])
        for b in buckets:
            if not b.get('public_access_block'):
                risks.append(f"[High] S3 Bucket {b['name']} does not have Public Access Block enabled.")

        # 2. IAM Checks
        iam = data.get('iam', {})
        users_no_mfa = iam.get('mfa_summary', {}).get('users_without_mfa', 0)
        if users_no_mfa > 0:
            risks.append(f"[Medium] {users_no_mfa} IAM Users do not have MFA enabled.")

        # 3. EC2 Checks
        # (SG checks were done inline in enumerator for now, but usually should be here)
        
        return risks

    def print_report(self, risks: List[str]):
        if not risks:
            console.print("[green][+] Compliance Check Passed (Basic)[/green]")
            return

        table = Table(title="Compliance Risks")
        table.add_column("Severity", style="red")
        table.add_column("Description")
        
        for risk in risks:
            sev = "High" if "[High]" in risk else "Medium"
            desc = risk.replace(f"[{sev}] ", "")
            table.add_row(sev, desc)
            
        console.print(table)
