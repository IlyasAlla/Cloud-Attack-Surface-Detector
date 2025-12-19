import json
import os
import glob
from datetime import datetime
from typing import Dict, Any, List, Tuple
from rich.console import Console
from rich.table import Table

console = Console()

class StateManager:
    """
    Manages saving/loading of scan states and diffing them for drift detection.
    """
    def __init__(self, storage_dir: str = "scans"):
        self.storage_dir = storage_dir
        if not os.path.exists(storage_dir):
            os.makedirs(storage_dir)

    def save_state(self, data: Dict[str, Any]) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.storage_dir, f"state_{timestamp}.json")
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            console.print(f"[cyan]State saved to {filename}[/cyan]")
            return filename
        except Exception as e:
            console.print(f"[red]Failed to save state: {e}[/red]")
            return ""

    def load_latest_state(self, exclude_file: str = None) -> Dict[str, Any]:
        """Loads the most recent state file, verifying it's not the one we just saved."""
        files = glob.glob(os.path.join(self.storage_dir, "state_*.json"))
        files.sort(key=os.path.getmtime, reverse=True)
        
        for f in files:
            if exclude_file and os.path.abspath(f) == os.path.abspath(exclude_file):
                continue
            try:
                with open(f, 'r') as fd:
                    return json.load(fd)
            except Exception:
                continue
        return None

    def diff(self, current: Dict[str, Any], previous: Dict[str, Any]) -> List[str]:
        changes = []
        
        # S3 Diff
        curr_s3 = {b['name']: b for b in current.get('s3', [])}
        prev_s3 = {b['name']: b for b in previous.get('s3', [])}
        
        for name in curr_s3:
            if name not in prev_s3:
                changes.append(f"[NEW] S3 Bucket: {name}")
            elif curr_s3[name].get('public_access_block') != prev_s3[name].get('public_access_block'):
                 changes.append(f"[MODIFIED] S3 Bucket {name} Public Access Block changed")

        for name in prev_s3:
            if name not in curr_s3:
                changes.append(f"[REMOVED] S3 Bucket: {name}")

        # IAM User Diff
        curr_users = {u['name']: u for u in current.get('iam', {}).get('users', [])}
        prev_users = {u['name']: u for u in previous.get('iam', {}).get('users', [])}
        
        for name in curr_users:
            if name not in prev_users:
                 changes.append(f"[NEW] IAM User: {name}")
        
        for name in prev_users:
            if name not in curr_users:
                changes.append(f"[REMOVED] IAM User: {name}")

        # EC2 Diff
        curr_ec2 = {i['id']: i for i in current.get('ec2', [])}
        prev_ec2 = {i['id']: i for i in previous.get('ec2', [])}
        
        for id in curr_ec2:
            if id not in prev_ec2:
                changes.append(f"[NEW] EC2 Instance: {id}")
        
        for id in prev_ec2:
            if id not in curr_ec2:
                changes.append(f"[REMOVED] EC2 Instance: {id}")

        return changes

    def print_diff_report(self, changes: List[str]):
        if not changes:
            console.print("[green]No infrastructure drift detected (No changes).[/green]")
            return

        table = Table(title="Drift Detection / Changes")
        table.add_column("Change Type", style="bold")
        table.add_column("Resource")
        
        for change in changes:
            if "[NEW]" in change:
                style = "green"
            elif "[REMOVED]" in change:
                style = "red"
            else:
                style = "yellow"
            
            parts = change.split("] ", 1)
            ctype = parts[0] + "]"
            res = parts[1] if len(parts) > 1 else ""
            
            table.add_row(ctype, res, style=style)
            
        console.print(table)
