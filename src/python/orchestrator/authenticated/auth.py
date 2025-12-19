import boto3
from typing import Optional
from rich.console import Console

console = Console()

class AuthHandler:
    """
    Handles authentication with AWS using boto3.
    """
    def __init__(self, profile: str = None, region: str = "us-east-1"):
        self.profile = profile
        self.region = region
        self.session = None

    def get_session(self) -> Optional[boto3.Session]:
        try:
            if self.profile:
                console.print(f"[cyan]Authenticating with AWS profile: {self.profile}[/cyan]")
                self.session = boto3.Session(profile_name=self.profile, region_name=self.region)
            else:
                console.print(f"[cyan]Authenticating with AWS environment variables / default profile[/cyan]")
                self.session = boto3.Session(region_name=self.region)
            
            # Verify identity
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            console.print(f"[green]Authenticated as: {identity['Arn']}[/green]")
            return self.session
        except Exception as e:
            console.print(f"[bold red]Authentication Failed: {e}[/bold red]")
            return None
