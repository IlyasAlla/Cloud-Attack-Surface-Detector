class OIDCAnalyzer:
    """
    Analyzes OIDC Identity Providers to identify the external platform.
    """

    PROVIDERS = {
        "GitHub Actions": "token.actions.githubusercontent.com",
        "Google Cloud (GCP)": "accounts.google.com",
        "Azure AD": "login.microsoftonline.com",
        "AWS EKS": "oidc.eks",
        "GitLab CI": "gitlab.com",
        "Terraform Cloud": "app.terraform.io"
    }

    def analyze_provider(self, url: str) -> str:
        """
        Identifies the platform based on the OIDC Provider URL.
        Returns the platform name or 'Unknown OIDC Provider'.
        """
        if not url:
            return "Unknown OIDC Provider"

        for name, signature in self.PROVIDERS.items():
            if signature in url:
                return name
        
        return "Unknown OIDC Provider"
