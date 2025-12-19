import os
import google.generativeai as genai
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class AIAgent:
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            logger.warning("GEMINI_API_KEY not found in environment variables. AI features will be disabled.")
            self.model = None
        else:
            try:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel('gemini-2.0-flash-lite-preview')
                logger.info("AI Agent initialized with Gemini 2.0 Flash Lite.")
            except Exception as e:
                logger.error(f"Failed to initialize AI Agent: {e}")
                self.model = None

    def reload_config(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            logger.warning("GEMINI_API_KEY not found during reload.")
            self.model = None
            return False
        
        try:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel('gemini-2.0-flash-lite-preview')
            logger.info("AI Agent re-initialized with Gemini 2.0 Flash Lite.")
            return True
        except Exception as e:
            logger.error(f"Failed to re-initialize AI Agent: {e}")
            self.model = None
            return False

    def analyze_vulnerability(self, asset_info: Dict, vulnerabilities: Dict) -> str:
        if not self.model:
            return "AI Agent is not configured. Please set GEMINI_API_KEY."

        prompt = f"""
        You are an expert Red Team Operator and Cloud Security Engineer.
        Analyze the following asset and its vulnerabilities.
        
        Asset Context:
        - ID: {asset_info.get('id')}
        - Type: {asset_info.get('resource_type')}
        - Provider: {asset_info.get('provider')}
        - Metadata: {asset_info.get('metadata')}
        
        Vulnerabilities Detected:
        {vulnerabilities}
        
        Provide a concise, actionable report in Markdown format with the following sections:
        
        ### 1.  Threat Analysis
        Explain why this is dangerous. What can an attacker do? (Be specific to the asset type).
        
        ### 2. ️ Exploitation (Red Team)
        Briefly describe how to verify or exploit this. Provide a CLI command or script snippet if applicable (e.g., AWS CLI, curl, python).
        
        ### 3. ️ Remediation (Blue Team)
        Step-by-step fix. Provide Terraform/CloudFormation code or CLI commands to patch it.
        
        Keep it technical and direct.
        """
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"AI Analysis failed: {e}")
            return f"Error generating analysis: {str(e)}"

    def analyze_scan(self, scan_data: Dict) -> str:
        if not self.model:
            return "AI Agent is not configured. Please set GEMINI_API_KEY."

        # Summarize data to fit in context window
        summary = scan_data.get("summary", {})
        assets = scan_data.get("assets", [])
        
        # Filter for vulnerable assets only to save tokens
        vuln_assets = [
            {
                "id": a.get("id"),
                "type": a.get("resource_type"),
                "vulns": a.get("vulnerabilities")
            }
            for a in assets if a.get("vulnerabilities")
        ]

        prompt = f"""
        You are a CISO and Lead Security Architect.
        Generate a comprehensive Executive Security Report for the following cloud infrastructure scan.

        Scan Summary:
        - Total Assets: {summary.get("total_assets")}
        - Vulnerable Assets: {summary.get("vuln_assets")}
        - Scan Type: {scan_data.get("type")}
        - Timestamp: {scan_data.get("timestamp")}

        Vulnerable Assets Detail:
        {vuln_assets}

        Please provide a report in Markdown format with the following sections. Use **Tables** where appropriate to summarize data.

        # ️ Executive Security Summary
        > **Executive Overview**: Provide a high-level summary of the security posture. Is the infrastructure secure? What is the overall risk level (Low/Medium/High/Critical)?

        ##  Top 3 Critical Risks
        Identify the 3 most dangerous vulnerabilities. Use a table for this section:
        | Risk | Severity | Impact |
        | :--- | :--- | :--- |
        | ... | ... | ... |

        ##  Attack Surface Analysis
        Briefly analyze the exposure.
        - **Public Endpoints**: Are there too many?
        - **Identity**: Is IAM weak?
        - **Data**: Is storage unencrypted?

        ##  Strategic Recommendations
        Provide 3-5 high-level strategic actions.
        1. **Action 1**: Detail...
        2. **Action 2**: Detail...

        ## ️ Immediate Remediation Plan
        A checklist of technical actions.
        - [ ] Action 1
        - [ ] Action 2

        Tone: Professional, authoritative, and actionable. Use emojis to highlight key points.
        """

        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"AI Scan Analysis failed: {e}")
            return f"Error generating scan report: {str(e)}"
