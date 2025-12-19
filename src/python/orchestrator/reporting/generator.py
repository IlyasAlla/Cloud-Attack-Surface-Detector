from jinja2 import Environment, FileSystemLoader
import os
from typing import List, Dict
from src.python.orchestrator.core.normalizer import TargetResource

class ReportGenerator:
    def __init__(self, template_dir: str = "src/python/orchestrator/reporting/templates"):
        # Adjust path to be absolute or relative to execution
        base_path = os.path.dirname(os.path.abspath(__file__))
        template_path = os.path.join(base_path, "templates")
        self.env = Environment(loader=FileSystemLoader(template_path))

    def _prepare_graph_data(self, assets: List[TargetResource], enable_attack_paths: bool = True, enable_persistence: bool = True, enable_privesc: bool = True) -> List[Dict]:
        """Converts assets into Cytoscape.js elements (nodes and edges)."""
        elements = []
        regions = set()
        
        # 1. Create Asset Nodes & Basic Edges
        for asset in assets:
            # Determine Color
            node_color = "#ccc"
            if asset.resource_type == "EC2": node_color = "#00f2ff"
            elif asset.resource_type == "S3": node_color = "#ffbd00"
            elif asset.resource_type == "IAM": node_color = "#7000ff"
            elif "IAM" in asset.resource_type: node_color = "#7000ff"
            elif "OIDC Provider" in asset.resource_type: node_color = "#ff00ff"

            # Flatten vulnerabilities
            vulns = []
            for v_list in asset.vulnerabilities.values():
                vulns.extend(v_list)
            is_vuln = len(vulns) > 0

            # Asset Node
            elements.append({
                "data": {
                    "id": asset.id,
                    "label": asset.hostname or asset.id,
                    "type": asset.resource_type.split(" ")[0],
                    "provider": asset.provider,
                    "region": asset.region,
                    "ip": asset.ip_address,
                    "vulnerable": str(is_vuln).lower(),
                    "vulnerabilities": vulns,
                    "ports": asset.open_ports,
                    "metadata": asset.metadata,
                    "color": node_color
                }
            })

            # Region Node
            if asset.region and asset.region != "global":
                region_id = f"region_{asset.region}"
                if asset.region not in regions:
                    elements.append({
                        "data": { "id": region_id, "label": asset.region, "type": "Region", "color": "#555" }
                    })
                    regions.add(asset.region)
                elements.append({
                    "data": { "source": asset.id, "target": region_id, "label": "DEPLOYED_IN" }
                })

            # Internet/Port Edges
            if asset.open_ports:
                internet_id = "The_Internet"
                if not any(e['data'].get('id') == internet_id for e in elements):
                     elements.append({
                        "data": { "id": internet_id, "label": "Internet", "type": "Network", "color": "#fff" }
                    })
                elements.append({
                    "data": { "source": internet_id, "target": asset.id, "label": f"EXPOSES {len(asset.open_ports)} PORTS" }
                })

        # 2. Advanced Analysis (Edges & Special Nodes)
        from src.python.orchestrator.analysis.iam_analyzer import IAMAnalyzer
        iam_analyzer = IAMAnalyzer()
        
        for asset in assets:
            # IAM Privilege Escalation
            if enable_privesc and "IAM" in asset.resource_type:
                policies = asset.metadata.get("Policies", [])
                escalations = iam_analyzer.check_privilege_escalation(policies)
                if escalations:
                    # Update vulns in existing node
                    for el in elements:
                        if el['data'].get('id') == asset.id:
                            el['data']['vulnerabilities'].extend(escalations)
                            el['data']['vulnerable'] = "true"
                    
                    # Create Admin Node & Edge
                    admin_node_id = "Privilege_Escalation_Target"
                    if not any(e['data'].get('id') == admin_node_id for e in elements):
                        elements.append({
                            "data": { "id": admin_node_id, "label": "Full Admin Privileges", "type": "Target", "color": "#ff0000" }
                        })
                    elements.append({
                        "data": { "source": asset.id, "target": admin_node_id, "label": "CAN_ESCALATE", "lineColor": "#ff0000" }
                    })

            # OIDC Trust (Always run if data exists, as it's just visualization)
            if asset.resource_type == "IAM Role":
                assume_policy = asset.metadata.get("AssumeRolePolicyDocument", {})
                for statement in assume_policy.get("Statement", []):
                    if statement.get("Effect") == "Allow":
                        principal = statement.get("Principal", {})
                        federated = principal.get("Federated")
                        if federated:
                            feds = [federated] if isinstance(federated, str) else federated
                            for fed_arn in feds:
                                if ":oidc-provider/" in fed_arn:
                                    provider_url = fed_arn.split(":oidc-provider/")[-1]
                                    elements.append({
                                        "data": { "source": asset.id, "target": provider_url, "label": "TRUSTS_OIDC", "lineColor": "#ff00ff", "lineStyle": "dashed" }
                                    })

        # 3. Attack Path Analysis (Kill Chains)
        if enable_attack_paths:
            from src.python.orchestrator.analysis.attack_path_analyzer import AttackPathAnalyzer
            path_analyzer = AttackPathAnalyzer()
            kill_chains = path_analyzer.analyze(assets)
            
            for chain in kill_chains:
                chain_id = f"chain_{chain['name'].replace(' ', '_')}"
                if not any(e['data'].get('id') == chain_id for e in elements):
                    elements.append({
                        "data": { "id": chain_id, "label": f"KILL CHAIN: {chain['name']}", "type": "KillChain", "color": "#ff0000", "metadata": {"Description": chain['description']} }
                    })
                for asset_id in chain['assets']:
                    elements.append({
                        "data": { "source": asset_id, "target": chain_id, "label": "PART_OF_CHAIN", "lineColor": "#ff4500", "lineStyle": "dashed" }
                    })

        # 4. Persistence & C2 Analysis
        if enable_persistence:
            from src.python.orchestrator.analysis.persistence_analyzer import PersistenceAnalyzer
            persistence_analyzer = PersistenceAnalyzer()
            persistence_findings = persistence_analyzer.analyze(assets)
            
            for finding in persistence_findings:
                asset_id = finding['asset_id']
                for el in elements:
                    if el['data'].get('id') == asset_id:
                        el['data']['vulnerabilities'].append(f"{finding['type']}: {finding['description']}")
                        el['data']['vulnerable'] = "true"
                        if finding['severity'] == "HIGH":
                            el['data']['color'] = "#ff4500"

        return elements

    def generate_html(self, assets: List[TargetResource], output_file: str, template_name: str = "report.html", 
                      enable_attack_paths: bool = True, enable_persistence: bool = True, enable_privesc: bool = True):
        """Generates an HTML report from the scan results."""
        template = self.env.get_template(template_name)
        
        # Calculate stats
        total_assets = len(assets)
        vuln_assets = sum(1 for a in assets if a.vulnerabilities)
        
        # Cloud specific stats
        shadow_assets = sum(1 for a in assets if a.metadata.get("Shadow") == "True")
        providers = list(set(a.provider for a in assets))

        # Graph Data (only if using graph template)
        graph_data = []
        if "graph" in template_name:
            graph_data = self._prepare_graph_data(assets, enable_attack_paths, enable_persistence, enable_privesc)

        # Convert Pydantic models to dicts for Jinja2
        assets_dicts = [asset.model_dump() for asset in assets]

        from datetime import datetime
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html_content = template.render(
            assets=assets_dicts,
            stats={
                "total": total_assets,
                "vuln": vuln_assets,
                "shadow_assets": shadow_assets,
                "providers": providers,
                "generated_at": generated_at
            },
            graph_data=graph_data
        )
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        print(f"Report generated at: {output_file}")
