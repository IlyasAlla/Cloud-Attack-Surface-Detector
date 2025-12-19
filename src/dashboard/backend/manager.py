import os
import json
import uuid
import threading
import logging
from datetime import datetime
from typing import List, Dict, Optional
from pydantic import BaseModel

from src.python.orchestrator.core.discovery import enumerate_subdomains
from src.python.orchestrator.cloud_providers.aws import AWSProvider
from src.python.orchestrator.core.runner import run_scanner
from src.python.orchestrator.reporting.generator import ReportGenerator
from src.python.orchestrator.core.normalizer import TargetResource, CloudProvider

logger = logging.getLogger(__name__)

# ... (imports)

class ScanConfig(BaseModel):
    name: str
    type: str # "network" or "cloud"
    target: Optional[str] = None
    provider: Optional[str] = None
    
    # Network Flags
    subdomains: bool = False
    ssl_scan: bool = False
    
    # Red Team Flags
    privilege_escalation: bool = True
    active_exploit: bool = False
    secrets_scan: bool = True
    attack_paths: bool = True
    multi_cloud: bool = True
    persistence: bool = True

class ScanStatus(BaseModel):
    id: str
    name: str
    type: str
    status: str # "running", "completed", "failed"
    timestamp: str
    assets_count: int = 0
    vuln_count: int = 0

class ScanManager:
    def __init__(self, data_dir: str = None):
        if data_dir:
            self.data_dir = data_dir
        else:
            # Use absolute path relative to this file
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.data_dir = os.path.join(base_dir, "data", "scans")
            
        os.makedirs(self.data_dir, exist_ok=True)
        logger.info(f"ScanManager initialized with data directory: {self.data_dir}")
        self.active_scans: Dict[str, dict] = {} # In-memory status of running scans

    def list_scans(self) -> List[ScanStatus]:
        scans = []
        # 1. Add running scans
        for scan_id, info in self.active_scans.items():
            scans.append(ScanStatus(
                id=scan_id,
                name=info['config'].name,
                type=info['config'].type,
                status="running",
                timestamp=info['start_time']
            ))
        
        # 2. Add completed scans from disk
        if os.path.exists(self.data_dir):
            for filename in os.listdir(self.data_dir):
                if filename.endswith(".json"):
                    try:
                        with open(os.path.join(self.data_dir, filename), 'r') as f:
                            data = json.load(f)
                            # Basic validation
                            if 'id' in data and 'summary' in data:
                                scans.append(ScanStatus(
                                    id=data['id'],
                                    name=data.get('name', 'Unknown Scan'),
                                    type=data.get('type', 'unknown'),
                                    status="completed",
                                    timestamp=data.get('timestamp', ''),
                                    assets_count=data['summary'].get('total_assets', 0),
                                    vuln_count=data['summary'].get('vuln_assets', 0)
                                ))
                    except Exception as e:
                        logger.error(f"Failed to load scan {filename}: {e}")
        
        # Sort by timestamp desc
        scans.sort(key=lambda x: x.timestamp, reverse=True)
        return scans

    def get_scan(self, scan_id: str) -> Optional[Dict]:
        # Check active first (though usually we want results, which might not be ready)
        if scan_id in self.active_scans:
            return {"status": "running", "info": "Scan is still in progress"}
            
        # Check disk
        filepath = os.path.join(self.data_dir, f"{scan_id}.json")
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                return json.load(f)
        return None

    def start_scan(self, config: ScanConfig) -> str:
        scan_id = str(uuid.uuid4())
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        self.active_scans[scan_id] = {
            "config": config,
            "start_time": timestamp,
            "status": "running"
        }
        
        # Run in background thread
        thread = threading.Thread(target=self._run_scan_logic, args=(scan_id, config, timestamp))
        thread.start()
        
        return scan_id

    def _run_scan_logic(self, scan_id: str, config: ScanConfig, timestamp: str):
        try:
            logger.info(f"Starting scan {scan_id}...")
            all_assets = []
            
            # 1. Discovery / Target Parsing
            if config.type == "network" and config.target:
                # Direct Target Logic
                target = config.target.replace("http://", "").replace("https://", "").rstrip("/")
                
                targets = [target]
                
                # Subdomain Enumeration
                if config.subdomains:
                    logger.info(f"Enumerating subdomains for {target}...")
                    subs = enumerate_subdomains(target)
                    if subs:
                        logger.info(f"Found {len(subs)} subdomains")
                        targets.extend(subs)
                
                # Resolve IPs and Create Assets
                import socket
                for t in targets:
                    try:
                        ip = socket.gethostbyname(t)
                    except (socket.gaierror, socket.herror) as e:
                        logger.warning(f"Failed to resolve {t}: {e}")
                        ip = t
                    except Exception as e:
                        logger.error(f"Unexpected error resolving {t}: {e}")
                        ip = t
                    
                    all_assets.append(TargetResource(
                        id=t,
                        ip_address=ip,
                        hostname=t,
                        provider=CloudProvider.NETWORK,
                        region="global",
                        resource_type="DirectTarget",
                        metadata={"Source": "Dashboard Scan"}
                    ))
                
            elif config.type == "cloud" and config.provider:
                if config.provider.lower() == "aws":
                    aws = AWSProvider(
                        scan_secrets=config.secrets_scan,
                        scan_oidc=config.multi_cloud
                    )
                    all_assets.extend(aws.discover_assets())
            
            # 2. Scanning (Go Scanner)
            # Filter scannable
            scannable = [a for a in all_assets if a.ip_address and a.ip_address != "N/A"]
            if scannable:
                # We need to handle the progress bar or logging here differently for web
                # For now, just run it
                scanned = run_scanner(scannable)
                
                # Merge
                asset_map = {a.id: a for a in all_assets}
                for sa in scanned:
                    asset_map[sa.id] = sa
                all_assets = list(asset_map.values())

            # 3. Post-Processing (Graph Data Generation)
            # We reuse ReportGenerator just to get the graph elements logic
            gen = ReportGenerator()
            graph_elements = gen._prepare_graph_data(
                all_assets,
                enable_attack_paths=config.attack_paths,
                enable_persistence=config.persistence,
                enable_privesc=config.privilege_escalation
            )

            # 4. Save Results
            vuln_count = sum(1 for a in all_assets if a.vulnerabilities)
            
            result_data = {
                "id": scan_id,
                "name": config.name,
                "type": config.type,
                "timestamp": timestamp,
                "config": config.model_dump(),
                "summary": {
                    "total_assets": len(all_assets),
                    "vuln_assets": vuln_count,
                    "providers": list(set(a.provider for a in all_assets))
                },
                "assets": [a.model_dump() for a in all_assets],
                "graph": graph_elements
            }
            
            filepath = os.path.join(self.data_dir, f"{scan_id}.json")
            with open(filepath, 'w') as f:
                json.dump(result_data, f, indent=2)
                
            logger.info(f"Scan {scan_id} completed. Saved to {filepath}")

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            
            # Save failed state to disk so it doesn't disappear
            failed_data = {
                "id": scan_id,
                "name": config.name,
                "type": config.type,
                "timestamp": timestamp,
                "status": "failed",
                "error": str(e),
                "config": config.model_dump(),
                "summary": {
                    "total_assets": 0,
                    "vuln_assets": 0,
                    "providers": []
                },
                "assets": [],
                "graph": []
            }
            
            filepath = os.path.join(self.data_dir, f"{scan_id}.json")
            with open(filepath, 'w') as f:
                json.dump(failed_data, f, indent=2)
                
        finally:
            # Remove from active
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]

    def export_csv(self, scan_id: str) -> Optional[str]:
        data = self.get_scan(scan_id)
        if not data or 'assets' not in data:
            return None
            
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(['ID', 'Type', 'Provider', 'Region', 'IP Address', 'Hostname', 'Vulnerabilities', 'Metadata'])
        
        for asset in data['assets']:
            vulns = "; ".join([f"{k}: {v}" for k, v in asset.get('vulnerabilities', {}).items()])
            meta = json.dumps(asset.get('metadata', {}))
            
            writer.writerow([
                asset.get('id'),
                asset.get('resource_type'),
                asset.get('provider'),
                asset.get('region'),
                asset.get('ip_address'),
                asset.get('hostname'),
                vulns,
                meta
            ])
            
        return output.getvalue()

    def export_pdf(self, scan_id: str) -> Optional[bytes]:
        data = self.get_scan(scan_id)
        if not data:
            return None
            
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet
        import io
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        story.append(Paragraph(f"Mission Report: {data.get('name', 'Unknown')}", styles['Title']))
        story.append(Spacer(1, 12))
        
        # Summary
        summary_data = [
            ["Scan ID", data.get('id')],
            ["Date", data.get('timestamp')],
            ["Type", data.get('type')],
            ["Total Assets", str(data.get('summary', {}).get('total_assets', 0))],
            ["Vulnerable Assets", str(data.get('summary', {}).get('vuln_assets', 0))]
        ]
        t = Table(summary_data, colWidths=[150, 300])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(t)
        story.append(Spacer(1, 24))
        
        # Assets
        story.append(Paragraph("Discovered Assets", styles['Heading2']))
        story.append(Spacer(1, 12))
        
        asset_data = [["ID", "Type", "IP", "Vulnerabilities"]]
        for asset in data.get('assets', []):
            vulns = str(len(asset.get('vulnerabilities', {})))
            asset_data.append([
                asset.get('id')[:30], # Truncate for PDF
                asset.get('resource_type'),
                asset.get('ip_address'),
                vulns
            ])
            
        t2 = Table(asset_data, colWidths=[200, 100, 100, 100])
        t2.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(t2)
        
        doc.build(story)
        buffer.seek(0)
        buffer.seek(0)
        return buffer.getvalue()

    def delete_scan(self, scan_id: str) -> bool:
        # Prevent deleting running scans
        if scan_id in self.active_scans:
            return False
            
        filepath = os.path.join(self.data_dir, f"{scan_id}.json")
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
                return True
            except Exception as e:
                logger.error(f"Failed to delete scan {scan_id}: {e}")
                return False
        return False

    def simulate_breach(self, scan_id: str, start_node_id: str) -> Dict:
        """
        Simulate a breach starting from a specific node.
        Returns a list of compromised nodes and the edges traversed.
        """
        data = self.get_scan(scan_id)
        if not data or 'graph' not in data:
            return {"compromised_nodes": [], "traversed_edges": []}

        graph = data['graph']
        
        # Build Adjacency List
        adj = {}
        for edge in [e for e in graph if isinstance(e, dict) and e.get('group') == 'edges']:
            src = edge['data']['source']
            dst = edge['data']['target']
            edge_id = edge['data']['id']
            
            if src not in adj: adj[src] = []
            adj[src].append({"target": dst, "edge_id": edge_id})

        # BFS Traversal
        queue = [start_node_id]
        compromised_nodes = set([start_node_id])
        traversed_edges = set()
        
        while queue:
            current = queue.pop(0)
            
            if current in adj:
                for neighbor in adj[current]:
                    target = neighbor['target']
                    edge_id = neighbor['edge_id']
                    
                    if target not in compromised_nodes:
                        compromised_nodes.add(target)
                        traversed_edges.add(edge_id)
                        queue.append(target)
                    elif target in compromised_nodes and edge_id not in traversed_edges:
                         # Still mark edge as traversed if it connects two compromised nodes (optional, but good for visuals)
                         traversed_edges.add(edge_id)

        return {
            "compromised_nodes": list(compromised_nodes),
            "traversed_edges": list(traversed_edges)
        }
