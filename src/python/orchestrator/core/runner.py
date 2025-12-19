import subprocess
import json
import logging
import sys
from typing import List
from .normalizer import TargetResource

logger = logging.getLogger(__name__)

import os

def run_scanner(targets: List[TargetResource], ports: str = None, binary_path: str = None) -> List[TargetResource]:
    # Resolve binary path dynamically if not provided
    if binary_path is None:
        # runner.py is in src/python/orchestrator/core/
        # bin/ is in cloud-attack-surface-detector/bin/
        # So we go up 4 levels: core -> orchestrator -> python -> src -> root
        base_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.abspath(os.path.join(base_dir, "../../../../"))
        binary_path = os.path.join(project_root, "bin", "naabu")

    # Naabu doesn't take JSON input via stdin in the same way the custom scanner likely did.
    # We need to adapt this to run naabu for each target or use a list file.
    # Naabu can take a list of hosts via stdin.
    
    logger.info(f"Starting Naabu scanner with {len(targets)} targets...")
    
    target_ips = [t.ip_address for t in targets if t.ip_address]
    if not target_ips:
        return targets

    try:
        # Build command
        cmd = [binary_path, "-json", "-silent"]
        if ports:
            cmd.extend(["-p", ports])
        
        # Prepare input (newline separated IPs)
        input_data = "\n".join(target_ips)

        # Run Naabu
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate(input=input_data)
        
        if process.returncode != 0:
            logger.error(f"Naabu failed: {stderr}")
            return targets # Return original targets without updates

        # Parse Naabu JSON output
        # {"ip":"1.2.3.4", "port":80}
        scan_results = []
        for line in stdout.splitlines():
            try:
                scan_results.append(json.loads(line))
            except json.JSONDecodeError:
                pass
            
        # Correlate results back to TargetResource objects
        lookup = {}
        for t in targets:
            if t.ip_address not in lookup:
                lookup[t.ip_address] = []
            lookup[t.ip_address].append(t)

        for result in scan_results:
            ip = result.get('ip')
            port = result.get('port')
            
            if ip in lookup:
                for asset in lookup[ip]:
                    if port not in asset.open_ports:
                        asset.open_ports.append(port)
                        
        # Flatten the list of lists
        return [asset for sublist in lookup.values() for asset in sublist]

    except Exception as e:
        logger.error(f"Scanner execution failed: {e}")
        return targets

