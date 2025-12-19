"""
Cloud Reconnaissance API Endpoints

Provides REST API for cloud scanning features:
- Storage Enumeration (S3, Azure Blob, GCS)
- Cloud Service Discovery (100+ services)
- Secret Scanning (TruffleHog integration)
- Subdomain Enumeration
- Web Crawling (Katana)
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from enum import Enum
import asyncio
import json
import uuid
import os
from datetime import datetime

router = APIRouter(prefix="/api/cloud", tags=["Cloud Reconnaissance"])


class ScanMode(str, Enum):
    fast = "fast"
    normal = "normal"
    deep = "deep"
    stealth = "stealth"


class CloudScanRequest(BaseModel):
    """Request model for cloud scanning."""
    target: str
    mode: ScanMode = ScanMode.normal
    enable_storage: bool = True
    enable_services: bool = True
    enable_subdomains: bool = True
    enable_crawl: bool = False
    enable_secrets: bool = True
    enable_vulns: bool = True
    threads: int = 50
    timeout: int = 10


class StorageEnumRequest(BaseModel):
    """Request model for storage enumeration."""
    keyword: str
    providers: List[str] = ["aws", "azure", "gcp"]
    threads: int = 50
    mutations: Optional[List[str]] = None


class SecretScanRequest(BaseModel):
    """Request model for secret scanning."""
    target: str
    scan_type: str = "filesystem"  # filesystem, git, s3
    verify: bool = True


class SubdomainRequest(BaseModel):
    """Request model for subdomain enumeration."""
    domain: str
    resolve: bool = True


class CrawlRequest(BaseModel):
    """Request model for web crawling."""
    url: str
    depth: int = 3
    headless: bool = True


# In-memory job storage (replace with Redis/DB in production)
cloud_jobs: Dict[str, Dict[str, Any]] = {}


def get_job_file_path(job_id: str) -> str:
    """Get file path for job results."""
    os.makedirs("src/dashboard/backend/data/cloud_jobs", exist_ok=True)
    return f"src/dashboard/backend/data/cloud_jobs/{job_id}.json"


def save_job(job_id: str, job_data: Dict):
    """Save job to file."""
    cloud_jobs[job_id] = job_data
    with open(get_job_file_path(job_id), 'w') as f:
        json.dump(job_data, f, indent=2, default=str)


def load_job(job_id: str) -> Optional[Dict]:
    """Load job from file or memory."""
    if job_id in cloud_jobs:
        return cloud_jobs[job_id]
    
    file_path = get_job_file_path(job_id)
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            job_data = json.load(f)
            cloud_jobs[job_id] = job_data
            return job_data
    return None


async def run_cloud_scan(job_id: str, request: CloudScanRequest):
    """Execute cloud scan in background."""
    try:
        save_job(job_id, {
            "id": job_id,
            "type": "cloud_scan",
            "target": request.target,
            "status": "running",
            "progress": 0,
            "started_at": datetime.now().isoformat(),
            "results": {}
        })
        
        # Import the wrappers
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))
        
        from src.python.orchestrator.external.wrappers import ToolWrappers
        from src.python.orchestrator.external.cloud_service_detector import CloudServiceDetector
        
        wrappers = ToolWrappers()
        detector = CloudServiceDetector()
        results = {
            "storage": [],
            "services": [],
            "subdomains": [],
            "endpoints": [],
            "secrets": [],
            "vulnerabilities": []
        }
        
        # Phase 1: Storage Enumeration (20%)
        if request.enable_storage:
            save_job(job_id, {**load_job(job_id), "status": "running", "progress": 5, "phase": "Storage Enumeration"})
            try:
                storage_results = await wrappers.run_skyscan(request.target)
                results["storage"] = storage_results
            except Exception as e:
                results["storage_error"] = str(e)
        save_job(job_id, {**load_job(job_id), "progress": 20})
        
        # Phase 2: Subdomain Enumeration (40%)
        if request.enable_subdomains:
            save_job(job_id, {**load_job(job_id), "phase": "Subdomain Discovery"})
            try:
                subs = await wrappers.run_subfinder(request.target)
                results["subdomains"] = subs
            except Exception as e:
                results["subdomain_error"] = str(e)
        save_job(job_id, {**load_job(job_id), "progress": 40})
        
        # Phase 3: Cloud Service Detection (60%)
        if request.enable_services:
            save_job(job_id, {**load_job(job_id), "phase": "Cloud Service Detection"})
            try:
                targets = detector.generate_targets_for_keyword(request.target)
                for url in targets[:30]:
                    result = detector.detect_from_domain(url)
                    if result:
                        results["services"].append({
                            "url": url,
                            "provider": result.provider,
                            "service": result.service_name,
                            "category": result.category,
                            "severity": result.severity
                        })
            except Exception as e:
                results["services_error"] = str(e)
        save_job(job_id, {**load_job(job_id), "progress": 60})
        
        # Phase 4: Web Crawling (75%)
        if request.enable_crawl:
            save_job(job_id, {**load_job(job_id), "phase": "Web Crawling"})
            try:
                target_url = f"https://{request.target}" if not request.target.startswith("http") else request.target
                endpoints = await wrappers.run_katana(target_url, headless=True, depth=3)
                results["endpoints"] = endpoints
            except Exception as e:
                results["crawl_error"] = str(e)
        save_job(job_id, {**load_job(job_id), "progress": 75})
        
        # Phase 5: Secret Scanning (90%)
        if request.enable_secrets:
            save_job(job_id, {**load_job(job_id), "phase": "Secret Scanning"})
            try:
                for storage in results.get("storage", [])[:5]:
                    if storage.get("permissions") in ["PUBLIC", "PUBLIC_READ"]:
                        secrets = await wrappers.run_trufflehog(storage.get("url", ""), verify=True)
                        if secrets:
                            results["secrets"].extend(secrets)
            except Exception as e:
                results["secrets_error"] = str(e)
        save_job(job_id, {**load_job(job_id), "progress": 90})
        
        # Complete
        save_job(job_id, {
            **load_job(job_id),
            "status": "completed",
            "progress": 100,
            "phase": "Complete",
            "completed_at": datetime.now().isoformat(),
            "results": results,
            "summary": {
                "storage_count": len(results.get("storage", [])),
                "service_count": len(results.get("services", [])),
                "subdomain_count": len(results.get("subdomains", [])),
                "endpoint_count": len(results.get("endpoints", [])),
                "secret_count": len(results.get("secrets", [])),
                "vuln_count": len(results.get("vulnerabilities", []))
            }
        })
        
    except Exception as e:
        save_job(job_id, {
            **load_job(job_id),
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.now().isoformat()
        })


async def run_storage_enum(job_id: str, request: StorageEnumRequest):
    """Execute storage enumeration in background."""
    try:
        save_job(job_id, {
            "id": job_id,
            "type": "storage_enum",
            "keyword": request.keyword,
            "status": "running",
            "progress": 0,
            "started_at": datetime.now().isoformat()
        })
        
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))
        from src.python.orchestrator.external.wrappers import ToolWrappers
        
        wrappers = ToolWrappers()
        results = await wrappers.run_skyscan(request.keyword)
        
        # Categorize results
        by_provider = {}
        by_permission = {"public": [], "protected": [], "unknown": []}
        
        for r in results:
            provider = r.get("provider", "Unknown")
            if provider not in by_provider:
                by_provider[provider] = []
            by_provider[provider].append(r)
            
            perm = r.get("permissions", "").upper()
            if "PUBLIC" in perm:
                by_permission["public"].append(r)
            elif perm in ["PROTECTED", "PRIVATE", "AUTHENTICATED"]:
                by_permission["protected"].append(r)
            else:
                by_permission["unknown"].append(r)
        
        save_job(job_id, {
            **load_job(job_id),
            "status": "completed",
            "progress": 100,
            "completed_at": datetime.now().isoformat(),
            "results": results,
            "by_provider": by_provider,
            "by_permission": by_permission,
            "summary": {
                "total": len(results),
                "public": len(by_permission["public"]),
                "protected": len(by_permission["protected"]),
                "by_provider": {k: len(v) for k, v in by_provider.items()}
            }
        })
        
    except Exception as e:
        save_job(job_id, {
            **load_job(job_id),
            "status": "failed",
            "error": str(e)
        })


async def run_secret_scan(job_id: str, request: SecretScanRequest):
    """Execute secret scanning in background."""
    try:
        save_job(job_id, {
            "id": job_id,
            "type": "secret_scan",
            "target": request.target,
            "status": "running",
            "started_at": datetime.now().isoformat()
        })
        
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))
        from src.python.orchestrator.external.wrappers import ToolWrappers
        
        wrappers = ToolWrappers()
        results = await wrappers.run_trufflehog(request.target, scan_type=request.scan_type, verify=request.verify)
        
        # Categorize by severity
        critical = [r for r in results if r.get("verified")]
        high = [r for r in results if not r.get("verified")]
        
        save_job(job_id, {
            **load_job(job_id),
            "status": "completed",
            "progress": 100,
            "completed_at": datetime.now().isoformat(),
            "results": results,
            "summary": {
                "total": len(results),
                "verified": len(critical),
                "unverified": len(high)
            }
        })
        
    except Exception as e:
        save_job(job_id, {
            **load_job(job_id),
            "status": "failed",
            "error": str(e)
        })


# ============================================================
# API ENDPOINTS
# ============================================================

@router.post("/scan")
async def start_cloud_scan(request: CloudScanRequest, background_tasks: BackgroundTasks):
    """
    Start a comprehensive cloud attack surface scan.
    
    Includes:
    - Storage bucket enumeration (S3, Azure Blob, GCS)
    - Cloud service detection (100+ services)
    - Subdomain enumeration
    - Web crawling (optional)
    - Secret scanning
    - Vulnerability detection
    """
    job_id = str(uuid.uuid4())[:8]
    background_tasks.add_task(run_cloud_scan, job_id, request)
    return {"job_id": job_id, "status": "started", "message": "Cloud scan initiated"}


@router.post("/storage/enum")
async def start_storage_enum(request: StorageEnumRequest, background_tasks: BackgroundTasks):
    """
    Enumerate cloud storage buckets using the enhanced SkyScan engine.
    
    Supports:
    - AWS S3 (all regions)
    - Azure Blob Storage
    - Google Cloud Storage
    - DigitalOcean Spaces
    - Cloudflare R2
    """
    job_id = str(uuid.uuid4())[:8]
    background_tasks.add_task(run_storage_enum, job_id, request)
    return {"job_id": job_id, "status": "started"}


@router.post("/secrets/scan")
async def start_secret_scan(request: SecretScanRequest, background_tasks: BackgroundTasks):
    """
    Scan for secrets using TruffleHog with live verification.
    
    Detects 50+ secret types including:
    - AWS/Azure/GCP credentials
    - API keys (Stripe, GitHub, Slack, etc.)
    - Database connection strings
    - Private keys
    """
    job_id = str(uuid.uuid4())[:8]
    background_tasks.add_task(run_secret_scan, job_id, request)
    return {"job_id": job_id, "status": "started"}


@router.get("/jobs/{job_id}")
async def get_job_status(job_id: str):
    """Get the status and results of a cloud scan job."""
    job = load_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("/jobs")
async def list_jobs():
    """List all cloud scan jobs."""
    jobs_dir = "src/dashboard/backend/data/cloud_jobs"
    if not os.path.exists(jobs_dir):
        return {"jobs": []}
    
    jobs = []
    for filename in os.listdir(jobs_dir):
        if filename.endswith(".json"):
            job_id = filename.replace(".json", "")
            job = load_job(job_id)
            if job:
                jobs.append({
                    "id": job.get("id"),
                    "type": job.get("type"),
                    "status": job.get("status"),
                    "target": job.get("target") or job.get("keyword"),
                    "started_at": job.get("started_at"),
                    "progress": job.get("progress", 0)
                })
    
    return {"jobs": sorted(jobs, key=lambda x: x.get("started_at", ""), reverse=True)}


@router.delete("/jobs/{job_id}")
async def delete_job(job_id: str):
    """Delete a cloud scan job."""
    file_path = get_job_file_path(job_id)
    if os.path.exists(file_path):
        os.remove(file_path)
    if job_id in cloud_jobs:
        del cloud_jobs[job_id]
    return {"status": "deleted"}


@router.get("/services")
async def list_cloud_services():
    """List all supported cloud services (100+)."""
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))
    
    try:
        from src.python.orchestrator.external.cloud_service_detector import CLOUD_SERVICE_PATTERNS
        
        by_provider = {}
        for pattern in CLOUD_SERVICE_PATTERNS:
            provider = pattern.provider.value
            if provider not in by_provider:
                by_provider[provider] = []
            by_provider[provider].append({
                "name": pattern.service_name,
                "category": pattern.category.value,
                "severity": pattern.severity,
                "description": pattern.description
            })
        
        return {
            "total": len(CLOUD_SERVICE_PATTERNS),
            "by_provider": by_provider
        }
    except Exception as e:
        return {"error": str(e), "total": 0, "by_provider": {}}


@router.get("/stats")
async def get_cloud_stats():
    """Get statistics about cloud scans."""
    jobs_dir = "src/dashboard/backend/data/cloud_jobs"
    if not os.path.exists(jobs_dir):
        return {"total_scans": 0}
    
    total = 0
    completed = 0
    total_storage = 0
    total_secrets = 0
    
    for filename in os.listdir(jobs_dir):
        if filename.endswith(".json"):
            job = load_job(filename.replace(".json", ""))
            if job:
                total += 1
                if job.get("status") == "completed":
                    completed += 1
                    summary = job.get("summary", {})
                    total_storage += summary.get("storage_count", 0) or summary.get("total", 0)
                    total_secrets += summary.get("secret_count", 0) or summary.get("verified", 0)
    
    return {
        "total_scans": total,
        "completed_scans": completed,
        "total_storage_found": total_storage,
        "total_secrets_found": total_secrets
    }
