from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
import os
import logging
from .manager import ScanManager, ScanConfig, ScanStatus
from src.dashboard.backend.ai_agent import AIAgent
from src.dashboard.backend.credentials import CredentialsManager # Added import
from src.dashboard.backend.cloud_recon import router as cloud_recon_router  # NEW: Cloud Recon API

app = FastAPI(title="Cloud Attack Surface Command Center")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all for dev, restrict in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(cloud_recon_router)  # NEW: Cloud Recon endpoints

# Initialize Managers (Renamed 'manager' to 'scan_manager' and added 'ai_agent')
# Initialize Managers
scan_manager = ScanManager()
ai_agent = AIAgent()
credentials_manager = CredentialsManager()

@app.get("/")
def read_root():
    return {"status": "online", "system": "Command Center Backend", "version": "2.0"}

# AI Endpoint (Added new endpoint and Pydantic model)
from pydantic import BaseModel # BaseModel is already imported later, but good to have it here for clarity if AIRequest is used before SettingsUpdate

class AIRequest(BaseModel):
    asset: dict
    vulnerabilities: dict

@app.post("/api/ai/analyze")
async def analyze_vulnerability(request: AIRequest):
    analysis = ai_agent.analyze_vulnerability(request.asset, request.vulnerabilities)
    return {"analysis": analysis}

class ScanReportRequest(BaseModel):
    scan_data: dict

@app.post("/api/ai/scan_report")
async def generate_scan_report(request: ScanReportRequest):
    report = ai_agent.analyze_scan(request.scan_data)
    return {"report": report}

class BreachSimulationRequest(BaseModel):
    scan_id: str
    start_node_id: str

@app.post("/api/graph/simulate_breach")
def simulate_breach(request: BreachSimulationRequest):
    result = scan_manager.simulate_breach(request.scan_id, request.start_node_id)
    return result

@app.get("/api/scans", response_model=List[ScanStatus])
def list_scans():
    return scan_manager.list_scans()

from fastapi.responses import Response

@app.get("/api/scans/{scan_id}/export/csv")
def export_scan_csv(scan_id: str):
    csv_content = scan_manager.export_csv(scan_id)
    if not csv_content:
        return {"error": "Scan not found or no assets"}
    
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"}
    )

@app.get("/api/scans/{scan_id}/export/pdf")
def export_scan_pdf(scan_id: str):
    pdf_content = scan_manager.export_pdf(scan_id)
    if not pdf_content:
        return {"error": "Scan not found"}
    
    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.pdf"}
    )

@app.post("/api/scan")
def start_scan(config: ScanConfig):
    scan_id = scan_manager.start_scan(config)
    return {"scan_id": scan_id, "status": "started"}

@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    result = scan_manager.get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result

@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str):
    success = scan_manager.delete_scan(scan_id)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to delete scan. It might be running or doesn't exist.")
    return {"status": "deleted", "id": scan_id}

# Configure Logging
log_file = "src/dashboard/backend/data/app.log"
os.makedirs(os.path.dirname(log_file), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Settings Management
from pydantic import BaseModel
import os

class SettingsUpdate(BaseModel):
    # AWS
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_default_region: Optional[str] = None
    
    # Azure
    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[str] = None
    azure_tenant_id: Optional[str] = None
    azure_subscription_id: Optional[str] = None
    
    # GCP
    google_application_credentials: Optional[str] = None
    
    # AI
    gemini_api_key: Optional[str] = None

@app.post("/api/settings")
def update_settings(settings: SettingsUpdate):
    # 0. Save to credentials.json
    credentials_manager.save_credentials(settings.model_dump(exclude_none=True))

    # 1. Update .env file
    env_path = ".env"
    lines = []
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            lines = f.readlines()
    
    # Helper to update or append
    def update_line(key, value):
        if value is None: return # Skip if not provided
        
        found = False
        for i, line in enumerate(lines):
            if line.startswith(f"{key}="):
                lines[i] = f"{key}={value}\n"
                found = True
                break
        if not found:
            if lines and not lines[-1].endswith('\n'):
                lines[-1] += '\n'
            lines.append(f"{key}={value}\n")
        
        # Also update process env
        os.environ[key] = value
    
    # AWS
    update_line("AWS_ACCESS_KEY_ID", settings.aws_access_key_id)
    update_line("AWS_SECRET_ACCESS_KEY", settings.aws_secret_access_key)
    update_line("AWS_DEFAULT_REGION", settings.aws_default_region)
    
    # Azure
    update_line("AZURE_CLIENT_ID", settings.azure_client_id)
    update_line("AZURE_CLIENT_SECRET", settings.azure_client_secret)
    update_line("AZURE_TENANT_ID", settings.azure_tenant_id)
    update_line("AZURE_SUBSCRIPTION_ID", settings.azure_subscription_id)
    
    # GCP
    update_line("GOOGLE_APPLICATION_CREDENTIALS", settings.google_application_credentials)
    
    # AI
    update_line("GEMINI_API_KEY", settings.gemini_api_key)
    
    with open(env_path, "w") as f:
        f.writelines(lines)
    
    # Reload AI Agent
    ai_agent.reload_config()
    
    # Reload AI Agent
    ai_agent.reload_config()
    
    return {"status": "updated"}

@app.get("/api/settings")
def get_settings():
    return credentials_manager.get_credentials(mask=True)

@app.get("/api/logs")
def get_logs(lines: int = 100):
    if not os.path.exists(log_file):
        return {"logs": []}
    
    try:
        with open(log_file, "r") as f:
            all_lines = f.readlines()
            return {"logs": all_lines[-lines:]}
    except Exception as e:
        return {"logs": [f"Error reading logs: {str(e)}"]}
