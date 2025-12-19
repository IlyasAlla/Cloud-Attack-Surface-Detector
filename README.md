<div align="center">

# Cloud Attack Surface Detector

### The Ultimate Multi-Cloud Security Reconnaissance Framework

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Go 1.21+](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://golang.org/dl/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![AWS](https://img.shields.io/badge/AWS-Supported-FF9900.svg)](https://aws.amazon.com/)
[![Azure](https://img.shields.io/badge/Azure-Supported-0078D4.svg)](https://azure.microsoft.com/)
[![GCP](https://img.shields.io/badge/GCP-Supported-4285F4.svg)](https://cloud.google.com/)

**Discover | Scan | Analyze | Visualize**

*A hybrid Python-Go security tool that maps your cloud attack surface across AWS, Azure, and GCP.*

</div>

---

## Overview

**Cloud Attack Surface Detector (CASD)** is an open-source security framework designed for penetration testers, red teams, and security engineers. It automatically discovers cloud assets, scans for open ports, detects leaked secrets, and visualizes attack paths.

### Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Cloud Discovery** | Enumerate assets across AWS, Azure, and GCP simultaneously |
| **High-Speed Scanning** | Go-powered scanner handles 10,000+ concurrent connections |
| **Secrets Detection** | Find hardcoded API keys, passwords, and credentials |
| **Attack Path Analysis** | Identify privilege escalation chains (e.g., "Golden Ticket") |
| **Web Dashboard** | Real-time visualization with Next.js frontend |
| **AI-Powered Reports** | Generate executive summaries using Gemini AI |

---

## Architecture

```
+-------------------+       +-------------------+       +-------------------+
|  Python           |  -->  |  Go SkyScan       |  -->  |  Next.js          |
|  Orchestrator     |       |  Engine           |       |  Dashboard        |
|  (Discovery, API) |       |  (Port Scanning)  |       |  (Visualization)  |
+-------------------+       +-------------------+       +-------------------+
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- Go 1.21+
- Node.js 18+ (for Dashboard)
- Cloud credentials (AWS/Azure/GCP)

### Installation

#### Automated Installation (Recommended)

Run the installation script to automatically set up everything:

```bash
# Clone the repository
git clone https://github.com/your-org/cloud-attack-surface-detector.git
cd cloud-attack-surface-detector

# Run the installer
chmod +x install.sh
./install.sh
```

**Install Script Options:**
| Option | Description |
|--------|-------------|
| `--skip-dashboard` | Skip Node.js dashboard installation |
| `--skip-go` | Skip Go scanner compilation |
| `--help` | Show help message |

```bash
# Example: Install without dashboard
./install.sh --skip-dashboard

# Example: Python-only installation
./install.sh --skip-dashboard --skip-go
```

---

#### Manual Installation

If you prefer manual installation, follow these steps:

##### Step 1: Clone the Repository

```bash
git clone https://github.com/your-org/cloud-attack-surface-detector.git
cd cloud-attack-surface-detector
```

#### Step 2: Set Up Python Environment

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

# Or install from src/python
pip install -r src/python/requirements.txt
```

**Required Python Packages:**
- `boto3` - AWS SDK
- `azure-mgmt-network`, `azure-identity` - Azure SDK
- `google-cloud-asset` - GCP SDK
- `typer`, `rich` - CLI framework
- `pydantic` - Data validation
- `fastapi`, `uvicorn` - Dashboard backend
- `jinja2` - Report templating

#### Step 3: Build Go Scanner (Optional)

```bash
cd src/go/skyscan
go build -o ../../../bin/skyscan ./cmd/skyscan
cd ../../..

# Verify installation
./bin/skyscan --version
```

#### Step 4: Install Dashboard Dependencies

The dashboard requires Node.js 18+ and npm. Install the frontend dependencies:

```bash
cd src/dashboard/frontend
npm install
cd ../../..
```

**Frontend Dependencies (package.json):**
| Package | Version | Purpose |
|---------|---------|---------|
| `next` | 16.0.5 | React framework |
| `react` | 19.2.0 | UI library |
| `react-dom` | 19.2.0 | React DOM |
| `lucide-react` | 0.555.0 | Icons |
| `cytoscape` | 3.33.1 | Network graph visualization |
| `framer-motion` | 12.23.24 | Animations |
| `react-markdown` | 10.1.0 | Markdown rendering |
| `clsx` | 2.1.1 | CSS class utilities |

**Dev Dependencies:**
| Package | Version |
|---------|---------|
| `typescript` | ^5 |
| `eslint` | ^9 |
| `@types/react` | ^19 |
| `@types/node` | ^20 |

#### Quick Install (All Components)

```bash
# One-liner to install everything
pip install -r requirements.txt && \
cd src/go/skyscan && go build -o ../../../bin/skyscan ./cmd/skyscan && cd ../../.. && \
cd src/dashboard/frontend && npm install && cd ../../..
```

### Configuration

Create a `.env` file in the project root:

```bash
# AWS Credentials
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=us-east-1

# Azure Credentials (Optional)
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret
AZURE_TENANT_ID=your_tenant_id
AZURE_SUBSCRIPTION_ID=your_subscription_id

# GCP Credentials (Optional)
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# AI Features (Optional)
GEMINI_API_KEY=your_gemini_api_key
```

---

## Usage

### Command Line Interface (CLI)

The primary way to use CASD is through the `cloud-asf` CLI.

#### 1. External Reconnaissance (Domain-Based)

Discover subdomains and scan external infrastructure without cloud credentials:

```bash
# Basic external scan
cloud-asf recon full --domain example.com

# With specific modules
cloud-asf recon full --domain example.com --enable-secrets --enable-fuzzing

# Output to JSON
cloud-asf recon full --domain example.com --output results.json --format json
```

#### 2. Cloud Asset Discovery

Enumerate assets directly from cloud provider APIs:

```bash
# Scan all configured providers
cloud-asf scan --providers aws,azure,gcp

# AWS only with deep mode
cloud-asf scan --providers aws --mode deep

# Skip network scanning (discovery only)
cloud-asf scan --providers aws --skip-scanner
```

#### 3. Storage Bucket Enumeration

Find exposed S3, Azure Blob, and GCS buckets:

```bash
# Permutation-based bucket discovery
cloud-asf storage enumerate --keyword companyname --providers aws,gcp

# Check specific bucket
cloud-asf storage check --bucket my-bucket-name --provider aws
```

#### 4. Secrets Scanning

Scan repositories or directories for leaked credentials:

```bash
# Scan a local directory
cloud-asf secrets scan --path /path/to/codebase

# Scan with TruffleHog integration
cloud-asf secrets scan --path /path/to/repo --deep
```

### Web Dashboard

For a visual experience, launch the dashboard:

```bash
# Terminal 1: Start Backend
cd src/dashboard/backend
uvicorn main:app --reload --port 8000

# Terminal 2: Start Frontend
cd src/dashboard/frontend
npm run dev
```

Then open your browser to `http://localhost:3000`.

### Example Workflow

A typical red team engagement workflow:

```bash
# Step 1: External Recon (no credentials needed)
cloud-asf recon full --domain target.com --output recon.json

# Step 2: Cloud Discovery (with credentials)
cloud-asf scan --providers aws --output cloud_assets.json

# Step 3: Generate Report
cloud-asf report --input cloud_assets.json --output report.html --format html
```

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `cloud-asf recon full` | Full external reconnaissance |
| `cloud-asf recon dns` | DNS enumeration only |
| `cloud-asf recon ports` | Port scanning only |
| `cloud-asf scan` | Cloud asset discovery and scanning |
| `cloud-asf storage enumerate` | Bucket permutation discovery |
| `cloud-asf storage check` | Check specific bucket permissions |
| `cloud-asf secrets scan` | Credential leak detection |
| `cloud-asf report` | Generate HTML/JSON report |
| `cloud-asf dashboard` | Launch web dashboard |

### Common Options

| Option | Description |
|--------|-------------|
| `--domain` | Target domain for external recon |
| `--providers` | Cloud providers to scan (aws, azure, gcp) |
| `--mode` | Scan intensity (fast, normal, deep, stealth) |
| `--output` | Output file path |
| `--format` | Output format (json, html, csv) |
| `--timeout` | Connection timeout in milliseconds |
| `--concurrency` | Number of concurrent workers |

---

## Project Structure

```
cloud-attack-surface-detector/
├── src/
│   ├── python/orchestrator/     # Python CLI and cloud logic
│   │   ├── main.py              # Typer CLI entry point
│   │   ├── cloud_providers/     # AWS, Azure, GCP modules
│   │   ├── analysis/            # Attack path, IAM, secrets analysis
│   │   └── reporting/           # HTML/JSON report generation
│   ├── go/skyscan/              # High-performance Go scanner
│   │   ├── cmd/skyscan/         # Binary entry point
│   │   └── pkg/                  # Core scanning packages
│   └── dashboard/               # Next.js web interface
│       ├── backend/             # FastAPI backend
│       └── frontend/            # React frontend
├── tests/                       # Unit and integration tests
├── reports/                     # Generated scan reports
├── .env.example                 # Configuration template
├── LICENSE                      # MIT License
└── README.md                    # This file
```

---

## Security Considerations

> **Warning:** This tool is designed for authorized security testing only.

- Always obtain written permission before scanning
- Cloud providers may flag scanning activity
- Some scans may trigger WAF or IDS alerts
- Never store credentials in version control

---

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Made with security in mind**

</div>
