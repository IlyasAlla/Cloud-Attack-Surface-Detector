#!/bin/bash

#===============================================================================
#  Cloud Attack Surface Detector - Installation Script
#  
#  This script automates the complete installation of CASD including:
#  - Python virtual environment and dependencies
#  - Go scanner binary compilation
#  - Node.js dashboard dependencies
#  - Environment configuration
#
#  Usage: ./install.sh [options]
#  Options:
#    --skip-dashboard    Skip Node.js dashboard installation
#    --skip-go           Skip Go scanner compilation
#    --help              Show this help message
#===============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
INSTALL_DASHBOARD=true
INSTALL_GO=true

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-dashboard)
            INSTALL_DASHBOARD=false
            shift
            ;;
        --skip-go)
            INSTALL_GO=false
            shift
            ;;
        --help)
            echo "Usage: ./install.sh [options]"
            echo ""
            echo "Options:"
            echo "  --skip-dashboard    Skip Node.js dashboard installation"
            echo "  --skip-go           Skip Go scanner compilation"
            echo "  --help              Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║       Cloud Attack Surface Detector - Installation Script         ║"
echo "║                         Version 2.0.0                             ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

#-------------------------------------------------------------------------------
# Check Prerequisites
#-------------------------------------------------------------------------------
echo -e "${YELLOW}[1/6] Checking prerequisites...${NC}"

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "  ${GREEN}✓${NC} Python $PYTHON_VERSION found"
else
    echo -e "  ${RED}✗${NC} Python 3 not found. Please install Python 3.11+"
    exit 1
fi

# Check pip
if command -v pip3 &> /dev/null || command -v pip &> /dev/null; then
    echo -e "  ${GREEN}✓${NC} pip found"
else
    echo -e "  ${RED}✗${NC} pip not found. Please install pip"
    exit 1
fi

# Check Go (optional)
if [ "$INSTALL_GO" = true ]; then
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version 2>&1 | awk '{print $3}')
        echo -e "  ${GREEN}✓${NC} $GO_VERSION found"
    else
        echo -e "  ${YELLOW}!${NC} Go not found. Skipping Go scanner build."
        echo -e "      Install Go 1.21+ from https://golang.org/dl/"
        INSTALL_GO=false
    fi
fi

# Check Node.js (optional)
if [ "$INSTALL_DASHBOARD" = true ]; then
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node --version 2>&1)
        echo -e "  ${GREEN}✓${NC} Node.js $NODE_VERSION found"
    else
        echo -e "  ${YELLOW}!${NC} Node.js not found. Skipping dashboard installation."
        echo -e "      Install Node.js 18+ from https://nodejs.org/"
        INSTALL_DASHBOARD=false
    fi
fi

# Check npm (optional)
if [ "$INSTALL_DASHBOARD" = true ]; then
    if command -v npm &> /dev/null; then
        NPM_VERSION=$(npm --version 2>&1)
        echo -e "  ${GREEN}✓${NC} npm $NPM_VERSION found"
    else
        echo -e "  ${YELLOW}!${NC} npm not found. Skipping dashboard installation."
        INSTALL_DASHBOARD=false
    fi
fi

#-------------------------------------------------------------------------------
# Create Python Virtual Environment
#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[2/6] Setting up Python virtual environment...${NC}"

if [ -d ".venv" ]; then
    echo -e "  ${GREEN}✓${NC} Virtual environment already exists"
else
    python3 -m venv .venv
    echo -e "  ${GREEN}✓${NC} Virtual environment created"
fi

# Activate virtual environment
source .venv/bin/activate
echo -e "  ${GREEN}✓${NC} Virtual environment activated"

#-------------------------------------------------------------------------------
# Install Python Dependencies
#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[3/6] Installing Python dependencies...${NC}"

# Upgrade pip first
pip install --upgrade pip --quiet

# Install from requirements.txt
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt --quiet
    echo -e "  ${GREEN}✓${NC} Installed dependencies from requirements.txt"
elif [ -f "src/python/requirements.txt" ]; then
    pip install -r src/python/requirements.txt --quiet
    echo -e "  ${GREEN}✓${NC} Installed dependencies from src/python/requirements.txt"
else
    echo -e "  ${YELLOW}!${NC} No requirements.txt found, installing core packages..."
    pip install boto3 azure-identity azure-mgmt-network google-cloud-asset \
                typer rich pydantic fastapi uvicorn jinja2 --quiet
    echo -e "  ${GREEN}✓${NC} Core packages installed"
fi

#-------------------------------------------------------------------------------
# Build Go Scanner
#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[4/6] Building Go scanner...${NC}"

if [ "$INSTALL_GO" = true ]; then
    # Create bin directory if it doesn't exist
    mkdir -p bin
    
    if [ -d "src/go/skyscan" ]; then
        cd src/go/skyscan
        go build -o ../../../bin/skyscan ./cmd/skyscan 2>/dev/null || \
        go build -o ../../../bin/skyscan . 2>/dev/null || \
        echo -e "  ${YELLOW}!${NC} Go build failed, but continuing..."
        cd ../../..
        
        if [ -f "bin/skyscan" ]; then
            chmod +x bin/skyscan
            echo -e "  ${GREEN}✓${NC} Go scanner built: bin/skyscan"
        else
            echo -e "  ${YELLOW}!${NC} Scanner binary not created"
        fi
    else
        echo -e "  ${YELLOW}!${NC} Go source directory not found"
    fi
else
    echo -e "  ${YELLOW}○${NC} Skipped (--skip-go or Go not installed)"
fi

#-------------------------------------------------------------------------------
# Install Dashboard Dependencies
#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[5/6] Installing dashboard dependencies...${NC}"

if [ "$INSTALL_DASHBOARD" = true ]; then
    if [ -d "src/dashboard/frontend" ]; then
        cd src/dashboard/frontend
        npm install --silent 2>/dev/null || npm install
        cd ../../..
        echo -e "  ${GREEN}✓${NC} Dashboard dependencies installed"
    else
        echo -e "  ${YELLOW}!${NC} Dashboard directory not found"
    fi
else
    echo -e "  ${YELLOW}○${NC} Skipped (--skip-dashboard or Node.js not installed)"
fi

#-------------------------------------------------------------------------------
# Setup Environment Configuration
#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[6/6] Setting up configuration...${NC}"

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "  ${GREEN}✓${NC} Created .env from .env.example"
        echo -e "  ${YELLOW}!${NC} Please edit .env with your cloud credentials"
    else
        # Create a basic .env file
        cat > .env << 'EOF'
# AWS Credentials
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1

# Azure Credentials (Optional)
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
AZURE_TENANT_ID=
AZURE_SUBSCRIPTION_ID=

# GCP Credentials (Optional)
GOOGLE_APPLICATION_CREDENTIALS=

# AI Features (Optional)
GEMINI_API_KEY=
EOF
        echo -e "  ${GREEN}✓${NC} Created default .env file"
        echo -e "  ${YELLOW}!${NC} Please edit .env with your cloud credentials"
    fi
else
    echo -e "  ${GREEN}✓${NC} .env file already exists"
fi

#-------------------------------------------------------------------------------
# Installation Complete
#-------------------------------------------------------------------------------
echo ""
echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                    Installation Complete!                         ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BLUE}Next Steps:${NC}"
echo ""
echo "  1. Configure your cloud credentials:"
echo -e "     ${YELLOW}nano .env${NC}"
echo ""
echo "  2. Activate the virtual environment:"
echo -e "     ${YELLOW}source .venv/bin/activate${NC}"
echo ""
echo "  3. Run your first scan:"
echo -e "     ${YELLOW}./cloud-asf recon full --domain example.com${NC}"
echo ""
echo "  4. (Optional) Start the dashboard:"
echo -e "     ${YELLOW}./start_dashboard.sh${NC}"
echo ""
echo -e "${BLUE}Documentation:${NC} See README.md for full usage guide"
echo ""
