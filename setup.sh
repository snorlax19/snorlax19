#!/bin/bash

# GCP Recon Tool Setup Script

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== GCP Reconnaissance Tool Setup ===${NC}\n"

# Check Python version
echo -e "${YELLOW}Checking Python version...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "Python version: ${GREEN}$PYTHON_VERSION${NC}"
else
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    exit 1
fi

# Check pip
echo -e "\n${YELLOW}Checking pip...${NC}"
if command -v pip3 &> /dev/null; then
    echo -e "pip is installed: ${GREEN}✓${NC}"
else
    echo -e "${RED}Error: pip is not installed${NC}"
    exit 1
fi

# Create virtual environment (optional but recommended)
echo -e "\n${YELLOW}Would you like to create a virtual environment? (recommended) [y/N]${NC}"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv
    echo -e "${GREEN}Virtual environment created${NC}"
    echo -e "${YELLOW}To activate it, run: source venv/bin/activate${NC}"

    # Activate virtual environment
    source venv/bin/activate
fi

# Install dependencies
echo -e "\n${YELLOW}Installing dependencies...${NC}"
pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Dependencies installed successfully!${NC}"
else
    echo -e "${RED}Error installing dependencies${NC}"
    exit 1
fi

# Check for gcloud
echo -e "\n${YELLOW}Checking for gcloud CLI...${NC}"
if command -v gcloud &> /dev/null; then
    GCLOUD_VERSION=$(gcloud version --format="value(core.version)")
    echo -e "gcloud CLI version: ${GREEN}$GCLOUD_VERSION${NC}"

    echo -e "\n${YELLOW}Would you like to authenticate with gcloud now? [y/N]${NC}"
    read -r auth_response
    if [[ "$auth_response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        gcloud auth application-default login
    fi
else
    echo -e "${YELLOW}gcloud CLI is not installed${NC}"
    echo -e "Install it from: https://cloud.google.com/sdk/docs/install"
    echo -e "Or use service account credentials with the --credentials flag"
fi

echo -e "\n${GREEN}=== Setup Complete ===${NC}\n"
echo -e "Next steps:"
echo -e "1. Authenticate with GCP (if not already done):"
echo -e "   ${YELLOW}gcloud auth application-default login${NC}"
echo -e "\n2. Run a scan:"
echo -e "   ${YELLOW}python3 gcp_recon.py --project YOUR-PROJECT-ID${NC}"
echo -e "\n3. Or use the quick scan script:"
echo -e "   ${YELLOW}./run_scan.sh YOUR-PROJECT-ID${NC}"
echo -e "\nFor more information, see README.md"
