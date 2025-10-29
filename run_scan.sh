#!/bin/bash

# GCP Reconnaissance Tool - Quick Scan Script
# Usage: ./run_scan.sh <project-id>

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if project ID is provided
if [ -z "$1" ]; then
    echo -e "${RED}Error: Project ID is required${NC}"
    echo "Usage: ./run_scan.sh <project-id> [credentials-path]"
    exit 1
fi

PROJECT_ID=$1
CREDENTIALS_PATH=${2:-""}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="scan_${PROJECT_ID}_${TIMESTAMP}.json"

echo -e "${GREEN}=== GCP Reconnaissance Tool ===${NC}"
echo -e "Project: ${YELLOW}$PROJECT_ID${NC}"
echo -e "Timestamp: ${YELLOW}$TIMESTAMP${NC}"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    exit 1
fi

# Check if dependencies are installed
if ! python3 -c "import google.cloud.compute_v1" 2>/dev/null; then
    echo -e "${YELLOW}Installing dependencies...${NC}"
    pip install -r requirements.txt
fi

# Build command
CMD="python3 gcp_recon.py --project $PROJECT_ID --output $OUTPUT_FILE --verbose"

if [ -n "$CREDENTIALS_PATH" ]; then
    CMD="$CMD --credentials $CREDENTIALS_PATH"
fi

# Run the scan
echo -e "${GREEN}Starting scan...${NC}"
echo ""

eval $CMD

# Check if scan was successful
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}=== Scan Complete ===${NC}"
    echo -e "Results saved to: ${YELLOW}$OUTPUT_FILE${NC}"
    echo ""
    echo "To view the JSON results:"
    echo "  cat $OUTPUT_FILE | python3 -m json.tool"
else
    echo -e "${RED}Scan failed. Check the logs above for errors.${NC}"
    exit 1
fi
