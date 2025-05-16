#!/bin/bash
# Network Security Automation Tool Error Reset and Fix Script
# Author: Joel Aaron Guff

# Text colors for better readability
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}┌───────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│        NETWORK SECURITY AUTOMATION        │${NC}"
echo -e "${BLUE}│            ERROR RESET & FIX              │${NC}"
echo -e "${BLUE}└───────────────────────────────────────────┘${NC}"
echo ""

# Check if Python is available
if ! command -v python &> /dev/null; then
    echo -e "${RED}Error: Python is not installed or not in PATH${NC}"
    exit 1
fi

# Kill any running Python processes
echo -e "${YELLOW}Stopping any running Python processes...${NC}"
pkill -f python || true
echo -e "${GREEN}✓ Stopped running processes${NC}"

# Remove database file
echo -e "${YELLOW}Removing existing database...${NC}"
rm -f instance/netsec.db
echo -e "${GREEN}✓ Database removed${NC}"

# Run the database rebuild script to create fresh tables and users
echo -e "${YELLOW}Rebuilding database with compatible password hashing...${NC}"
python rebuild_database.py
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to rebuild database${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Database rebuilt successfully${NC}"

echo ""
echo -e "${GREEN}All fixes have been applied successfully!${NC}"
echo -e "You can now start the application with ${BLUE}./start_demo.sh${NC}"
echo ""
echo -e "${BLUE}Login credentials:${NC}"
echo -e "  Username: ${GREEN}demo${NC}"
echo -e "  Password: ${GREEN}demo123${NC}"