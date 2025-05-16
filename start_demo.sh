#!/bin/bash
# Single-click demo script for Network Security Automation Tool
# Author: Joel Aaron Guff

# Text colors for better readability
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}┌───────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│        NETWORK SECURITY AUTOMATION        │${NC}"
echo -e "${BLUE}│              DEMO LAUNCHER                │${NC}"
echo -e "${BLUE}└───────────────────────────────────────────┘${NC}"
echo ""

# Stop any running Python processes
echo -e "${YELLOW}Stopping any existing processes...${NC}"
pkill -f python || true
echo -e "${GREEN}✓ Environment ready${NC}"

# Reset the database
echo -e "${YELLOW}Setting up fresh demo environment...${NC}"
python rebuild_database.py
echo -e "${GREEN}✓ Database rebuilt successfully${NC}"

# Print demo information
echo ""
echo -e "${BLUE}┌───────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│               DEMO SUMMARY                │${NC}"
echo -e "${BLUE}└───────────────────────────────────────────┘${NC}"
echo ""
echo -e "Login Credentials:"
echo -e "  ${GREEN}Username:${NC} demo"
echo -e "  ${GREEN}Password:${NC} demo123"
echo ""
echo -e "Demo Environment Contains:"
echo -e "  ${GREEN}•${NC} 5 Network Devices (Router, Firewall, Switches, Server)"
echo -e "  ${GREEN}•${NC} Network Topology Connections"
echo -e "  ${GREEN}•${NC} Security Audit Reports"
echo -e "  ${GREEN}•${NC} Configuration Backups"
echo -e "  ${GREEN}•${NC} Ping Telemetry Data"
echo ""
echo -e "Key Features:"
echo -e "  ${GREEN}•${NC} Device Management & Connectivity"
echo -e "  ${GREEN}•${NC} Security Audit & Compliance Checks"
echo -e "  ${GREEN}•${NC} Configuration Backup & Comparison"
echo -e "  ${GREEN}•${NC} Real-time Monitoring & Telemetry"
echo -e "  ${GREEN}•${NC} Interactive Network Topology"
echo -e "  ${GREEN}•${NC} AI-powered Configuration Wizard"
echo ""
echo -e "${YELLOW}Starting the application...${NC}"
echo -e "The web interface will be available at: ${GREEN}http://localhost:8080${NC}"
echo -e "Press ${RED}Ctrl+C${NC} to stop the server"
echo ""

# Start the application
python main.py