#!/bin/bash
# Reckon Enhanced - Tool Installation Script
# Installs all required and optional tools for Reckon v2.0+

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}"
echo "╔════════════════════════════════════════╗"
echo "║  Reckon v2.0 - Tool Installation      ║"
echo "║  Enhanced Pentesting Framework         ║"
echo "╚════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run as root${NC}"
   echo "Run: sudo bash install-tools.sh"
   exit 1
fi

echo -e "${YELLOW}[*]${NC} Updating package lists..."
apt-get update -qq

# Required tools
echo -e "${YELLOW}[*]${NC} Installing required tools..."
apt-get install -y -qq \
    nmap \
    curl \
    wget \
    dnsutils \
    whois \
    2>/dev/null || true

# Web scanning
echo -e "${YELLOW}[*]${NC} Installing web scanning tools..."
apt-get install -y -qq \
    nikto \
    dirb \
    2>/dev/null || true

# Service enumeration
echo -e "${YELLOW}[*]${NC} Installing service enumeration tools..."
apt-get install -y -qq \
    enum4linux \
    smbclient \
    2>/dev/null || true

# SQL injection testing
echo -e "${YELLOW}[*]${NC} Installing SQL injection testing..."
apt-get install -y -qq sqlmap 2>/dev/null || true

# SSL/TLS testing
echo -e "${YELLOW}[*]${NC} Installing SSL/TLS testing tools..."
apt-get install -y -qq openssl 2>/dev/null || true

# testssl.sh (REQUIRED)
echo -e "${YELLOW}[*]${NC} Installing testssl.sh (required)..."
if ! command -v testssl.sh &> /dev/null; then
    cd /opt 2>/dev/null || mkdir -p /opt
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git 2>/dev/null || true
    ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh 2>/dev/null || true
    chmod +x /opt/testssl.sh/testssl.sh 2>/dev/null || true
fi

# Python tools
echo -e "${YELLOW}[*]${NC} Installing Python-based tools..."
apt-get install -y -qq python3 python3-pip 2>/dev/null || true
pip3 install -q python-docx 2>/dev/null || true

# Nuclei (if Go is available)
if command -v go &> /dev/null; then
    echo -e "${YELLOW}[*]${NC} Installing Nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest 2>/dev/null || true
    
    echo -e "${YELLOW}[*]${NC} Installing ffuf..."
    go install -v github.com/ffuf/ffuf@latest 2>/dev/null || true
else
    echo -e "${YELLOW}[-]${NC} Go not found - skipping Nuclei and ffuf installation"
fi

echo ""
echo -e "${GREEN}✓ Installation complete!${NC}"
echo ""
echo -e "${YELLOW}[*]${NC} Installed tools summary:"
echo ""

tools_installed=0

if command -v nmap &> /dev/null; then
    echo -e "${GREEN}✓${NC} nmap $(nmap -V 2>&1 | head -1)"
    ((tools_installed++))
fi

if command -v nikto &> /dev/null; then
    echo -e "${GREEN}✓${NC} nikto"
    ((tools_installed++))
fi

if command -v dirb &> /dev/null; then
    echo -e "${GREEN}✓${NC} dirb"
    ((tools_installed++))
fi

if command -v enum4linux &> /dev/null; then
    echo -e "${GREEN}✓${NC} enum4linux"
    ((tools_installed++))
fi

if command -v sqlmap &> /dev/null; then
    echo -e "${GREEN}✓${NC} sqlmap"
    ((tools_installed++))
fi

if command -v testssl.sh &> /dev/null; then
    echo -e "${GREEN}✓${NC} testssl.sh"
    ((tools_installed++))
fi

if command -v nuclei &> /dev/null; then
    echo -e "${GREEN}✓${NC} nuclei"
    ((tools_installed++))
fi

if command -v ffuf &> /dev/null; then
    echo -e "${GREEN}✓${NC} ffuf"
    ((tools_installed++))
fi

echo ""
echo -e "${YELLOW}[*]${NC} Reckon is ready to use!"
echo "Usage: ./reckon.sh <target>"
echo ""
