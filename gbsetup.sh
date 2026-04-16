#!/bin/bash
# GateBell — by Kotech Petacomm
# One-line installer

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

echo ""
echo -e "${BOLD}  Kotech Petacomm — GateBell Installer${RESET}"
echo -e "  ${DIM}Setting up the GateBell APT repository...${RESET}"
echo ""

# Root check
if [ "$EUID" -ne 0 ]; then
    echo -e "  ${YELLOW}Please run with sudo:${RESET}"
    echo -e "  ${CYAN}curl -fsSL https://repo.kotechsoft.com/install.sh | sudo bash${RESET}"
    echo ""
    exit 1
fi

# Dependencies
apt-get install -y -qq curl gnupg apt-transport-https

# GPG key
echo -e "  ${DIM}→ Adding Kotech Petacomm GPG key...${RESET}"
curl -fsSL https://repo.kotechsoft.com/kotech-petacomm.gpg | \
    gpg --dearmor -o /usr/share/keyrings/kotech-petacomm.gpg

# APT source
echo -e "  ${DIM}→ Adding GateBell repository...${RESET}"
echo "deb [signed-by=/usr/share/keyrings/kotech-petacomm.gpg] https://repo.kotechsoft.com stable main" \
    > /etc/apt/sources.list.d/gatebell.list

# Install
echo -e "  ${DIM}→ Installing GateBell...${RESET}"
apt-get update -qq
apt-get install -y gatebell

echo ""
echo -e "  ${GREEN}${BOLD}GateBell installed successfully! 🔔${RESET}"
echo -e "  ${DIM}Run the setup wizard:${RESET} ${CYAN}${BOLD}sudo gatebell-setup${RESET}"
echo ""
