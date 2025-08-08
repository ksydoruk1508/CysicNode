#!/bin/bash

# ===== Colors =====
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'
PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'
set -Eeuo pipefail

# ===== Paths =====
EVM_FILE="/root/.cysic_evm"
CLAIMER_PY="/root/cysic_claimer.py"
CLAIMER_LOG="/var/log/cysic_claimer.log"
CLAIMER_PID="/var/run/cysic_claimer.pid"

# ===== Base deps (без whiptail) =====
function ensure_base_packages {
  echo -e "${BLUE}Installing dependencies...${NC}"
  sudo apt-get update -y && sudo apt-get upgrade -y
  sudo apt-get install -y make screen build-essential unzip lz4 gcc git jq \
      python3 python3-pip figlet curl
}

# ===== Install gum (TUI arrows) =====
function ensure_gum {
  if command -v gum >/dev/null 2>&1; then return 0; fi
  echo -e "${BLUE}Installing gum (for arrow-key menu)...${NC}"
  GUM_VER="0.14.1"

  # Detect arch
  ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
  case "$ARCH" in
    amd64|x86_64)  DEB_ARCH="x86_64";  TAR_ARCH="x86_64";;
    arm64|aarch64) DEB_ARCH="arm64";   TAR_ARCH="arm64";;
    armhf|arm)     DEB_ARCH="armv7";   TAR_ARCH="armv7";;
    *)             DEB_ARCH="x86_64";  TAR_ARCH="x86_64";;
  esac

  TMP_DIR="$(mktemp -d)"
  DEB="$TMP_DIR/gum_${GUM_VER}_Linux_${DEB_ARCH}.deb"
  TAR="$TMP_DIR/gum_${GUM_VER}_Linux_${TAR_ARCH}.tar.gz"

  # Try .deb
  if curl -fsSL -o "$DEB" "https://github.com/charmbracelet/gum/releases/download/v${GUM_VER}/gum_${GUM_VER}_Linux_${DEB_ARCH}.deb"; then
    sudo dpkg -i "$DEB" >/dev/null 2>&1 || true
  fi

  # Fallback tar.gz
  if ! command -v gum >/dev/null 2>&1; then
    if curl -fsSL -o "$TAR" "https://github.com/charmbracelet/gum/releases/download/v${GUM_VER}/gum_${GUM_VER}_Linux_${TAR_ARCH}.tar.gz"; then
      tar -xzf "$TAR" -C "$TMP_DIR" >/dev/null 2>&1 || true
      [ -f "$TMP_DIR/gum" ] && sudo install -m 0755 "$TMP_DIR/gum" /usr/local/bin/gum || true
    fi
  fi

  rm -rf "$TMP_DIR" || true
}

function ensure_python_libs {
  echo -e "${BLUE}Installing Python libs (requests, web3, eth-account)...${NC}"
  python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
  python3 -m pip install requests web3 eth-account >/dev/null 2>&1
}

# ===== Banner =====
function show_banner {
  clear
  if command -v figlet >/dev/null 2>&1; then
    echo -e "${CYAN}"
    figlet -w 120 "CYSIC VERIFIER" || figlet "CYSIC VERIFIER"
    echo -e "${NC}"
  else
    echo -e "${CYAN}CYSIC VERIFIER${NC}"
  fi
  echo -e "💙 ${CYAN}My channel for latest updates:${NC} https://t.me/c6zr7"
  echo
}

# ===== Node: install =====
function install_node {
  ensure_base_packages
  echo -e "${YELLOW}Введите адрес привязанного EVM-кошелька / Enter your linked EVM address:${NC}"
  read EVM_WALLET
  if [ -z "$EVM_WALLET" ]; then echo -e "${RED}EVM address cannot be empty.${NC}"; return; fi
  echo "$EVM_WALLET" | sudo tee "$EVM_FILE" >/dev/null

  echo -e "${BLUE}Downloading & running Cysic setup...${NC}"
  curl -L --fail https://github.com/cysic-labs/phase2_libs/releases/download/v1.0.0/setup_linux.sh > ~/setup_linux.sh
  chmod +x ~/setup_linux.sh
  bash ~/setup_linux.sh "$EVM_WALLET"

  echo -e "${BLUE}Creating systemd service...${NC}"
  sudo tee /etc/systemd/system/cysic.service > /dev/null <<EOF
[Unit]
Description=Cysic Verifier
Wants=network-online.target
After=network-online.target

[Service]
User=$USER
WorkingDirectory=/root/cysic-verifier
ExecStart=/bin/bash /root/cysic-verifier/start.sh
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

  echo -e "${BLUE}Enabling & starting service...${NC}"
  sudo systemctl daemon-reload
  sudo systemctl enable cysic
  sudo systemctl start cysic
  echo -e "${GREEN}Installation complete!${NC}"
  echo -e "${YELLOW}Logs:${NC} ${CYAN}sudo journalctl -u cysic -f --no-hostname -o cat${NC}"
}

# ===== Node: update =====
function update_node {
  if [ -f "$EVM_FILE" ]; then EVM_WALLET=$(cat "$EVM_FILE"); else
    echo -e "${YELLOW}Введите адрес EVM-кошелька / Enter EVM address:${NC}"
    read EVM_WALLET
    [ -z "$EVM_WALLET" ] && { echo -e "${RED}EVM address cannot be empty.${NC}"; return; }
    echo "$EVM_WALLET" | sudo tee "$EVM_FILE" >/dev/null
  fi
  echo -e "${BLUE}Updating Cysic node...${NC}"
  curl -L --fail https://github.com/cysic-labs/phase2_libs/releases/download/v1.0.0/setup_linux.sh > ~/setup_linux.sh
  chmod +x ~/setup_linux.sh
  bash ~/setup_linux.sh "$EVM_WALLET"
  echo -e "${BLUE}Restarting service...${NC}"
  sudo systemctl restart cysic
  echo -e "${GREEN}Node restarted.${NC}"
}

# ===== Node: control =====
function restart_node { echo -e "${BLUE}Restarting node...${NC}"; sudo systemctl restart cysic; echo -e "${GREEN}Done.${NC}"; }
function stop_node    { echo -e "${BLUE}Stopping node...${NC}";  sudo systemctl stop cysic;     echo -e "${GREEN}Done.${NC}"; }
function view_logs    { echo -e "${YELLOW}Follow logs (CTRL+C to exit):${NC}"; sudo journalctl -u cysic -f --no-hostname -o cat; }

function remove_node {
  echo -e "${RED}This will completely remove the node. Continue? (y/n)${NC}"
  read confirm
  if [ "$confirm" = "y" ]; then
    sudo systemctl stop cysic || true
    sudo systemctl disable cysic || true
    rm -rf /root/cysic-verifier
    sudo rm -f /etc/systemd/system/cysic.service
    sudo systemctl daemon-reload
    sudo systemctl reset-failed || true
    echo -e "${GREEN}Node removed.${NC}"
  else
    echo -e "${YELLOW}Operation cancelled.${NC}"
  fi
}

function other_nodes {
  echo -e "${BLUE}Opening other nodes installer...${NC}"
  wget -q -O Ultimative_Node_Installer.sh https://raw.githubusercontent.com/ksydoruk1508/Ultimative_Node_Installer/main/Ultimative_Node_Installer.sh \
    && sudo chmod +x Ultimative_Node_Installer.sh && ./Ultimative_Node_Installer.sh
}

# ===== Claimer Python =====
function write_claimer_py {
sudo tee "$CLAIMER_PY" >/dev/null <<'PYEOF'
import argparse, requests, time, random, sys
from web3 import Web3
from eth_account.messages import encode_defunct
from datetime import datetime

BASE_URL = "https://api-pre.prover.xyz"
def now(): return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def validate_private_key(pk: str) -> bool:
    if not pk: return False
    pk = pk.strip()
    if pk.startswith('0x'): pk = pk[2:]
    if len(pk) != 64: return False
    try: int(pk, 16); return True
    except ValueError: return False

class CysicClaimer:
    def __init__(self, private_key: str, invite_code: str):
        self.private_key = private_key.strip()
              

