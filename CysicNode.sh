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

# ===== Ensure base deps =====
function ensure_base_packages {
  echo -e "${BLUE}Installing dependencies...${NC}"
  sudo apt-get update -y && sudo apt-get upgrade -y
  sudo apt-get install -y make screen build-essential unzip lz4 gcc git jq \
      python3 python3-pip whiptail figlet curl
}

# ===== Try to install gum (arrow-key TUI) =====
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

  # Try deb first
  if curl -fsSL -o "$DEB" "https://github.com/charmbracelet/gum/releases/download/v${GUM_VER}/gum_${GUM_VER}_Linux_${DEB_ARCH}.deb"; then
    sudo dpkg -i "$DEB" >/dev/null 2>&1 || true
  fi

  # Fallback to tar.gz if gum still not available
  if ! command -v gum >/dev/null 2>&1; then
    if curl -fsSL -o "$TAR" "https://github.com/charmbracelet/gum/releases/download/v${GUM_VER}/gum_${GUM_VER}_Linux_${TAR_ARCH}.tar.gz"; then
      tar -xzf "$TAR" -C "$TMP_DIR" >/dev/null 2>&1 || true
      if [ -f "$TMP_DIR/gum" ]; then
        sudo install -m 0755 "$TMP_DIR/gum" /usr/local/bin/gum || true
      fi
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

# ===== Claimer Python writer =====
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
        self.invite_code = invite_code.strip()
        self.w3 = Web3()
        try:
            self.account = self.w3.eth.account.from_key(self.private_key)
            self.wallet_address = self.account.address
        except Exception as e:
            raise ValueError(f"Invalid private key: {e}")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Content-Type': 'application/json',
            'Origin': 'https://app.cysic.xyz',
            'Referer': 'https://app.cysic.xyz/',
        })

    def sign_message(self, message: str) -> str:
        msg = encode_defunct(text=message)
        signed = self.account.sign_message(msg)
        return signed.signature.hex()

    def bind_invite_code(self) -> bool:
        try:
            url = f"{BASE_URL}/api/v1/user/updateProfile"
            message = f"Welcome to Cysic! Invite Code: {self.invite_code}"
            headers = {
                "Content-Type": "application/json",
                "X-Cysic-Address": self.wallet_address,
                "X-Cysic-Sign": self.sign_message(message)
            }
            r = self.session.post(url, headers=headers, json={"inviteCode": self.invite_code})
            print(f"[{now()}] Bind invite code status: {r.status_code}")
            if r.status_code == 200:
                print(f"[{now()}] Response: {r.json()}")
                return True
            print(f"[{now()}] Error: {r.text}")
            return False
        except Exception as e:
            print(f"[{now()}] Invite code bind error: {e}")
            return False

    def claim_tokens(self) -> bool:
        try:
            headers = {"X-Cysic-Address": self.wallet_address, "X-Cysic-Sign": self.sign_message("Welcome to Cysic!")}
            r = self.session.get(f"{BASE_URL}/api/v1/user/faucet", headers=headers)
            print(f"[{now()}] Claim status: {r.status_code}")
            try:
                data = r.json(); print(f"[{now()}] Response: {data}"); code = data.get("code")
            except Exception:
                print(f"[{now()}] Non-JSON response: {r.text}"); code = None
            if code in (0, 10099):  # success or already/time-limited
                print(f"[{now()}] ✅ OK"); return True
            if code == 10199:
                print(f"[{now()}] ❌ Authorization required"); return False
            print(f"[{now()}] ℹ️  Other code: {data}")
            return True
        except Exception as e:
            print(f"[{now()}] Claim error: {e}")
            return False

    def run_cycle(self) -> bool:
        print("="*70); print(f"[{now()}] Start cycle for wallet: {self.wallet_address}"); print("-"*70)
        print(f"[{now()}] Binding invite code: {self.invite_code}")
        if not self.bind_invite_code(): print(f"[{now()}] ❌ Bind failed"); return False
        print(f"[{now()}] ✅ Invite bound")
        print(f"[{now()}] Claiming test tokens...")
        ok = self.claim_tokens()
        print(f"[{now()}] {'✅ Success' if ok else '❌ Failed'}")
        return ok

def main():
    p = argparse.ArgumentParser(description="Cysic test token claimer (0.1/24h)")
    p.add_argument("--pk", required=True, help="Private key")
    p.add_argument("--invite", required=True, help="Invite code")
    a = p.parse_args()
    if not validate_private_key(a.pk): print("Invalid private key format"); sys.exit(1)
    c = CysicClaimer(a.pk, a.invite)
    while True:
        try:
            c.run_cycle()
            m = random.randint(1441, 1445); s = m*60
            print(f"\n⏰ Next cycle in {m} minutes ({s} seconds)")
            print(f"[{now()}] Next at: {datetime.fromtimestamp(time.time()+s).strftime('%Y-%m-%d %H:%M:%S')}")
            print("="*70)
            time.sleep(s)
        except KeyboardInterrupt:
            print(f"\n[{now()}] Interrupted"); break
        except Exception as e:
            print(f"[{now()}] Unhandled: {e}"); time.sleep(30)

if __name__ == "__main__": main()
PYEOF
}

# ===== Claimer control =====
function start_claimer {
  ensure_base_packages; ensure_python_libs; write_claimer_py
  echo -e "${YELLOW}Введите приватный ключ вашего кошелька Cysic:${NC}"; read -r PRIVATE_KEY
  echo -e "${YELLOW}Введите invite code от Cysic:${NC}"; read -r INVITE_CODE
  if [ -z "$PRIVATE_KEY" ] || [ -z "$INVITE_CODE" ]; then
    echo -e "${RED}Private key and invite code are required.${NC}"; return
  fi
  sudo touch "$CLAIMER_LOG"; sudo chmod 644 "$CLAIMER_LOG"

  if command -v screen >/dev/null 2>&1; then
    screen -S cysic-claimer -X quit >/dev/null 2>&1 || true
    screen -S cysic-claimer -dm bash -lc "python3 '$CLAIMER_PY' --pk '$PRIVATE_KEY' --invite '$INVITE_CODE' >> '$CLAIMER_LOG' 2>&1"
    sudo rm -f "$CLAIMER_PID" 2>/dev/null || true
    echo -e "${GREEN}Claimer started in screen (logs: $CLAIMER_LOG).${NC}"
    echo -e "${YELLOW}Attach: screen -r cysic-claimer  (detach: Ctrl+A, D)${NC}"
  else
    nohup python3 "$CLAIMER_PY" --pk "$PRIVATE_KEY" --invite "$INVITE_CODE" >> "$CLAIMER_LOG" 2>&1 &
    echo $! | sudo tee "$CLAIMER_PID" >/dev/null
    echo -e "${GREEN}Claimer started with nohup (PID $(cat $CLAIMER_PID)). Logs: $CLAIMER_LOG${NC}"
  fi
}

function claimer_logs {
  echo -e "${YELLOW}Claimer logs (CTRL+C to exit):${NC}"
  [ -f "$CLAIMER_LOG" ] && tail -n 200 -f "$CLAIMER_LOG" || echo -e "${RED}No log file: $CLAIMER_LOG${NC}"
}

function stop_claimer {
  echo -e "${BLUE}Stopping claimer...${NC}"
  if screen -list 2>/dev/null | grep -q "cysic-claimer"; then
    screen -S cysic-claimer -X quit || true
    echo -e "${GREEN}Screen session stopped.${NC}"
  fi
  if [ -f "$CLAIMER_PID" ]; then
    PID=$(cat "$CLAIMER_PID" || true)
    if [ -n "${PID:-}" ] && ps -p "$PID" >/dev/null 2>&1; then
      kill "$PID" || true; sleep 1
      ps -p "$PID" >/dev/null 2>&1 && kill -9 "$PID" || true
      echo -e "${GREEN}Process $PID stopped.${NC}"
    fi
    sudo rm -f "$CLAIMER_PID" 2>/dev/null || true
  fi
  pkill -f "$CLAIMER_PY" >/dev/null 2>&1 || true
  echo -e "${GREEN}Done.${NC}"
}

# ===== Menus =====
function menu_gum {
  show_banner
  export GUM_CHOOSE_HEADER="⚡ What do you want to do? (Use arrow keys)"
  export GUM_CHOOSE_CURSOR="›"
  export GUM_CHOOSE_CURSOR_PREFIX=" "
  export GUM_CHOOSE_SELECTED_PREFIX="✔ "
  export GUM_CHOOSE_UNSELECTED_PREFIX="  "
  export GUM_CHOOSE_HEIGHT=12

  CHOICE=$(gum choose \
    "👉  Install Cysic node / Установка ноды" \
    "🔁  Restart node / Рестарт ноды" \
    "⬆️  Update node / Обновление ноды" \
    "📜  View node logs / Просмотр логов ноды" \
    "🗑️  Remove node / Удаление ноды" \
    "🧰  Other nodes installer / Другие ноды" \
    "⏹️  Stop node / Остановить ноду" \
    "🚰  Start test-token claimer / Запустить клеймер" \
    "🔎  View claimer logs / Логи клеймера" \
    "🛑  Stop claimer / Остановить клеймер" \
    "❌  Exit / Выход" )
  echo "$CHOICE"
}

function menu_whiptail {
  CHOICE=$(whiptail --title "CYSIC VERIFIER" --menu "What do you want to do? (Use arrow keys)" 20 78 12 \
    "1" "Install Cysic node / Установка ноды" \
    "2" "Restart node / Рестарт ноды" \
    "3" "Update node / Обновление ноды" \
    "4" "View node logs / Просмотр логов" \
    "5" "Remove node / Удаление ноды" \
    "6" "Other nodes installer / Другие ноды" \
    "7" "Stop node / Остановить ноду" \
    "8" "Start test-token claimer / Запустить клеймер" \
    "9" "View claimer logs / Логи клеймера" \
    "10" "Stop claimer / Остановить клеймер" \
    "11" "Exit / Выход" \
    3>&1 1>&2 2>&3) || true
  echo "$CHOICE"
}

function main_menu {
  ensure_base_packages
  ensure_gum   # важно: ставим gum перед проверкой

  while true; do
    local choice
    if command -v gum >/dev/null 2>&1; then
      choice=$(menu_gum)
      case "$choice" in
        *"Install Cysic node"*)          install_node ;;
        *"Restart node"*)                restart_node ;;
        *"Update node"*)                 update_node ;;
        *"View node logs"*)              view_logs ;;
        *"Remove node"*)                 remove_node ;;
        *"Other nodes"*)                 other_nodes ;;
        *"Stop node"*)                   stop_node ;;
        *"Start test-token claimer"*)    start_claimer ;;
        *"View claimer logs"*)           claimer_logs ;;
        *"Stop claimer"*)                stop_claimer ;;
        *"Exit"*)                        break ;;
        *) ;;
      esac
    elif command -v whiptail >/dev/null 2>&1; then
      show_banner
      choice=$(menu_whiptail)
      case "$choice" in
        1) install_node ;; 2) restart_node ;; 3) update_node ;; 4) view_logs ;;
        5) remove_node ;; 6) other_nodes ;; 7) stop_node ;; 8) start_claimer ;;
        9) claimer_logs ;; 10) stop_claimer ;; 11) break ;;
        *) ;;
      esac
    else
      show_banner
      echo -e "${YELLOW}1) Install  2) Restart  3) Update  4) Logs  5) Remove  6) Other  7) Stop  8) Claimer  9) Claimer logs  10) Stop claimer  11) Exit${NC}"
      read -p "> " choice
      case "$choice" in
        1) install_node ;; 2) restart_node ;; 3) update_node ;; 4) view_logs ;;
        5) remove_node ;; 6) other_nodes ;; 7) stop_node ;; 8) start_claimer ;;
        9) claimer_logs ;; 10) stop_claimer ;; 11) break ;;
        *) ;;
      esac
    fi
  done
}

main_menu
