#!/bin/bash

# ==== Colors / Цвета ====
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'
PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'
set -Eeuo pipefail

# ==== Paths / Пути ====
EVM_FILE="/root/.cysic_evm"
NODE_DIR="/root/cysic-verifier"
NODE_SCREEN="cysic"                # screen session name for node / имя screen-сессии ноды
NODE_LOG="/var/log/cysic_node.log" # node log file / файл логов ноды
CLAIMER_PY="/root/cysic_claimer.py"
CLAIMER_LOG="/var/log/cysic_claimer.log"
CLAIMER_SCREEN="cysic-claimer"     # screen session name for claimer / имя screen-сессии клеймера

# ==== Ensure curl / Проверка curl ====
if ! command -v curl >/dev/null 2>&1; then
  apt update -y && apt install -y curl
fi

# ==== Banner / Баннер ====
echo -e "${PURPLE}"
cat << "EOF"
 ██████ ██    ██ ███████ ██  ██████     ██    ██ ███████ ██████  ██ ███████ ██ ███████ ██████  
██       ██  ██  ██      ██ ██          ██    ██ ██      ██   ██ ██ ██      ██ ██      ██   ██ 
██        ████   ███████ ██ ██          ██    ██ █████   ██████  ██ █████   ██ █████   ██████  
██         ██         ██ ██ ██           ██  ██  ██      ██   ██ ██ ██      ██ ██      ██   ██ 
 ██████    ██    ███████ ██  ██████       ████   ███████ ██   ██ ██ ██      ██ ███████ ██   ██ 

 ________________________________________________________________________________________________________________________________________

 ██  ██████  ██       █████  ███    ██ ██████   █████  ███    ██ ████████ ███████                                                         
██  ██        ██     ██   ██ ████   ██ ██   ██ ██   ██ ████   ██    ██    ██                                                             
██  ██        ██     ███████ ██ ██  ██ ██   ██ ███████ ██ ██  ██    ██    █████                                                          
██  ██        ██     ██   ██ ██  ██ ██ ██   ██ ██   ██ ██  ██ ██    ██    ██                                                             
 ██  ██████  ██      ██   ██ ██   ████ ██████  ██   ██ ██   ████    ██    ███████

Donate: 0x0004230c13c3890F34Bb9C9683b91f539E809000
EOF
echo -e "${NC}"

# ==== Base deps / Базовые зависимости ====
ensure_base() {
  echo -e "${BLUE}Installing dependencies... / Устанавливаем зависимости...${NC}"
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y screen build-essential unzip lz4 gcc git jq python3 python3-pip curl >/dev/null 2>&1
}

ensure_python_libs() {
  echo -e "${BLUE}Installing Python libs (requests, web3, eth-account)... / Ставим Python-библиотеки...${NC}"
  python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
  python3 -m pip install requests web3 eth-account >/dev/null 2>&1
}

# ==== Node: start in screen with file logging / Запуск ноды в screen с логированием в файл ====
_start_node_internal() {
  ensure_base
  if [ ! -d "$NODE_DIR" ]; then
    echo -e "${RED}Node directory not found. Install the node first. / Каталог ноды не найден. Сначала установите ноду.${NC}"
    return 1
  fi
  sudo touch "$NODE_LOG"; sudo chown "$USER":"$USER" "$NODE_LOG"; sudo chmod 664 "$NODE_LOG"
  # Close previous session if exists / Закрыть старую сессию
  screen -S "$NODE_SCREEN" -X quit >/dev/null 2>&1 || true
  echo -e "${BLUE}Starting node in screen (${NODE_SCREEN})... / Стартуем ноду в screen (${NODE_SCREEN})...${NC}"
  # Use stdbuf for line-buffered piping; no login shell to avoid ~/.bash_profile / Линейный буфер, без логин-оболочки
  screen -S "$NODE_SCREEN" -dm bash -c "cd '$NODE_DIR' && stdbuf -oL -eL bash start.sh 2>&1 | tee -a '$NODE_LOG'"
  echo -e "${GREEN}Node started. Logs: ${NODE_LOG} / Нода запущена. Логи: ${NODE_LOG}${NC}"
}

# ==== Node: install + auto start / Установка + автозапуск ====
install_node() {
  ensure_base
  echo -e "${YELLOW}Enter your linked EVM address: / Введите адрес привязанного EVM-кошелька:${NC}"
  read -r EVM_WALLET
  if [ -z "$EVM_WALLET" ]; then echo -e "${RED}EVM address cannot be empty. / Адрес EVM не может быть пустым.${NC}"; return; fi
  echo "$EVM_WALLET" > "$EVM_FILE"

  echo -e "${BLUE}Downloading and running Cysic installer... / Скачиваем и запускаем установщик Cysic...${NC}"
  curl -fsSL https://github.com/cysic-labs/cysic-phase3/releases/download/v1.0.0/setup_linux.sh > ~/setup_linux.sh
  chmod +x ~/setup_linux.sh
  bash ~/setup_linux.sh "$EVM_WALLET"

  _start_node_internal
  echo -e "${GREEN}Install complete and node is running. / Установка завершена, нода запущена.${NC}"
}

# ==== Node: stop/restart/logs/update/remove / Останов/рестарт/логи/обновление/удаление ====
stop_node() {
  echo -e "${BLUE}Stopping node... / Останавливаем ноду...${NC}"
  screen -S "$NODE_SCREEN" -X quit >/dev/null 2>&1 || true
  pkill -f "$NODE_DIR/start.sh" >/dev/null 2>&1 || true
  pkill -f "cysic-verifier" >/dev/null 2>&1 || true
  echo -e "${GREEN}Node stopped. / Нода остановлена.${NC}"
}

restart_node() { stop_node; sleep 1; _start_node_internal; }

node_logs() {
  echo -e "${YELLOW}Following node logs (CTRL+C to exit)... / Просмотр логов ноды (CTRL+C для выхода)...${NC}"
  if [ ! -f "$NODE_LOG" ]; then
    echo -e "${BLUE}Creating log file... / Создаём файл логов...${NC}"
    sudo touch "$NODE_LOG"; sudo chown "$USER":"$USER" "$NODE_LOG"; sudo chmod 664 "$NODE_LOG"
  fi
  tail -n 200 -f "$NODE_LOG"
}

update_node() {
  if [ -f "$EVM_FILE" ]; then
    EVM_WALLET=$(cat "$EVM_FILE")
  else
    echo -e "${YELLOW}Enter EVM address: / Введите адрес EVM:${NC}"
    read -r EVM_WALLET
    [ -z "$EVM_WALLET" ] && { echo -e "${RED}EVM address cannot be empty. / Адрес EVM не может быть пустым.${NC}"; return; }
    echo "$EVM_WALLET" > "$EVM_FILE"
  fi
  echo -e "${BLUE}Updating node... / Обновляем ноду...${NC}"
  curl -fsSL https://github.com/cysic-labs/cysic-phase3/releases/download/v1.0.0/setup_linux.sh > ~/setup_linux.sh
  chmod +x ~/setup_linux.sh
  bash ~/setup_linux.sh "$EVM_WALLET"
  echo -e "${BLUE}Restarting node... / Перезапуск ноды...${NC}"
  restart_node
}

remove_node() {
  echo -e "${RED}Remove node completely? (y/n) / Удалить ноду полностью? (y/n)${NC}"
  read -r confirm
  if [[ "$confirm" == "y" ]]; then
    stop_node
    rm -rf "$NODE_DIR" ~/setup_linux.sh "$NODE_LOG" "$EVM_FILE"
    echo -e "${GREEN}Node removed. / Нода удалена.${NC}"
  else
    echo -e "${YELLOW}Cancelled. / Отменено.${NC}"
  fi
}

# ==== Claimer Python / Скрипт клеймера ====
write_claimer_py() {
sudo tee "$CLAIMER_PY" >/dev/null <<'PYEOF'
import argparse, requests, random, time, sys
from web3 import Web3
from eth_account.messages import encode_defunct
from datetime import datetime

BASE_URL = "https://api-pre.prover.xyz"
def now(): return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def validate_private_key(pk: str) -> bool:
    pk = pk.strip()
    if pk.startswith('0x'): pk = pk[2:]
    return len(pk) == 64 and all(c in '0123456789abcdefABCDEF' for c in pk)

class CysicClaimer:
    def __init__(self, pk, invite):
        self.pk = pk.strip(); self.invite = invite.strip()
        self.w3 = Web3()
        try:
            self.account = self.w3.eth.account.from_key(self.pk)
        except Exception as e:
            sys.exit(f"Invalid private key: {e}")
        self.wallet = self.account.address
        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": "https://app.cysic.xyz",
            "Referer": "https://app.cysic.xyz/",
        })

    def sign(self, text: str) -> str:
        return self.account.sign_message(encode_defunct(text=text)).signature.hex()

    def bind_invite(self) -> bool:
        r = self.s.post(f"{BASE_URL}/api/v1/user/updateProfile",
                        headers={"X-Cysic-Address": self.wallet, "X-Cysic-Sign": self.sign(f"Welcome to Cysic! Invite Code: {self.invite}")},
                        json={"inviteCode": self.invite})
        print(f"[{now()}] Bind invite: {r.status_code} {r.text[:200]}")
        return r.status_code == 200

    def claim(self) -> bool:
        r = self.s.get(f"{BASE_URL}/api/v1/user/faucet",
                       headers={"X-Cysic-Address": self.wallet, "X-Cysic-Sign": self.sign('Welcome to Cysic!')})
        print(f"[{now()}] Claim: {r.status_code} {r.text[:200]}")
        try:
            code = r.json().get("code")
            return code in (0, 10099)
        except Exception:
            return False

    def cycle(self):
        print("="*70)
        print(f"[{now()}] Wallet: {self.wallet}")
        ok = self.bind_invite() and self.claim()
        print(f"[{now()}] {'✅ Success' if ok else '❌ Fail'}")

def main():
    ap = argparse.ArgumentParser(description="Cysic test token claimer (0.1/24h)")
    ap.add_argument("--pk", required=True); ap.add_argument("--invite", required=True)
    a = ap.parse_args()
    if not validate_private_key(a.pk): sys.exit("Invalid PK format")
    c = CysicClaimer(a.pk, a.invite)
    while True:
        try:
            c.cycle()
            m = random.randint(1441, 1445); s = m*60
            print(f"[{now()}] Next in {m} min ({s} sec)")
            time.sleep(s)
        except KeyboardInterrupt:
            print(f"[{now()}] Interrupted"); break
        except Exception as e:
            print(f"[{now()}] Unhandled: {e}"); time.sleep(30)

if __name__ == "__main__": main()
PYEOF
}

# ==== Claimer: start/logs/stop (screen, unbuffered) / Старт/логи/стоп ====
start_claimer() {
  ensure_base; ensure_python_libs; write_claimer_py
  echo -e "${YELLOW}Enter your Cysic private key: / Введите приватный ключ кошелька Cysic:${NC}"
  read -r PRIVATE_KEY
  echo -e "${YELLOW}Enter your Cysic invite code: / Введите invite code от Cysic:${NC}"
  read -r INVITE
  if [ -z "$PRIVATE_KEY" ] || [ -z "$INVITE" ]; then
    echo -e "${RED}Private key and invite code are required. / Оба поля обязательны.${NC}"; return
  fi
  sudo touch "$CLAIMER_LOG"; sudo chown "$USER":"$USER" "$CLAIMER_LOG"; sudo chmod 664 "$CLAIMER_LOG"
  screen -S "$CLAIMER_SCREEN" -X quit >/dev/null 2>&1 || true
  echo -e "${BLUE}Starting claimer in screen (${CLAIMER_SCREEN})... / Запускаем клеймер в screen (${CLAIMER_SCREEN})...${NC}"
  # -u + PYTHONUNBUFFERED to flush; stdbuf for pipe / без буферизации
  screen -S "$CLAIMER_SCREEN" -dm bash -c "export PYTHONUNBUFFERED=1; python3 -u '$CLAIMER_PY' --pk '$PRIVATE_KEY' --invite '$INVITE' 2>&1 | stdbuf -oL -eL tee -a '$CLAIMER_LOG'"
  echo -e "${GREEN}Claimer started. Logs: ${CLAIMER_LOG} / Клеймер запущен. Логи: ${CLAIMER_LOG}${NC}"
}

claimer_logs() {
  echo -e "${YELLOW}Following claimer logs (CTRL+C to exit)... / Просмотр логов клеймера (CTRL+C для выхода)...${NC}"
  if [ ! -f "$CLAIMER_LOG" ]; then
    sudo touch "$CLAIMER_LOG"; sudo chown "$USER":"$USER" "$CLAIMER_LOG"; sudo chmod 664 "$CLAIMER_LOG"
  fi
  tail -n 200 -f "$CLAIMER_LOG"
}

stop_claimer() {
  echo -e "${BLUE}Stopping claimer... / Останавливаем клеймер...${NC}"
  screen -S "$CLAIMER_SCREEN" -X quit >/dev/null 2>&1 || true
  pkill -f "$CLAIMER_PY" >/dev/null 2>&1 || true
  echo -e "${GREEN}Claimer stopped. / Клеймер остановлен.${NC}"
}

# ==== Menu / Меню ====
main_menu() {
  while true; do
    echo -e "${CYAN}
1. Install node (auto start) / Установить ноду (автостарт)
2. Stop node / Остановить ноду
3. Restart node / Рестарт ноды
4. View node logs / Логи ноды
5. Update node / Обновить ноду
6. Remove node / Удалить ноду
7. Start claimer / Запустить клеймер
8. View claimer logs / Логи клеймера
9. Stop claimer / Остановить клеймер
10. Exit / Выход${NC}"
    read -rp "Choice / Выбор: " c
    case "$c" in
      1) install_node ;;
      2) stop_node ;;
      3) restart_node ;;
      4) node_logs ;;
      5) update_node ;;
      6) remove_node ;;
      7) start_claimer ;;
      8) claimer_logs ;;
      9) stop_claimer ;;
      10) break ;;
      *) echo -e "${RED}Invalid choice, try again. / Неверный выбор, попробуйте снова.${NC}" ;;
    esac
  done
}

main_menu
