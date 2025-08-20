#!/bin/bash

# ==== Colors / Цвета ====
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'
PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'
set -Eeuo pipefail

# ==== Paths / Пути ====
EVM_FILE="$HOME/.cysic_evm"
NODE_DIR="$HOME/cysic-verifier"
NODE_SERVICE="cysic"               # systemd service name / имя systemd-сервиса

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

Donate: 0x0004230c13c3890F34Bb9C9683b91f539E809000
EOF
echo -e "${NC}"

# ==== Base deps / Базовые зависимости ====
ensure_base() {
  echo -e "${BLUE}Installing dependencies... / Устанавливаем зависимости...${NC}"
  apt-get update -y >/dev/null 2>&1 || true
  # screen остаётся для клеймера
  apt-get install -y screen build-essential unzip lz4 gcc git jq python3 python3-pip curl >/dev/null 2>&1
}

ensure_python_libs() {
  echo -e "${BLUE}Installing Python libs (requests, web3, eth-account)... / Ставим Python-библиотеки...${NC}"
  python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
  python3 -m pip install requests web3 eth-account >/dev/null 2>&1
}

# ==== Node via systemd / Нода через systemd ====

_create_cysic_service() {
  # Пишем unit в /etc/systemd/system/cysic.service по заданному шаблону
  sudo tee /etc/systemd/system/${NODE_SERVICE}.service > /dev/null << EOF
[Unit]
Description=Cysic Verifier Node
After=network-online.target

[Service]
User=$USER
ExecStart=/bin/bash -c 'cd $HOME/cysic-verifier && bash start.sh'
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable ${NODE_SERVICE} >/dev/null 2>&1 || true
}

_start_node_systemd() {
  echo -e "${BLUE}Starting node service... / Запускаем сервис ноды...${NC}"
  sudo systemctl start ${NODE_SERVICE}
  echo -e "${GREEN}Node started as systemd service '${NODE_SERVICE}'. / Нода запущена как сервис '${NODE_SERVICE}'.${NC}"
  echo -e "${YELLOW}Logs: sudo journalctl -u ${NODE_SERVICE} -f --no-hostname -o cat${NC}"
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

  _create_cysic_service
  _start_node_systemd
  echo -e "${GREEN}Install complete and node is running under systemd. / Установка завершена, нода работает под systemd.${NC}"
}

# ==== Node: stop/restart/logs/update/remove / Останов/рестарт/логи/обновление/удаление ====
stop_node() {
  echo -e "${BLUE}Stopping node service... / Останавливаем сервис ноды...${NC}"
  sudo systemctl stop ${NODE_SERVICE} || true
  echo -e "${GREEN}Node stopped. / Нода остановлена.${NC}"
}

restart_node() {
  echo -e "${BLUE}Restarting node service... / Перезапускаем сервис ноды...${NC}"
  sudo systemctl restart ${NODE_SERVICE}
  echo -e "${GREEN}Node restarted. / Нода перезапущена.${NC}"
}

node_logs() {
  echo -e "${YELLOW}Following node logs (CTRL+C to exit)... / Просмотр логов ноды (CTRL+C для выхода)...${NC}"
  sudo journalctl -u ${NODE_SERVICE} -f --no-hostname -o cat
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
  echo -e "${BLUE}Restarting node service... / Перезапуск сервиса ноды...${NC}"
  sudo systemctl restart ${NODE_SERVICE}
  echo -e "${GREEN}Update complete. / Обновление завершено.${NC}"
}

remove_node() {
  echo -e "${RED}Remove node completely? (y/n) / Удалить ноду полностью? (y/n)${NC}"
  read -r confirm
  if [[ "$confirm" == "y" ]]; then
    sudo systemctl disable --now ${NODE_SERVICE} >/dev/null 2>&1 || true
    sudo rm -f /etc/systemd/system/${NODE_SERVICE}.service
    sudo systemctl daemon-reload
    rm -rf "$NODE_DIR" ~/setup_linux.sh "$EVM_FILE"
    echo -e "${GREEN}Node removed and service deleted. / Нода и сервис удалены.${NC}"
  else
    echo -e "${YELLOW}Cancelled. / Отменено.${NC}"
  fi
}

# ==== Claimer Python / Скрипт клеймера (без изменений) ====
write_claimer_py() {
sudo tee "$CLAIMER_PY" >/dev/null <<'PYEOF'
import argparse, requests, random, time, sys
from web3 import Web3
from eth_account.messages import encode_defunct
from datetime import datetime

BASE_URL = "https://api-pre.prover.xyz"

def now() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def validate_private_key(pk: str) -> bool:
    pk = (pk or "").strip()
    if pk.startswith('0x'):
        pk = pk[2:]
    return len(pk) == 64 and all(c in '0123456789abcdefABCDEF' for c in pk)

def parse_cooldown_seconds(msg) -> int:
    try:
        val = int(str(msg).strip())
    except Exception:
        return 0
    now_ts = int(time.time())
    if val > now_ts + 60:
        return max(0, val - now_ts)
    return max(0, val)

class CysicClaimer:
    def __init__(self, pk: str, invite: str):
        self.pk = pk.strip()
        self.invite = invite.strip()
        self.w3 = Web3()
        try:
            self.account = self.w3.eth.account.from_key(self.pk)
        except Exception as e:
            sys.exit(f"Invalid private key / Некорректный приватный ключ: {e}")
        self.wallet = self.account.address

        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": "https://app.cysic.xyz",
            "Referer": "https://app.cysic.xyz/",
        })
        self.timeout = 30

    def sign(self, text: str) -> str:
        return self.account.sign_message(encode_defunct(text=text)).signature.hex()

    def bind_invite(self) -> bool:
        try:
            r = self.s.post(
                f"{BASE_URL}/api/v1/user/updateProfile",
                headers={
                    "X-Cysic-Address": self.wallet,
                    "X-Cysic-Sign": self.sign(f"Welcome to Cysic! Invite Code: {self.invite}")
                },
                json={"inviteCode": self.invite},
                timeout=self.timeout
            )
            print(f"[{now()}] Bind invite / Привязка инвайта: {r.status_code} {r.text[:200]}")
            return r.status_code == 200
        except Exception as e:
            print(f"[{now()}] Bind error / Ошибка привязки: {e}")
            return False

    def claim(self) -> tuple[bool, int]:
        try:
            r = self.s.get(
                f"{BASE_URL}/api/v1/user/faucet",
                headers={
                    "X-Cysic-Address": self.wallet,
                    "X-Cysic-Sign": self.sign("Welcome to Cysic!")
                },
                timeout=self.timeout
            )
            print(f"[{now()}] Claim response / Ответ клейма: {r.status_code} {r.text[:200]}")
        except Exception as e:
            print(f"[{now()}] Claim request error / Ошибка запроса клейма: {e}")
            return False, 300

        try:
            data = r.json()
        except Exception:
            return False, 300

        code = data.get("code")
        msg  = data.get("msg")

        if code == 0:
            base = 24 * 60 * 60
            jitter = random.randint(60, 180)
            print(f"[{now()}] ✅ Claimed successfully / Клейм успешен")
            return True, base + jitter

        if code == 10099:
            wait = parse_cooldown_seconds(msg)
            if wait == 0:
                wait = 24 * 60 * 60
            wait += random.randint(30, 90)
            h, m = wait // 3600, (wait % 3600) // 60
            print(f"[{now()}] ⏳ Cooldown: next allowed in ~{h}h {m}m / До следующего клейма ~{h}ч {m}м")
            return False, wait

        if code == 10199:
            print(f"[{now()}] ❌ Authorization required / Требуется авторизация")
            return False, 300

        print(f"[{now()}] ℹ️ Unexpected code / Неожиданный код: {code}, msg={msg}")
        return False, 300

def main():
    ap = argparse.ArgumentParser(description="Cysic test token claimer (0.1/24h)")
    ap.add_argument("--pk", required=True, help="Private key (hex)")
    ap.add_argument("--invite", required=True, help="Invite code")
    a = ap.parse_args()

    if not validate_private_key(a.pk):
        sys.exit("Invalid PK format / Неверный формат приватного ключа")

    claimer = CysicClaimer(a.pk, a.invite)

    while True:
        try:
            claimer.bind_invite()
            success, wait = claimer.claim()
            if not success:
                print(f"[{now()}] ℹ️ Not claimed this time / В этот раз клейма нет")
            h, m, s = wait // 3600, (wait % 3600) // 60, wait % 60
            print(f"[{now()}] Next attempt in {h:02d}:{m:02d}:{s:02d} ({wait} sec) / Следующая попытка через {h:02d}:{m:02d}:{s:02d} ({wait} сек)")
            print("=" * 70)
            time.sleep(wait)
        except KeyboardInterrupt:
            print(f"[{now()}] Interrupted / Остановлено пользователем")
            break
        except Exception as e:
            print(f"[{now()}] Unhandled error / Необработанная ошибка: {e}")
            time.sleep(60)

if __name__ == "__main__":
    main()
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
1. Install node (systemd, auto start) / Установить ноду (systemd, автостарт)
2. Stop node (systemd) / Остановить ноду
3. Restart node (systemd) / Рестарт ноды
4. View node logs (journalctl) / Логи ноды
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
