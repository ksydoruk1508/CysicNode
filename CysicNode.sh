#!/bin/bash

# Цвета текста
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # сброс цвета

set -Eeuo pipefail

# Файлы и пути
EVM_FILE="/root/.cysic_evm"
CLAIMER_PY="/root/cysic_claimer.py"
CLAIMER_LOG="/var/log/cysic_claimer.log"
CLAIMER_PID="/var/run/cysic_claimer.pid"   # используется для nohup-режима

# Проверка наличия curl и установка, если не установлен
if ! command -v curl &> /dev/null; then
    sudo apt update
    sudo apt install curl -y
fi
sleep 1

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

# ------------------------- УТИЛИТЫ -------------------------
function ensure_base_packages {
    echo -e "${BLUE}Устанавливаем зависимости / Installing dependencies...${NC}"
    sudo apt-get update -y && sudo apt-get upgrade -y
    sudo apt-get install -y make screen build-essential unzip lz4 gcc git jq python3 python3-pip whiptail
}

function ensure_python_libs {
    echo -e "${BLUE}Ставим Python-библиотеки (requests, web3, eth-account) / Installing Python libs...${NC}"
    python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
    python3 -m pip install requests web3 eth-account >/dev/null 2>&1
}

function has_whiptail {
    command -v whiptail >/dev/null 2>&1
}

# ------------------------- NODE: INSTALL -------------------------
function install_node {
    ensure_base_packages

    echo -e "${YELLOW}Введите адрес привязанного EVM-кошелька на сайте / Enter your linked EVM address:${NC}"
    read EVM_WALLET

    if [ -z "$EVM_WALLET" ]; then
        echo -e "${RED}EVM-кошелек не может быть пустым / EVM address cannot be empty.${NC}"
        return
    fi

    # Сохраняем для будущего обновления
    echo "$EVM_WALLET" | sudo tee "$EVM_FILE" >/dev/null

    echo -e "${BLUE}Скачиваем и запускаем установщик Cysic / Downloading & running Cysic setup...${NC}"
    curl -L --fail https://github.com/cysic-labs/phase2_libs/releases/download/v1.0.0/setup_linux.sh > ~/setup_linux.sh
    chmod +x ~/setup_linux.sh
    bash ~/setup_linux.sh "$EVM_WALLET"

    echo -e "${BLUE}Создаём systemd-сервис / Creating systemd service...${NC}"

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

    echo -e "${BLUE}Активируем и запускаем сервис / Enabling & starting service...${NC}"
    sudo systemctl daemon-reload
    sudo systemctl enable cysic
    sudo systemctl start cysic

    echo -e "${GREEN}Установка завершена / Installation complete!${NC}"
    echo -e "${YELLOW}Логи / Logs:${NC} ${CYAN}sudo journalctl -u cysic -f --no-hostname -o cat${NC}"
}

# ------------------------- NODE: UPDATE -------------------------
function update_node {
    # читаем EVM-адрес из файла, если есть, иначе попросим
    if [ -f "$EVM_FILE" ]; then
        EVM_WALLET=$(cat "$EVM_FILE")
    else
        echo -e "${YELLOW}Введите адрес EVM-кошелька / Enter EVM address:${NC}"
        read EVM_WALLET
        if [ -z "$EVM_WALLET" ]; then
            echo -e "${RED}EVM-кошелек не может быть пустым / EVM address cannot be empty.${NC}"
            return
        fi
        echo "$EVM_WALLET" | sudo tee "$EVM_FILE" >/dev/null
    fi

    echo -e "${BLUE}Обновляем ноду Cysic... / Updating Cysic node...${NC}"
    curl -L --fail https://github.com/cysic-labs/phase2_libs/releases/download/v1.0.0/setup_linux.sh > ~/setup_linux.sh
    chmod +x ~/setup_linux.sh
    bash ~/setup_linux.sh "$EVM_WALLET"

    echo -e "${BLUE}Перезапускаем ноду Cysic... / Restarting Cysic node...${NC}"
    sudo systemctl restart cysic
    echo -e "${GREEN}Нода перезапущена / Node restarted.${NC}"
}

# ------------------------- NODE: CONTROL -------------------------
function restart_node {
    echo -e "${BLUE}Перезапуск ноды Cysic / Restarting Cysic node...${NC}"
    sudo systemctl restart cysic
    echo -e "${GREEN}Нода перезапущена / Node restarted.${NC}"
}

function stop_node {
    echo -e "${BLUE}Останавливаем ноду Cysic / Stopping Cysic node...${NC}"
    sudo systemctl stop cysic
    echo -e "${GREEN}Нода остановлена / Node stopped.${NC}"
}

function view_logs {
    echo -e "${YELLOW}Просмотр логов (CTRL+C для выхода) / Follow logs (CTRL+C to exit):${NC}"
    sudo journalctl -u cysic -f --no-hostname -o cat
}

function remove_node {
    echo -e "${RED}Внимание: это удалит ноду Cysic полностью. Продолжить? (y/n) / Warning: This will remove Cysic node completely. Continue? (y/n)${NC}"
    read confirm
    if [ "$confirm" == "y" ]; then
        echo -e "${BLUE}Останавливаем и отключаем сервис / Stopping & disabling service...${NC}"
        sudo systemctl stop cysic || true
        sudo systemctl disable cysic || true

        echo -e "${BLUE}Удаляем файлы ноды / Removing node files...${NC}"
        rm -rf /root/cysic-verifier

        echo -e "${BLUE}Удаляем unit-файл / Removing systemd unit...${NC}"
        sudo rm -f /etc/systemd/system/cysic.service
        sudo systemctl daemon-reload
        sudo systemctl reset-failed || true

        echo -e "${GREEN}Нода удалена / Node removed.${NC}"
    else
        echo -e "${YELLOW}Операция отменена / Operation cancelled.${NC}"
    fi
}

function other_nodes {
    echo -e "${BLUE}Переходим к другим нодам / Switching to other nodes...${NC}"
    wget -q -O Ultimative_Node_Installer.sh https://raw.githubusercontent.com/ksydoruk1508/Ultimative_Node_Installer/main/Ultimative_Node_Installer.sh && sudo chmod +x Ultimative_Node_Installer.sh && ./Ultimative_Node_Installer.sh
}

# ------------------------- CLAIMER: PY SCRIPT -------------------------
function write_claimer_py {
sudo tee "$CLAIMER_PY" >/dev/null <<'PYEOF'
import argparse
import requests
from web3 import Web3
from eth_account.messages import encode_defunct
from datetime import datetime
import time, random, sys

BASE_URL = "https://api-pre.prover.xyz"

def now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def validate_private_key(pk: str) -> bool:
    if not pk: return False
    pk = pk.strip()
    if pk.startswith('0x'):
        pk = pk[2:]
    if len(pk) != 64:
        return False
    try:
        int(pk, 16)
        return True
    except ValueError:
        return False

class CysicClaimer:
    def __init__(self, private_key: str, invite_code: str):
        self.private_key = private_key.strip()
        self.invite_code = invite_code.strip()
        self.w3 = Web3()
        try:
            self.account = self.w3.eth.account.from_key(self.private_key)
            self.wallet_address = self.account.address
        except Exception as e:
            raise ValueError(f"Некорректный приватный ключ / Invalid private key: {e}")
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
            signature = self.sign_message(message)
            headers = {
                "Content-Type": "application/json",
                "X-Cysic-Address": self.wallet_address,
                "X-Cysic-Sign": signature
            }
            resp = self.session.post(url, headers=headers, json={"inviteCode": self.invite_code})
            print(f"[{now()}] Bind invite code status: {resp.status_code}")
            if resp.status_code == 200:
                print(f"[{now()}] Response: {resp.json()}")
                return True
            else:
                print(f"[{now()}] Error: {resp.text}")
                return False
        except Exception as e:
            print(f"[{now()}] Invite code bind error: {e}")
            return False

    def claim_tokens(self) -> bool:
        try:
            signature = self.sign_message("Welcome to Cysic!")
            headers = {
                "X-Cysic-Address": self.wallet_address,
                "X-Cysic-Sign": signature
            }
            url = f"{BASE_URL}/api/v1/user/faucet"
            resp = self.session.get(url, headers=headers)
            print(f"[{now()}] Claim status: {resp.status_code}")
            data = {}
            try:
                data = resp.json()
                print(f"[{now()}] Response: {data}")
            except Exception:
                print(f"[{now()}] Non-JSON response: {resp.text}")

            code = data.get('code')
            if code == 0:
                print(f"[{now()}] ✅ Tokens claimed successfully")
                return True
            if code == 10099:
                print(f"[{now()}] ℹ️  Already claimed or time-limited")
                return True
            if code == 10199:
                print(f"[{now()}] ❌ Authorization required")
                return False
            print(f"[{now()}] ℹ️  Other response code: {data}")
            return True
        except Exception as e:
            print(f"[{now()}] Claim error: {e}")
            return False

    def run_cycle(self) -> bool:
        print("="*70)
        print(f"[{now()}] Start cycle for wallet: {self.wallet_address}")
        print("-"*70)

        print(f"[{now()}] Binding invite code: {self.invite_code}")
        if not self.bind_invite_code():
            print(f"[{now()}] ❌ Invite code binding failed")
            return False
        print(f"[{now()}] ✅ Invite code bound")

        print(f"[{now()}] Claiming test tokens...")
        ok = self.claim_tokens()
        if ok:
            print(f"[{now()}] ✅ Cycle finished successfully")
        else:
            print(f"[{now()}] ❌ Cycle failed")
        return ok

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Cysic test token claimer (0.1/24h)")
    parser.add_argument("--pk", required=True, help="Private key (hex, with or without 0x)")
    parser.add_argument("--invite", required=True, help="Invite code")
    args = parser.parse_args()

    if not validate_private_key(args.pk):
        print("❌ Некорректный приватный ключ / Invalid private key format")
        sys.exit(1)

    claimer = CysicClaimer(args.pk, args.invite)

    while True:
        try:
            claimer.run_cycle()
            interval_minutes = random.randint(1441, 1445)
            interval_seconds = interval_minutes * 60
            print(f"\n⏰ Next cycle in {interval_minutes} minutes ({interval_seconds} seconds)")
            print(f"[{now()}] Next cycle at: {datetime.fromtimestamp(time.time()+interval_seconds).strftime('%Y-%m-%d %H:%M:%S')}")
            print("="*70)
            time.sleep(interval_seconds)
        except KeyboardInterrupt:
            print(f"\n[{now()}] ⚠️  Interrupted by user")
            break
        except Exception as e:
            print(f"[{now()}] Unhandled error: {e}")
            time.sleep(30)

if __name__ == "__main__":
    main()
PYEOF
}

# ------------------------- CLAIMER: RUN, LOGS, STOP -------------------------
function start_claimer {
    ensure_base_packages
    ensure_python_libs
    write_claimer_py

    echo -e "${YELLOW}Введите приватный ключ вашего кошелька Cysic / Enter the private key of your Cysic wallet:${NC}"
    read -r PRIVATE_KEY
    echo -e "${YELLOW}Введите invite code от Cysic / Enter your Cysic invite code:${NC}"
    read -r INVITE_CODE

    if [ -z "${PRIVATE_KEY}" ] || [ -z "${INVITE_CODE}" ]; then
        echo -e "${RED}Приватный ключ и invite code обязательны / Private key and invite code are required.${NC}"
        return
    fi

    sudo touch "$CLAIMER_LOG"
    sudo chmod 644 "$CLAIMER_LOG"

    # Пытаемся запустить в screen, при отсутствии — через nohup
    if command -v screen >/dev/null 2>&1; then
        echo -e "${BLUE}Запускаем клеймер в screen-сессии 'cysic-claimer' / Starting claimer in screen session 'cysic-claimer'...${NC}"
        screen -S cysic-claimer -X quit >/dev/null 2>&1 || true
        screen -S cysic-claimer -dm bash -lc "python3 '$CLAIMER_PY' --pk '$PRIVATE_KEY' --invite '$INVITE_CODE' >> '$CLAIMER_LOG' 2>&1"
        # В режиме screen PID клеймера может меняться — чистим PID-файл
        sudo rm -f "$CLAIMER_PID" 2>/dev/null || true
        echo -e "${GREEN}Клеймер запущен в screen. Логи: $CLAIMER_LOG / Claimer started in screen. Logs: $CLAIMER_LOG${NC}"
        echo -e "${YELLOW}Подключиться к screen: screen -r cysic-claimer (выйти: Ctrl+A, D)${NC}"
    else
        echo -e "${YELLOW}screen не найден, запускаем через nohup / 'screen' not found, falling back to nohup...${NC}"
        nohup python3 "$CLAIMER_PY" --pk "$PRIVATE_KEY" --invite "$INVITE_CODE" >> "$CLAIMER_LOG" 2>&1 &
        CLAIMER_BG_PID=$!
        echo "$CLAIMER_BG_PID" | sudo tee "$CLAIMER_PID" >/dev/null
        echo -e "${GREEN}Клеймер запущен через nohup (PID $CLAIMER_BG_PID). Логи: $CLAIMER_LOG / Claimer started with nohup. Logs: $CLAIMER_LOG${NC}"
    fi
}

function claimer_logs {
    echo -e "${YELLOW}Просмотр логов клеймера (CTRL+C для выхода) / View claimer logs (CTRL+C to exit):${NC}"
    if [ -f "$CLAIMER_LOG" ]; then
        tail -n 200 -f "$CLAIMER_LOG"
    else
        echo -e "${RED}Файл логов не найден: $CLAIMER_LOG / Log file not found.${NC}"
    fi
}

function stop_claimer {
    echo -e "${BLUE}Останавливаем клеймер / Stopping claimer...${NC}"

    # 1) Если есть screen-сессия — закрываем её
    if screen -list 2>/dev/null | grep -q "cysic-claimer"; then
        screen -S cysic-claimer -X quit || true
        echo -e "${GREEN}Screen-сессия 'cysic-claimer' остановлена / Screen session stopped.${NC}"
    fi

    # 2) Если запускался через nohup и есть PID — пробуем завершить
    if [ -f "$CLAIMER_PID" ]; then
        PID=$(cat "$CLAIMER_PID" || true)
        if [ -n "${PID:-}" ] && ps -p "$PID" >/dev/null 2>&1; then
            kill "$PID" || true
            sleep 1
            if ps -p "$PID" >/dev/null 2>&1; then
                kill -9 "$PID" || true
            fi
            echo -e "${GREEN}Процесс клеймера (PID $PID) остановлен / Claimer process stopped.${NC}"
        fi
        sudo rm -f "$CLAIMER_PID" 2>/dev/null || true
    fi

    # 3) На всякий случай убьём оставшиеся процессы скрипта клеймера
    pkill -f "$CLAIMER_PY" >/dev/null 2>&1 || true

    echo -e "${GREEN}Готово / Done.${NC}"
}

# ------------------------- МЕНЮ (TUI через whiptail или цифры) -------------------------
function menu_tui {
    # Возвращает выбранный номер в stdout, или пусто если отмена
    local CHOICE
    CHOICE=$(whiptail --title "Cysic Node Manager" --menu "Выберите действие / Choose an action" 20 78 12 \
        "1" "Установка ноды / Install Cysic node" \
        "2" "Рестарт ноды / Restart node" \
        "3" "Обновление ноды / Update node" \
        "4" "Просмотр логов ноды / View node logs" \
        "5" "Удаление ноды / Remove node" \
        "6" "Другие ноды / Other nodes installer" \
        "7" "Остановить ноду / Stop node" \
        "8" "Запустить клеймер / Start test-token claimer" \
        "9" "Проверка логов клеймера / View claimer logs" \
        "10" "Остановить клеймер / Stop claimer" \
        "11" "Выход / Exit" \
        3>&1 1>&2 2>&3) || true
    echo "$CHOICE"
}

function main_menu {
    ensure_base_packages  # чтобы whiptail был доступен
    while true; do
        local choice
        if has_whiptail; then
            choice=$(menu_tui)
            # если пользователь нажал Cancel/ESC — просто спросим, выйти ли
            if [ -z "${choice}" ]; then
                if whiptail --yesno "Выйти? / Exit?" 8 40; then
                    break
                else
                    continue
                fi
            fi
        else
            echo -e "${YELLOW}Выберите действие / Choose an action:${NC}"
            echo -e "${CYAN}1. Установка ноды Cysic / Install Cysic node${NC}"
            echo -e "${CYAN}2. Рестарт ноды / Restart node${NC}"
            echo -e "${CYAN}3. Обновление ноды / Update node${NC}"
            echo -e "${CYAN}4. Просмотр логов ноды / View node logs${NC}"
            echo -e "${CYAN}5. Удаление ноды / Remove node${NC}"
            echo -e "${CYAN}6. Перейти к другим нодам / Other nodes installer${NC}"
            echo -e "${CYAN}7. Остановить ноду / Stop node${NC}"
            echo -e "${CYAN}8. Запустить клеймер тестовых токенов / Start test-token claimer${NC}"
            echo -e "${CYAN}9. Проверка логов клеймера / View claimer logs${NC}"
            echo -e "${CYAN}10. Остановить клеймер / Stop claimer${NC}"
            echo -e "${CYAN}11. Выход / Exit${NC}"
            echo -e " "
            echo -e "${PURPLE}Все текстовые гайды / All text guides - https://teletype.in/@c6zr7${NC}"
            echo -e "${YELLOW}Введите номер / Enter number:${NC} "
            read choice
        fi

        case $choice in
            1) install_node ;;
            2) restart_node ;;
            3) update_node ;;
            4) view_logs ;;
            5) remove_node ;;
            6) other_nodes ;;
            7) stop_node ;;
            8) start_claimer ;;
            9) claimer_logs ;;
            10) stop_claimer ;;
            11) break ;;
            *) echo -e "${RED}Неверный выбор, попробуйте снова / Invalid choice, try again.${NC}" ;;
        esac
    done
}

main_menu
