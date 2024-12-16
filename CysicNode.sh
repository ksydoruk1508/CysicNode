#!/bin/bash

# Цвета текста
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # сброс цвета

# Проверка наличия curl и установка, если не установлен
if ! command -v curl &> /dev/null; then
    sudo apt update
    sudo apt install curl -y
fi
sleep 1

echo -e "${GREEN}"
cat << "EOF"
 ██████ ██    ██ ███████ ██  ██████     ███    ██  ██████  ██████  ███████ 
██       ██  ██  ██      ██ ██          ████   ██ ██    ██ ██   ██ ██      
██        ████   ███████ ██ ██          ██ ██  ██ ██    ██ ██   ██ █████   
██         ██         ██ ██ ██          ██  ██ ██ ██    ██ ██   ██ ██      
 ██████    ██    ███████ ██  ██████     ██   ████  ██████  ██████  ███████

________________________________________________________________________________________________________________________________________


███████  ██████  ██████      ██   ██ ███████ ███████ ██████      ██ ████████     ████████ ██████   █████  ██████  ██ ███    ██  ██████  
██      ██    ██ ██   ██     ██  ██  ██      ██      ██   ██     ██    ██           ██    ██   ██ ██   ██ ██   ██ ██ ████   ██ ██       
█████   ██    ██ ██████      █████   █████   █████   ██████      ██    ██           ██    ██████  ███████ ██   ██ ██ ██ ██  ██ ██   ███ 
██      ██    ██ ██   ██     ██  ██  ██      ██      ██          ██    ██           ██    ██   ██ ██   ██ ██   ██ ██ ██  ██ ██ ██    ██ 
██       ██████  ██   ██     ██   ██ ███████ ███████ ██          ██    ██           ██    ██   ██ ██   ██ ██████  ██ ██   ████  ██████  
                                                                                                                                         
                                                                                                                                         
 ██  ██████  ██       █████  ███    ██ ██████   █████  ███    ██ ████████ ███████                                                         
██  ██        ██     ██   ██ ████   ██ ██   ██ ██   ██ ████   ██    ██    ██                                                             
██  ██        ██     ███████ ██ ██  ██ ██   ██ ███████ ██ ██  ██    ██    █████                                                          
██  ██        ██     ██   ██ ██  ██ ██ ██   ██ ██   ██ ██  ██ ██    ██    ██                                                             
 ██  ██████  ██      ██   ██ ██   ████ ██████  ██   ██ ██   ████    ██    ███████

Donate: 0x0004230c13c3890F34Bb9C9683b91f539E809000
EOF
echo -e "${NC}"

function install_node {
    echo -e "${BLUE}Обновляем систему и устанавливаем необходимые пакеты...${NC}"
    sudo apt-get update -y && sudo apt-get upgrade -y && sudo apt-get install make screen build-essential unzip lz4 gcc git jq -y

    echo -e "${YELLOW}Введите адрес привязного вами EVM кошелька на сайте: ${NC}"
    read EVM_WALLET

    if [ -z "$EVM_WALLET" ]; then
        echo -e "${RED}EVM-кошелек не может быть пустым! Повторите попытку.${NC}"
        return
    fi

    echo -e "${BLUE}Скачиваем и запускаем скрипт установки cysic...${NC}"
    curl -L https://github.com/cysic-labs/phase2_libs/releases/download/v1.0.0/setup_linux.sh > ~/setup_linux.sh
    chmod +x ~/setup_linux.sh
    bash ~/setup_linux.sh $EVM_WALLET

    echo -e "${BLUE}Создаём системный сервис для Cysic...${NC}"

    sudo tee /etc/systemd/system/cysic.service > /dev/null <<EOF
[Unit]
Description=Cysic Verifier
After=network.target

[Service]
User=$USER
WorkingDirectory=/root/cysic-verifier
ExecStart=bash /root/cysic-verifier/start.sh
Restart=on-failure
RestartSec=10
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    echo -e "${BLUE}Активируем и запускаем сервис Cysic...${NC}"
    sudo systemctl enable cysic
    sudo systemctl daemon-reload
    sudo systemctl start cysic

    echo -e "${GREEN}Установка и запуск Cysic завершены!${NC}"
    echo -e "${YELLOW}Просмотреть логи можно командой:${NC} ${CYAN}sudo journalctl -u cysic -f --no-hostname -o cat${NC}"
}

function restart_node {
    echo -e "${BLUE}Перезапускаем ноду Cysic...${NC}"
    sudo systemctl restart cysic
    echo -e "${GREEN}Нода перезапущена.${NC}"
}

function view_logs {
    echo -e "${YELLOW}Просмотр логов (выход CTRL+C):${NC}"
    sudo journalctl -u cysic -f --no-hostname -o cat
}

function remove_node {
    echo -e "${RED}Внимание: это удалит ноду Cysic полностью. Продолжить? (y/n)${NC}"
    read confirm
    if [ "$confirm" == "y" ]; then
        echo -e "${BLUE}Останавливаем и отключаем сервис...${NC}"
        sudo systemctl stop cysic
        sudo systemctl disable cysic

        echo -e "${BLUE}Удаляем файлы ноды...${NC}"
        rm -rf /root/cysic-verifier

        echo -e "${BLUE}Удаляем сервисный файл...${NC}"
        sudo rm /etc/systemd/system/cysic.service
        sudo systemctl daemon-reload
        sudo systemctl reset-failed

        echo -e "${GREEN}Нода Cysic успешно удалена.${NC}"
    else
        echo -e "${YELLOW}Операция отменена.${NC}"
    fi
}

function other_nodes {
    echo -e "${BLUE}Переходим к другим нодам...${NC}"
    # Тут вы можете скачать и запустить ваш общий установщик других нод:
    wget -q -O Ultimative_Node_Installer.sh https://raw.githubusercontent.com/ksydoruk1508/Ultimative_Node_Installer/main/Ultimative_Node_Installer.sh && sudo chmod +x Ultimative_Node_Installer.sh && ./Ultimative_Node_Installer.sh
}

function main_menu {
    while true; do
        echo -e "${YELLOW}Выберите действие:${NC}"
        echo -e "${CYAN}1. Установка ноды Cysic${NC}"
        echo -e "${CYAN}2. Рестарт ноды${NC}"
        echo -e "${CYAN}3. Просмотр логов${NC}"
        echo -e "${CYAN}4. Удаление ноды${NC}"
        echo -e "${CYAN}5. Перейти к другим нодам${NC}"
        echo -e "${CYAN}6. Выход${NC}"
        echo -e " "
        echo -e "${PURPLE}Все текстовые гайды - https://teletype.in/@c6zr7${NC}"
                  
        echo -e "${YELLOW}Введите номер действия:${NC} "
        read choice
        case $choice in
            1) install_node ;;
            2) restart_node ;;
            3) view_logs ;;
            4) remove_node ;;
            5) other_nodes ;;
            6) break ;;
            *) echo -e "${RED}Неверный выбор, попробуйте снова.${NC}" ;;
        esac
    done
}

main_menu
