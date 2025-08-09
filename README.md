# 🛠️ Cysic Verifier Node & Claimer Manager

[![Made with Bash](https://img.shields.io/badge/Made%20with-Bash-1f425f.svg)](https://www.gnu.org/software/bash/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![OS](https://img.shields.io/badge/OS-Ubuntu%2020.04%2F22.04-orange)](https://ubuntu.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

🚀 This script automates the installation, updating, management, and monitoring of the **Cysic Verifier Node**  
along with a built-in **test token claimer**.

Supports a **bilingual interface (RU/EN)** and provides an interactive menu to control both the node and the claimer.

---

## 📌 Features

✅ Install Cysic Node  
🔄 Restart Node  
⬆️ Update Node  
📜 View Node Logs  
🗑 Remove Node  
🎯 Start Test Token Claimer  
📜 View Claimer Logs  
🛑 Stop Claimer  
🌐 RU/EN Interface  
⏳ Automatic 24h Claim Cooldown Handling  

---

## 📋 Requirements

- **Ubuntu 20.04 / 22.04**
- Python **3.10+**
- Packages: `curl`, `git`, `screen`, `python3-pip`, `jq`, `unzip`
- EVM wallet (**address & private key**)
- Cysic invite code (for the claimer)

---

## 🚀 Installation

```bash
# 1. Connect to your server
ssh user@your_server_ip

# 2. Clone the repository
git clone https://github.com/yourname/cysic-verifier-manager.git
cd cysic-verifier-manager

# 3. Make the script executable
chmod +x cysic.sh

# 4. Run it
./cysic.sh
```

---

## 📖 Usage

When you start the script, you’ll see a menu:

```
1. Install Node
2. Restart Node
3. Update Node
4. Node Logs
5. Remove Node
6. Start Claimer
7. Claimer Logs
8. Stop Claimer
9. Exit
```

Choose actions by typing the number.

---

## ⚡ Claimer (claimer.py)

* Automatically binds your invite code
* Claims tokens every **24 hours**
* Respects cooldown if a claim was already made
* Runs inside a `screen` session (`cysic-claimer`)

**Start from menu:**

1. Enter your EVM wallet private key
2. Enter your invite code
3. Runs in background automatically

---

## 📜 Logs

* **Node logs**

  ```bash
  ./cysic.sh → Node Logs
  ```

  or manually:

  ```bash
  screen -r cysic
  ```

* **Claimer logs**

  ```bash
  ./cysic.sh → Claimer Logs
  ```

  or manually:

  ```bash
  screen -r cysic-claimer
  ```

---

## 🛑 Stop

* **Node**

  ```bash
  ./cysic.sh → Stop Node
  ```
* **Claimer**

  ```bash
  ./cysic.sh → Stop Claimer
  ```

---

## 🖤 Authors

* Script & Menu: [ksydoruk1508](https://github.com/ksydoruk1508)
* Updated Claimer with Auto-Timer: ChatGPT + [ksydoruk1508](https://github.com/ksydoruk1508)
* Cysic Project: [app.cysic.xyz](https://app.cysic.xyz)

---

## ⚠️ Disclaimer

This script is provided **"as is"**.
Use at your own risk.
You are solely responsible for the security of your private keys.

---

## 📬 Support & Contacts

💬 Telegram Chat: [@nod3r\_team](https://t.me/nod3r_team)
📢 Telegram Channel: [@nod3r](https://t.me/nod3r)
🤖 Bot: [@wiki\_nod3r\_bot](https://t.me/wiki_nod3r_bot)
💻 GitHub: [ksydoruk1508/GensynNode](https://github.com/ksydoruk1508/GensynNode)

---

**If you have questions or issues — join our Telegram chat or open a GitHub Issue!**

```




# 🛠️ Cysic Verifier Node & Claimer Manager

Этот скрипт автоматизирует установку, обновление, управление и мониторинг **Cysic Verifier Node** и встроенного **тест-токен клеймера**.  
Поддерживает двухъязычный интерфейс (RU/EN) и удобное меню для управления нодой и клеймером.

---

## 📌 Возможности

- **Установка ноды Cysic**
- **Рестарт ноды**
- **Обновление ноды**
- **Просмотр логов ноды**
- **Удаление ноды**
- **Запуск клеймера тестовых токенов**
- **Просмотр логов клеймера**
- **Остановка клеймера**
- **Двухъязычный интерфейс** (русский / английский)
- **Автоматическая обработка таймера 24ч для клейма**

---

## 📋 Требования

- **Ubuntu 20.04 / 22.04**
- Python **3.10+**
- Пакеты: `curl`, `git`, `screen`, `python3-pip`, `jq`, `unzip`
- EVM-кошелёк (адрес и приватный ключ)
- Invite code от Cysic (для клеймера)

---

## 🚀 Установка

1. Подключитесь к серверу по SSH:
````markdown   
   ssh user@your_server_ip
````

2. Скачайте скрипт:

   ```bash
   git clone https://github.com/yourname/cysic-verifier-manager.git
   cd cysic-verifier-manager
   ```

3. Дайте права на запуск:

   ```bash
   chmod +x cysic.sh
   ```

4. Запустите:

   ```bash
   ./cysic.sh
   ```

---

## 📖 Как пользоваться

После запуска появится меню:

```
1. Установить ноду / Install node
2. Рестарт ноды / Restart node
3. Обновление ноды / Update node
4. Логи ноды / Node logs
5. Удалить ноду / Remove node
6. Запустить клеймер / Start claimer
7. Логи клеймера / Claimer logs
8. Остановить клеймер / Stop claimer
9. Выход / Exit
```

Навигация — с помощью ввода номера действия.

---

## ⚡ Клеймер (claimer.py)

* Автоматически привязывает ваш invite code
* Делает запрос на клейм токенов каждые **24 часа**
* Если клейм уже был сделан, учитывает **cooldown** от сервера
* Логи клеймера сохраняются в `screen` сессии `cysic-claimer`

Запуск клеймера из меню:

1. Введите приватный ключ EVM-кошелька
2. Введите invite code
3. Клеймер запустится в фоне

---

## 📜 Логи

* Логи ноды:

  ```bash
  ./cysic.sh → Логи ноды
  ```

  или вручную:

  ```bash
  screen -r cysic
  ```

* Логи клеймера:

  ```bash
  ./cysic.sh → Логи клеймера
  ```

  или вручную:

  ```bash
  screen -r cysic-claimer
  ```

---

## 🛑 Остановка

* Ноды:

  ```bash
  ./cysic.sh → Остановить ноду
  ```

* Клеймера:

  ```bash
  ./cysic.sh → Остановить клеймер
  ```

---

## 🖤 Авторы

* Скрипт и меню: **https://github.com/ksydoruk1508**
* Обновлённый клеймер с авто-таймером: **ChatGPT + (https://github.com/ksydoruk1508)**
* Проект **Cysic**: (https://app.cysic.xyz)

---

## ⚠️ Дисклеймер

Скрипт предоставляется **"как есть"**.
Используйте на свой страх и риск.
Вы несёте ответственность за безопасность приватных ключей.

---

## Поддержка и контакты

* Telegram-чат: [@nod3r\_team](https://t.me/nod3r_team)
* Telegram-канал: [@nod3r](https://t.me/nod3r)
* Бот: [@wiki\_nod3r\_bot](https://t.me/wiki_nod3r_bot)
* GitHub: [ksydoruk1508/GensynNode](https://github.com/ksydoruk1508/GensynNode)

---

**Если возникли вопросы или проблемы — пишите в чат или Issues на GitHub!**
