# 🛡️ SecNews Monitor

**Security News Monitor** — ระบบรวบรวมและติดตามข่าวสาร Cybersecurity จากแหล่งข่าว RSS/Atom ทั่วโลก พร้อมแจ้งเตือนผ่าน Discord และ Telegram

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-7-green?logo=mongodb&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-blue?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## ✨ Features

- 📰 **Multi-source RSS/Atom Feed** — ดึงข่าวจากแหล่งข่าว Security ชั้นนำ เช่น Krebs on Security, The Hacker News, BleepingComputer, CISA, NVD เป็นต้น
- 🔍 **Search & Filter** — ค้นหาข่าวตาม keyword, source, และช่วงวันที่
- 🔔 **Discord & Telegram Notifications** — แจ้งเตือนข่าวใหม่ผ่าน Webhook และ Bot
- ⏰ **Auto Scheduler** — ตั้งเวลาดึงข่าวอัตโนมัติรายวัน (Timezone: Asia/Bangkok)
- 🌐 **Web UI** — หน้าเว็บสำหรับอ่านข่าว จัดการ Sources และตั้งค่าแจ้งเตือน
- 🗄️ **MongoDB Storage** — เก็บข้อมูลข่าวใน MongoDB พร้อม index สำหรับ query ที่รวดเร็ว

---

## 🚀 Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/install/)

### Run with Docker Compose

```bash
# Clone the repository
git clone https://github.com/<your-username>/webmonitor.git
cd webmonitor

# Start the application
docker compose up -d

# Open in browser
open http://localhost:8080
```

### Optional: MongoDB Web UI (for debugging)

```bash
docker compose --profile debug up -d
# Access Mongo Express at http://localhost:8081
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `MONGO_URI` | `mongodb://mongodb:27017` | MongoDB connection URI |
| `MONGO_DB` | `secnews` | Database name |
| `TZ` | `Asia/Bangkok` | Timezone for scheduler |
| `DISCORD_WEBHOOK_URL` | — | Discord Webhook URL (optional) |
| `TELEGRAM_TOKEN` | — | Telegram Bot Token (optional) |
| `TELEGRAM_CHAT_ID` | — | Telegram Chat ID (optional) |

คุณสามารถตั้งค่าผ่านไฟล์ `.env` หรือ environment variables ใน `docker-compose.yml`

---

## 🗂️ Project Structure

```
webmonitor/
├── web.py              # Web server & UI (HTTP handler + embedded HTML/JS)
├── security_news.py    # RSS/Atom feed collector & MongoDB operations
├── notifier.py         # Discord & Telegram notification module
├── scheduler.py        # APScheduler auto-fetch scheduler
├── requirements.txt    # Python dependencies
├── Dockerfile          # Container build instructions
├── docker-compose.yml  # Multi-service orchestration
└── README.md
```

---

## 📡 Default RSS/Atom Sources

| Source | URL |
|---|---|
| Krebs on Security | krebsonsecurity.com |
| The Hacker News | thehackernews.com |
| BleepingComputer | bleepingcomputer.com |
| SecurityWeek | securityweek.com |
| Dark Reading | darkreading.com |
| CISA Advisories | cisa.gov |
| NVD Recent CVEs | nvd.nist.gov |
| Schneier on Security | schneier.com |
| SANS Internet Stormcast | isc.sans.edu |
| TechTalkThai Security | techtalkthai.com |
| *...and more* | |

สามารถเพิ่ม/ลบ/แก้ไข sources ได้ผ่านหน้า **Manage Sources** บน Web UI

---

## 🖥️ CLI Usage

นอกจาก Web UI แล้ว ยังสามารถใช้ command line ได้:

```bash
# Fetch articles from all enabled feeds
python3 security_news.py fetch

# Fetch from specific source
python3 security_news.py fetch --source "Krebs"

# List recent articles
python3 security_news.py list --limit 20

# Search articles
python3 security_news.py list --search "ransomware"

# Show statistics
python3 security_news.py stats

# Export to JSON
python3 security_news.py export --output backup.json

# List configured sources
python3 security_news.py sources
```

---

## 🔔 Notifications Setup

### Discord
1. ไปที่ Discord Server → **Settings** → **Integrations** → **Webhooks**
2. สร้าง Webhook ใหม่ → คัดลอก URL
3. วาง URL ในหน้า **Notifications** บน Web UI

### Telegram
1. สร้าง Bot ผ่าน [@BotFather](https://t.me/BotFather) → `/newbot`
2. คัดลอก Bot Token
3. ส่งข้อความถึง Bot แล้วใช้ปุ่ม **Find my Chat ID** บน Web UI
4. กรอก Token และ Chat ID ในหน้า **Notifications**

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
