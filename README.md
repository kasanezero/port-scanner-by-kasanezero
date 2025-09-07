# 🔎 py-port-scanner (v0.3)

A lightweight and educational port scanner written in Python.  
Simple alternative to **nmap**, supporting **TCP connect()**, **SYN**, and **UDP** scans.

---

## 🚀 Features
- **Connect scan** (default) using `socket.connect()`
- **SYN scan** with Scapy (`--method syn`) — requires admin/root
- **UDP scan** (`--method udp`) — basic heuristics
- **Top-1000 TCP preset** (`--top1000`) and `-p @file`
- **NEW (v0.3)**: `--open-only`, colored output, progress bar, output controls, port profiles

---

## 📥 Installation

```bash
python -m venv .venv
# Windows PowerShell:
# .venv\Scripts\Activate.ps1
# Git Bash / Linux / macOS:
# source .venv/bin/activate  OR  source .venv/Scripts/activate
pip install -r requirements.txt
```

> SYN scan needs Scapy and admin/root privileges.

---

## 🛠️ Usage

**Default scan (ports 1–1024, TCP connect):**
```bash
python main.py scanme.nmap.org
```

**Use top-1000 preset:**
```bash
python main.py scanme.nmap.org --top1000
```

**UDP scan (DNS/NTP):**
```bash
python main.py scanme.nmap.org --method udp -p 53,123 --timeout 2
```

**Only show/save open ports:**
```bash
python main.py scanme.nmap.org --top1000 --open-only
```

**Progress bar + colored output:**
```bash
python main.py scanme.nmap.org -p 1-500 --progress
```

**Explicit outputs / no-save:**
```bash
python main.py scanme.nmap.org --json-out data/scan.json --csv-out data/scan.csv
python main.py scanme.nmap.org --no-save
```

**Port profiles (no -p needed):**
```bash
python main.py scanme.nmap.org --web           # 80,443,8080,8443,...
python main.py db.internal --db                # 3306,5432,1433,6379,...
```

---

## 📂 Output
- Console table (with colors if available).
- Files (JSON/CSV) saved to `./data` by default; control with `--json-out`, `--csv-out`, `--no-save`, or `-o PREFIX`.

---

## ⚠️ Notes
- **Connect scan** / **UDP**: no special privileges.
- **SYN scan**: requires raw sockets (admin/root).
- Only scan systems you own or have permission to test. Use `scanme.nmap.org` for safe practice.

---

## 📜 License
MIT
