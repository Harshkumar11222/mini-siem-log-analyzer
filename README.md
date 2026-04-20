# Mini SIEM - Log Analyzer (Python + Flask)

A mini SIEM (Security Information and Event Management) project that parses Linux SSH authentication logs, detects suspicious activities (brute-force attacks, suspicious usernames), assigns risk scores, stores data in SQLite, and provides a Flask web dashboard.

---

## ✅ Features
- Parse SSH auth logs (failed/success logins)
- Detect brute-force attacks (IP-based attempts in a time window)
- Detect suspicious usernames (root/admin/test/guest)
- Risk scoring + flags
- Store logs & alerts in SQLite
- Flask dashboard:
  - Stats view
  - Logs view (filters)
  - Alerts view
- Export reports:
  - `outputs/report.csv`
  - `outputs/alerts_report.csv`

---

## 🧰 Tech Stack
- Python
- SQLite
- Flask
- HTML
- Chart.js (CDN)

---

## 📂 Project Structure
```text
mini-siem-log-analyzer/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── logs/
│   └── sample_auth.log
├── outputs/
│   ├── parsed_logs.json
│   ├── alerts.json
│   ├── report.csv
│   ├── alerts_report.csv
│   └── siem.db
├── src/
│   ├── parser.py
│   ├── detector.py
│   ├── database.py
│   └── report.py
├── templates/
│   ├── index.html
│   ├── logs.html
│   └── alerts.html
└── static/
