import json
import sqlite3
from pathlib import Path

ALERTS_FILE = Path("outputs/alerts.json")
DB_FILE = Path("outputs/siem.db")

def init_db(conn):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            username TEXT,
            ip TEXT,
            risk_score INTEGER,
            flags TEXT,
            raw_log TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            ip TEXT,
            attempts INTEGER,
            time_window_minutes INTEGER,
            severity TEXT
        )
    """)
    conn.commit()

def insert_data(conn, data):
    cur = conn.cursor()

    # Insert events
    for e in data["events"]:
        cur.execute("""
            INSERT INTO events (timestamp, event_type, username, ip, risk_score, flags, raw_log)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            e["timestamp"],
            e["event_type"],
            e["username"],
            e["ip"],
            e.get("risk_score", 0),
            ",".join(e.get("flags", [])),
            e["raw_log"]
        ))

    # Insert alerts
    for a in data["alerts"]:
        cur.execute("""
            INSERT INTO alerts (alert_type, ip, attempts, time_window_minutes, severity)
            VALUES (?, ?, ?, ?, ?)
        """, (
            a["alert_type"],
            a["ip"],
            a["attempts"],
            a["time_window_minutes"],
            a["severity"]
        ))

    conn.commit()

def show_summary(conn):
    cur = conn.cursor()

    total_events = cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_alerts = cur.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    top_ip = cur.execute("""
        SELECT ip, COUNT(*) as cnt
        FROM events
        GROUP BY ip
        ORDER BY cnt DESC
        LIMIT 1
    """).fetchone()

    print("\n📊 DB Summary")
    print("Total events:", total_events)
    print("Total alerts:", total_alerts)
    if top_ip:
        print("Top attacker IP:", top_ip[0], "| Attempts:", top_ip[1])

def main():
    if not ALERTS_FILE.exists():
        print("❌ alerts.json not found. Run detector first.")
        return

    data = json.loads(ALERTS_FILE.read_text(encoding="utf-8"))

    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)

    init_db(conn)

    # Clean old data (so re-run doesn't duplicate)
    cur = conn.cursor()
    cur.execute("DELETE FROM events")
    cur.execute("DELETE FROM alerts")
    conn.commit()

    insert_data(conn, data)
    show_summary(conn)

    conn.close()
    print(f"\n✅ Database saved at: {DB_FILE}")

if __name__ == "__main__":
    main()
