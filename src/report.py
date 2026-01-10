import sqlite3
import csv
from pathlib import Path

DB_FILE = Path("outputs/siem.db")
EVENTS_REPORT = Path("outputs/report.csv")
ALERTS_REPORT = Path("outputs/alerts_report.csv")

def export_query_to_csv(conn, query, csv_path):
    cur = conn.cursor()
    cur.execute(query)

    headers = [desc[0] for desc in cur.description]
    rows = cur.fetchall()

    csv_path.parent.mkdir(parents=True, exist_ok=True)

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    return len(rows)

def main():
    if not DB_FILE.exists():
        print("❌ Database not found. Run src\\database.py first.")
        return

    conn = sqlite3.connect(DB_FILE)

    events_count = export_query_to_csv(
        conn,
        """
        SELECT timestamp, event_type, username, ip, risk_score, flags
        FROM events
        ORDER BY id DESC
        """,
        EVENTS_REPORT
    )

    alerts_count = export_query_to_csv(
        conn,
        """
        SELECT alert_type, ip, attempts, time_window_minutes, severity
        FROM alerts
        ORDER BY id DESC
        """,
        ALERTS_REPORT
    )

    conn.close()

    print("✅ Reports Generated!")
    print(f"Events report: {EVENTS_REPORT}")
    print(f"Alerts report: {ALERTS_REPORT}")
    print("\n📊 Summary:")
    print("Total events:", events_count)
    print("Total alerts:", alerts_count)

if __name__ == "__main__":
    main()
