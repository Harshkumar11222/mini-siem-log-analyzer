from flask import Flask, render_template, request
import sqlite3
from pathlib import Path
from collections import Counter

DB_FILE = Path("outputs/siem.db")

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    conn = get_db_connection()

    total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    # Top IPs
    top_ips = conn.execute("""
        SELECT ip, COUNT(*) as cnt
        FROM events
        GROUP BY ip
        ORDER BY cnt DESC
        LIMIT 5
    """).fetchall()

    # Event types count for chart
    event_types = conn.execute("""
        SELECT event_type FROM events
    """).fetchall()

    event_counter = Counter([r["event_type"] for r in event_types])

    conn.close()

    chart_labels = list(event_counter.keys())
    chart_values = list(event_counter.values())

    return render_template(
        "index.html",
        total_events=total_events,
        total_alerts=total_alerts,
        top_ips=top_ips,
        chart_labels=chart_labels,
        chart_values=chart_values
    )

@app.route("/logs")
def logs():
    # Filters
    ip_filter = request.args.get("ip", "").strip()
    event_filter = request.args.get("event_type", "").strip()
    min_risk = request.args.get("min_risk", "").strip()

    query = """
        SELECT timestamp, event_type, username, ip, risk_score, flags
        FROM events
        WHERE 1=1
    """
    params = []

    if ip_filter:
        query += " AND ip = ?"
        params.append(ip_filter)

    if event_filter:
        query += " AND event_type = ?"
        params.append(event_filter)

    if min_risk.isdigit():
        query += " AND risk_score >= ?"
        params.append(int(min_risk))

    query += " ORDER BY id DESC LIMIT 200"

    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()

    event_types = conn.execute("SELECT DISTINCT event_type FROM events").fetchall()
    conn.close()

    return render_template(
        "logs.html",
        rows=rows,
        event_types=[r["event_type"] for r in event_types],
        ip_filter=ip_filter,
        event_filter=event_filter,
        min_risk=min_risk
    )

@app.route("/alerts")
def alerts():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT alert_type, ip, attempts, severity
        FROM alerts
        ORDER BY id DESC
    """).fetchall()
    conn.close()
    return render_template("alerts.html", rows=rows)

if __name__ == "__main__":
    app.run(debug=True)
