from flask import Flask, render_template, request
import sqlite3
from pathlib import Path
from collections import Counter
# import streamlit as st
# st.write("SIEM Dashboard Running ✅")


# st.title("Mini SIEM Log Analyzer")

# uploaded_file = st.file_uploader("Upload Log File", type=["log", "txt"])

# if uploaded_file is not None:
#     st.success("Log file uploaded successfully!")

#     logs = uploaded_file.read().decode("utf-8").splitlines()

#     st.subheader("First 10 Log Lines")
#     for line in logs[:10]:
#         st.text(line)

#     failed_attempts = [line for line in logs if "Failed" in line or "failed" in line]

#     st.subheader("Detected Failed Login Attempts")
#     st.write(f"Total Failed Attempts: {len(failed_attempts)}")


# if uploaded_file is not None:
#     st.success("Log file uploaded successfully!")

#     logs = uploaded_file.read().decode("utf-8").splitlines()

#     st.subheader("📄 First 10 Log Entries")
#     st.code("\n".join(logs[:10]), language="text")

#     # Example Detection Rule — Failed Logins
#     failed_logins = [line for line in logs if "Failed password" in line or "failed login" in line.lower()]

#     st.subheader("🚨 Security Alerts")

#     if failed_logins:
#         st.error(f"⚠️ Detected {len(failed_logins)} Failed Login Attempts (Possible Brute Force)")
#         with st.expander("Show Failed Login Logs"):
#             for log in failed_logins[:20]:
#                 st.text(log)
#     else:
#         st.success("✅ No failed login attacks detected")


import streamlit as st
import re
from collections import Counter
import pandas as pd

st.title("Mini SIEM Log Analyzer")
st.write("SIEM Dashboard Running ✅")

uploaded_file = st.file_uploader("Upload Log File", type=["log", "txt"])

if uploaded_file is not None:
    st.success("Log file uploaded successfully!")

    content = uploaded_file.read().decode("utf-8")
    logs = content.splitlines()

    st.subheader("📄 First 10 Log Entries")
    st.code("\n".join(logs[:10]), language="text")

    # 🚨 Failed Login Detection
    failed_logins = [line for line in logs if "failed" in line.lower()]
    st.subheader("🚨 Security Alerts")

    if failed_logins:
        st.error(f"⚠️ Detected {len(failed_logins)} Failed Login Attempts")
    else:
        st.success("✅ No failed login attacks detected")

    # 🌍 Top IPs
    ips = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', content)
    top_ips = Counter(ips).most_common(5)

    st.subheader("🌍 Top IP Addresses")
    st.table(top_ips)

    # 📊 Login Chart
    failed = len([l for l in logs if "failed" in l.lower()])
    success = len([l for l in logs if "success" in l.lower()])

    st.subheader("📊 Login Activity")
    st.bar_chart({"Failed": failed, "Successful": success})

    # ⬇ Download Report
    df = pd.DataFrame(logs, columns=["Log Entries"])
    st.download_button("⬇ Download Logs", df.to_csv(index=False), "report.csv")



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
