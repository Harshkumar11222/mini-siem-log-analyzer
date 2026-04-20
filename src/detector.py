import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime

INPUT_FILE = Path("outputs/parsed_logs.json")
ALERTS_FILE = Path("outputs/alerts.json")

# Settings
BRUTEFORCE_THRESHOLD = 3   # demo ke liye 3 (real world: 10)
TIME_WINDOW_MINUTES = 5

SUSPICIOUS_USERS = {"root", "admin", "test", "guest", "ubuntu"}

def parse_time(ts: str):
    # Add fixed year to avoid ambiguity warning
    ts = "2026 " + ts
    return datetime.strptime(ts, "%Y %b %d %H:%M:%S")


def main():
    if not INPUT_FILE.exists():
        print("❌ parsed_logs.json not found. Run parser first.")
        return

    events = json.loads(INPUT_FILE.read_text(encoding="utf-8"))

    # group failed attempts by IP
    failed_by_ip = defaultdict(list)
    alerts = []

    for e in events:
        # Risk score base
        e["risk_score"] = 0
        e["flags"] = []

        # suspicious username rule
        if e["username"].lower() in SUSPICIOUS_USERS:
            e["risk_score"] += 20
            e["flags"].append("SUSPICIOUS_USERNAME")

        if e["event_type"] == "SSH_FAILED":
            failed_by_ip[e["ip"]].append(parse_time(e["timestamp"]))

    # Brute force rule
    for ip, times in failed_by_ip.items():
        times.sort()

        count = 0
        window_start = None

        for t in times:
            if window_start is None:
                window_start = t
                count = 1
            else:
                diff = (t - window_start).total_seconds() / 60
                if diff <= TIME_WINDOW_MINUTES:
                    count += 1
                else:
                    window_start = t
                    count = 1

            if count >= BRUTEFORCE_THRESHOLD:
                alerts.append({
                    "alert_type": "BRUTE_FORCE",
                    "ip": ip,
                    "attempts": count,
                    "time_window_minutes": TIME_WINDOW_MINUTES,
                    "severity": "HIGH"
                })
                break

    # Add brute force flag to events
    brute_ips = {a["ip"] for a in alerts if a["alert_type"] == "BRUTE_FORCE"}
    for e in events:
        if e["ip"] in brute_ips and e["event_type"] == "SSH_FAILED":
            e["risk_score"] += 50
            e["flags"].append("BRUTE_FORCE_IP")

    ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)

    output = {
        "total_events": len(events),
        "total_alerts": len(alerts),
        "alerts": alerts,
        "events": events
    }

    ALERTS_FILE.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print("✅ Detection complete!")
    print(f"Total alerts: {len(alerts)}")
    print(f"Saved alerts to: {ALERTS_FILE}")

if __name__ == "__main__":
    main()
