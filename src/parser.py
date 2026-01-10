import re
import json
from pathlib import Path

LOG_FILE = Path("logs/sample_auth.log")
OUTPUT_FILE = Path("outputs/parsed_logs.json")

# Regex for ssh auth logs (failed + accepted)
PATTERN = re.compile(
    r"^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed password|Accepted password)\s+for\s+"
    r"(?:(?:invalid user)\s+)?(?P<user>\w+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def parse_line(line: str):
    match = PATTERN.search(line)
    if not match:
        return None

    data = match.groupdict()

    status = data["status"]
    event_type = "SSH_SUCCESS" if "Accepted" in status else "SSH_FAILED"

    return {
        "timestamp": f"{data['month']} {data['day']} {data['time']}",
        "event_type": event_type,
        "username": data["user"],
        "ip": data["ip"],
        "raw_log": line.strip()
    }

def main():
    if not LOG_FILE.exists():
        print(f"❌ Log file not found: {LOG_FILE}")
        return

    events = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            parsed = parse_line(line)
            if parsed:
                events.append(parsed)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        json.dump(events, out, indent=2)

    print("✅ Parsing complete!")
    print(f"Total events parsed: {len(events)}")
    print(f"Saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
