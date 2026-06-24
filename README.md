# Blessy-beaulah-0210
intrusion detection system snort
import re
from collections import Counter

ALERT_FILE = "sample_alerts.txt"

def parse_snort_alerts(file_path):
    alerts = []

    try:
        with open(file_path, "r") as file:
            data = file.readlines()

        for line in data:
            match = re.search(r'\[\*\*\] \[(.*?)\] (.*?) \[\*\*\]', line)

            if match:
                rule_id = match.group(1)
                alert_msg = match.group(2)

                alerts.append({
                    "Rule ID": rule_id,
                    "Alert Message": alert_msg
                })

        return alerts

    except FileNotFoundError:
        print("Alert file not found.")
        return []

def display_alerts(alerts):
    print("\n===== SNORT ALERT REPORT =====")

    if not alerts:
        print("No alerts found.")
        return

    for i, alert in enumerate(alerts, start=1):
        print(f"\nAlert {i}")
        print(f"Rule ID      : {alert['Rule ID']}")
        print(f"Description  : {alert['Alert Message']}")

def generate_statistics(alerts):
    attack_types = [alert["Alert Message"] for alert in alerts]
    stats = Counter(attack_types)

    print("\n===== ATTACK STATISTICS =====")

    for attack, count in stats.items():
        print(f"{attack}: {count}")

def main():
    alerts = parse_snort_alerts(ALERT_FILE)

    display_alerts(alerts)

    generate_statistics(alerts)

if __name__ == "__main__":
    main()
[**] [1:1000001:1] ICMP Ping Detected [**]
[Priority: 3]

[**] [1:1000002:1] Port Scan Detected [**]
[Priority: 2]

[**] [1:1000003:1] SQL Injection Attempt [**]
[Priority: 1]

[**] [1:1000002:1] Port Scan Detected [**]
[Priority: 2]

[**] [1:1000001:1] ICMP Ping Detected [**]
[Priority: 3]
No external libraries required
# Intrusion Detection System using Snort

## Objective
Monitor and analyze Snort IDS alerts using Python.

## Features
- Reads Snort alert logs
- Extracts attack details
- Displays alert reports
- Generates attack statistics

## Technologies Used
- Python 3
- Snort IDS

## How to Run

1. Install Python.
2. Place alert logs in sample_alerts.txt.
3. Run:

python snort_alert_monitor.py

## Output
- Alert details
- Attack frequency report