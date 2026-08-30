import sqlite3
import csv
import os
from collections import defaultdict
from datetime import datetime, timedelta
from feature_engineering import build_features
BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)
DATABASE = os.path.join(
    BASE_DIR,
    "data.db"
)
OUTPUT_FILE = os.path.join(
    BASE_DIR,
    "ml",
    "data",
    "behavior_dataset.csv"
)
WINDOW_MINUTES = 30
def get_events():
    connection = sqlite3.connect(
        DATABASE
    )
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT
            id,
            device_id,
            username,
            event_type,
            action,
            resource,
            source_ip,
            timestamp,
            risk_score
        FROM security_events
        WHERE username IS NOT NULL
        AND username != 'string'
        AND event_type IS NOT NULL
        AND event_type != 'string'
        AND timestamp IS NOT NULL
        AND timestamp != 'string'
        ORDER BY username, timestamp
        """
    )
    rows = cursor.fetchall()
    connection.close()
    return [dict(row) for row in rows]
def group_events(events):
    groups = defaultdict(list)
    for event in events:
        username = event["username"]
        try:
            timestamp = datetime.fromisoformat(
                event["timestamp"]
            )
        except ValueError:
            continue
        bucket_minute = (
            timestamp.minute
            // WINDOW_MINUTES
        ) * WINDOW_MINUTES
        window_start = timestamp.replace(
            minute=bucket_minute,
            second=0,
            microsecond=0
        )
        key = (
            username,
            window_start
        )
        groups[key].append(event)
    return groups
def calculate_label(events):
    suspicious_indicators = 0
    for event in events:
        event_type = str(
            event.get("event_type", "")
        ).lower()
        action = str(
            event.get("action", "")
        ).lower()
        resource = str(
            event.get("resource", "")
        ).lower()
        if (
            "failed" in action
            or "denied" in action
        ):
            suspicious_indicators += 1
        if "usb" in event_type:
            suspicious_indicators += 1
        if (
            "confidential" in resource
            or "sensitive" in resource
        ):
            suspicious_indicators += 1
        if (
            "powershell" in resource
            or "cmd.exe" in resource
        ):
            suspicious_indicators += 1
    if suspicious_indicators >= 3:
        return 1
    return 0
def main():
    print("=" * 70)
    print("SENTINELX - REAL EVENT DATASET BUILDER")
    print("=" * 70)
    print(
        f"Database: {DATABASE}"
    )
    events = get_events()
    print(
        f"Valid events loaded: {len(events)}"
    )
    if not events:
        print(
            "[ERROR] No valid events found."
        )
        return
    groups = group_events(events)
    print(
        f"Behavior windows created: {len(groups)}"
    )
    rows = []
    for (
        username,
        window_start
    ), window_events in groups.items():
        features = build_features(
            window_events
        )
        features["username"] = username
        features["window_start"] = (
            window_start.isoformat()
        )
        features["event_count"] = len(
            window_events
        )
        features["label"] = calculate_label(
            window_events
        )
        rows.append(features)
    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True
    )
    fieldnames = [
        "username",
        "window_start",
        "total_events",
        "event_count",
        "login_events",
        "failed_logins",
        "file_access_count",
        "confidential_file_access",
        "process_count",
        "usb_connections",
        "usb_disconnections",
        "network_connections",
        "unique_network_destinations",
        "after_hours_events",
        "label"
    ]
    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )
        writer.writeheader()
        writer.writerows(rows)
    normal = sum(
        1
        for row in rows
        if row["label"] == 0
    )
    suspicious = sum(
        1
        for row in rows
        if row["label"] == 1
    )
    print("-" * 70)
    print(
        f"ML samples generated: {len(rows)}"
    )
    print(
        f"Normal samples: {normal}"
    )
    print(
        f"Suspicious samples: {suspicious}"
    )
    print(
        f"Dataset: {OUTPUT_FILE}"
    )
    print("=" * 70)
if __name__ == "__main__":
    main()