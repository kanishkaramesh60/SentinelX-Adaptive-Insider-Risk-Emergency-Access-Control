import csv
import os
from feature_engineering import build_features
OUTPUT_FILE = "ml/data/behavior_dataset.csv"
def create_sample_events():
    normal_events = [
        {
            "event_type": "login",
            "action": "login_success",
            "resource": "user",
            "timestamp": "2026-08-30T10:00:00"
        },
        {
            "event_type": "file",
            "action": "file_access",
            "resource": "documents/report.txt",
            "timestamp": "2026-08-30T10:30:00"
        },
        {
            "event_type": "process",
            "action": "process_start",
            "resource": "chrome.exe",
            "timestamp": "2026-08-30T10:35:00"
        },
        {
            "event_type": "network",
            "action": "network_connection",
            "resource": "example.com:443",
            "timestamp": "2026-08-30T10:40:00"
        }
    ]
    suspicious_events = [
        {
            "event_type": "login",
            "action": "login_failed",
            "resource": "user",
            "timestamp": "2026-08-30T02:00:00"
        },
        {
            "event_type": "login",
            "action": "login_failed",
            "resource": "user",
            "timestamp": "2026-08-30T02:01:00"
        },
        {
            "event_type": "file",
            "action": "file_access",
            "resource": "confidential/file1.txt",
            "timestamp": "2026-08-30T02:05:00"
        },
        {
            "event_type": "file",
            "action": "file_access",
            "resource": "confidential/file2.txt",
            "timestamp": "2026-08-30T02:06:00"
        },
        {
            "event_type": "usb",
            "action": "usb_connected",
            "resource": "USB_STORAGE",
            "timestamp": "2026-08-30T02:10:00"
        },
        {
            "event_type": "process",
            "action": "process_start",
            "resource": "powershell.exe",
            "timestamp": "2026-08-30T02:11:00"
        },
        {
            "event_type": "network",
            "action": "network_connection",
            "resource": "unknown-destination:443",
            "timestamp": "2026-08-30T02:12:00"
        }
    ]
    return [
        (normal_events, 0),
        (suspicious_events, 1)
    ]
def main():
    os.makedirs(
        "ml/data",
        exist_ok=True
    )
    samples = create_sample_events()
    rows = []
    for events, label in samples:
        features = build_features(events)
        features["label"] = label
        rows.append(features)
    fieldnames = list(
        rows[0].keys()
    )
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
    print("=" * 65)
    print("SENTINELX - DATASET BUILDER")
    print("=" * 65)
    print(
        f"Dataset created: {OUTPUT_FILE}"
    )
    print(
        f"Samples: {len(rows)}"
    )
    print("=" * 65)
if __name__ == "__main__":
    main()