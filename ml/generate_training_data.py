import os
import random
import pandas as pd
BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)
OUTPUT_FILE = os.path.join(
    BASE_DIR,
    "ml",
    "data",
    "behavior_dataset.csv"
)
FEATURES = [
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
    "after_hours_events"
]
def normal_sample():
    file_access = random.randint(2, 15)
    return {
        "total_events": random.randint(10, 40),
        "event_count": random.randint(10, 40),
        "login_events": random.randint(1, 3),
        "failed_logins": 0,
        "file_access_count": file_access,
        "confidential_file_access": random.randint(
            0,
            min(2, file_access)
        ),
        "process_count": random.randint(5, 20),
        "usb_connections": random.choice([0, 0, 0, 1]),
        "usb_disconnections": random.choice([0, 0, 0, 1]),
        "network_connections": random.randint(5, 30),
        "unique_network_destinations": random.randint(1, 10),
        "after_hours_events": random.randint(0, 2),
        "label": 0
    }
def failed_login_sample():
    return {
        "total_events": random.randint(15, 35),
        "event_count": random.randint(15, 35),
        "login_events": random.randint(5, 12),
        "failed_logins": random.randint(4, 10),
        "file_access_count": random.randint(1, 8),
        "confidential_file_access": random.randint(0, 2),
        "process_count": random.randint(5, 15),
        "usb_connections": 0,
        "usb_disconnections": 0,
        "network_connections": random.randint(5, 20),
        "unique_network_destinations": random.randint(1, 8),
        "after_hours_events": random.randint(0, 5),
        "label": 1
    }
def data_exfiltration_sample():
    confidential = random.randint(15, 60)
    return {
        "total_events": random.randint(40, 100),
        "event_count": random.randint(40, 100),
        "login_events": random.randint(1, 4),
        "failed_logins": random.randint(0, 2),
        "file_access_count": random.randint(40, 100),
        "confidential_file_access": confidential,
        "process_count": random.randint(10, 30),
        "usb_connections": random.choice([0, 1, 1]),
        "usb_disconnections": random.choice([0, 1]),
        "network_connections": random.randint(30, 80),
        "unique_network_destinations": random.randint(10, 30),
        "after_hours_events": random.randint(0, 20),
        "label": 1
    }
def usb_exfiltration_sample():
    return {
        "total_events": random.randint(30, 80),
        "event_count": random.randint(30, 80),
        "login_events": random.randint(1, 4),
        "failed_logins": random.randint(0, 2),
        "file_access_count": random.randint(20, 60),
        "confidential_file_access": random.randint(10, 40),
        "process_count": random.randint(10, 25),
        "usb_connections": random.randint(1, 3),
        "usb_disconnections": random.randint(1, 3),
        "network_connections": random.randint(15, 50),
        "unique_network_destinations": random.randint(5, 20),
        "after_hours_events": random.randint(5, 30),
        "label": 1
    }
def after_hours_sample():
    return {
        "total_events": random.randint(20, 60),
        "event_count": random.randint(20, 60),
        "login_events": random.randint(2, 6),
        "failed_logins": random.randint(0, 3),
        "file_access_count": random.randint(10, 40),
        "confidential_file_access": random.randint(5, 25),
        "process_count": random.randint(8, 25),
        "usb_connections": random.choice([0, 1, 1]),
        "usb_disconnections": random.choice([0, 1]),
        "network_connections": random.randint(15, 50),
        "unique_network_destinations": random.randint(5, 20),
        "after_hours_events": random.randint(15, 50),
        "label": 1
    }
def suspicious_combination_sample():
    return {
        "total_events": random.randint(70, 150),
        "event_count": random.randint(70, 150),
        "login_events": random.randint(4, 10),
        "failed_logins": random.randint(3, 8),
        "file_access_count": random.randint(50, 120),
        "confidential_file_access": random.randint(20, 80),
        "process_count": random.randint(20, 50),
        "usb_connections": random.randint(1, 3),
        "usb_disconnections": random.randint(1, 3),
        "network_connections": random.randint(40, 100),
        "unique_network_destinations": random.randint(15, 40),
        "after_hours_events": random.randint(20, 70),
        "label": 1
    }
def main():
    print("=" * 70)
    print("SENTINELX - TRAINING DATA GENERATOR")
    print("=" * 70)
    random.seed(42)
    samples = []
    for _ in range(300):
        samples.append(
            normal_sample()
        )
    for _ in range(100):
        samples.append(
            failed_login_sample()
        )
    for _ in range(100):
        samples.append(
            data_exfiltration_sample()
        )
    for _ in range(100):
        samples.append(
            usb_exfiltration_sample()
        )
    for _ in range(100):
        samples.append(
            after_hours_sample()
        )
    for _ in range(100):
        samples.append(
            suspicious_combination_sample()
        )
    random.shuffle(samples)
    df = pd.DataFrame(samples)
    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True
    )
    df.to_csv(
        OUTPUT_FILE,
        index=False
    )
    print(
        f"[INFO] Dataset created: {OUTPUT_FILE}"
    )
    print(
        f"[INFO] Total samples: {len(df)}"
    )
    print("\nClass distribution:")
    print(
        df["label"].value_counts()
    )
    print("\nFeature columns:")
    for column in FEATURES:
        print(
            f"  - {column}"
        )
    print("=" * 70)
if __name__ == "__main__":
    main()