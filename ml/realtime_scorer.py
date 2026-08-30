import os
import sqlite3
import joblib
import pandas as pd
from datetime import datetime, timedelta
BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)
DATABASE = os.path.join(
    BASE_DIR,
    "data.db"
)
MODEL_FILE = os.path.join(
    BASE_DIR,
    "ml",
    "models",
    "xgboost_risk_model.pkl"
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
def load_model():
    if not os.path.exists(MODEL_FILE):
        raise FileNotFoundError(
            f"Model not found: {MODEL_FILE}"
        )
    return joblib.load(
        MODEL_FILE
    )
def get_recent_events(username=None, minutes=30):
    connection = sqlite3.connect(
        DATABASE
    )
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    if username:
        cursor.execute(
            """
            SELECT *
            FROM security_events
            WHERE username = ?
            ORDER BY timestamp DESC
            """,
            (username,)
        )
    else:
        cursor.execute(
            """
            SELECT *
            FROM security_events
            ORDER BY timestamp DESC
            """
        )
    rows = cursor.fetchall()
    connection.close()
    return [dict(row) for row in rows]
def is_after_hours(timestamp):
    try:
        dt = datetime.fromisoformat(
            timestamp
        )
        return int(
            dt.hour < 9 or dt.hour >= 18
        )
    except Exception:
        return 0
def build_features(events):
    features = {
        "total_events": 0,
        "event_count": 0,
        "login_events": 0,
        "failed_logins": 0,
        "file_access_count": 0,
        "confidential_file_access": 0,
        "process_count": 0,
        "usb_connections": 0,
        "usb_disconnections": 0,
        "network_connections": 0,
        "unique_network_destinations": 0,
        "after_hours_events": 0
    }
    network_destinations = set()
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
        timestamp = str(
            event.get("timestamp", "")
        )
        features["total_events"] += 1
        features["event_count"] += 1
        if (
            "login" in event_type
            or "authentication" in event_type
        ):
            features["login_events"] += 1
            if (
                "fail" in action
                or "denied" in action
            ):
                features["failed_logins"] += 1
        if (
            "file" in event_type
            or "file" in action
        ):
            features[
                "file_access_count"
            ] += 1
            if (
                "confidential" in resource
                or "sensitive" in resource
                or "secret" in resource
            ):
                features[
                    "confidential_file_access"
                ] += 1
        if (
            "process" in event_type
            or "execute" in action
        ):
            features[
                "process_count"
            ] += 1
        if "usb" in event_type:
            if "connect" in action:
                features[
                    "usb_connections"
                ] += 1
            if "disconnect" in action:
                features[
                    "usb_disconnections"
                ] += 1
        if (
            "network" in event_type
            or "network" in action
        ):
            features[
                "network_connections"
            ] += 1
            if resource:
                network_destinations.add(
                    resource
                )
        if timestamp:
            features[
                "after_hours_events"
            ] += is_after_hours(
                timestamp
            )
    features[
        "unique_network_destinations"
    ] = len(
        network_destinations
    )
    return features
def calculate_risk(features):
    model = load_model()
    data = {
        feature: [
            features.get(feature, 0)
        ]
        for feature in FEATURES
    }
    dataframe = pd.DataFrame(data)
    probability = model.predict_proba(
        dataframe
    )[0][1]
    risk_score = round(
        float(probability * 100),
        2
    )
    if risk_score < 25:
        risk_level = "LOW"
    elif risk_score < 50:
        risk_level = "MEDIUM"
    elif risk_score < 75:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"
    return {
        "probability": round(
            float(probability),
            4
        ),
        "risk_score": risk_score,
        "risk_level": risk_level
    }
def main():
    print("=" * 70)
    print("SENTINELX - REAL-TIME ML RISK SCORER")
    print("=" * 70)
    print(
        f"Database: {DATABASE}"
    )
    events = get_recent_events()
    print(
        f"Events found: {len(events)}"
    )
    if not events:
        print(
            "[WARNING] No security events found."
        )
        return
    users = {}
    for event in events:
        username = event.get(
            "username",
            "unknown"
        )
        if username not in users:
            users[username] = []
        users[username].append(
            event
        )
    print(
        f"Users found: {len(users)}"
    )
    print()
    for username, user_events in users.items():
        features = build_features(
            user_events
        )
        result = calculate_risk(
            features
        )
        print("-" * 70)
        print(
            f"USER: {username}"
        )
        print(
            f"Events: {len(user_events)}"
        )
        print(
            f"Probability: "
            f"{result['probability']}"
        )
        print(
            f"Risk Score: "
            f"{result['risk_score']}/100"
        )
        print(
            f"Risk Level: "
            f"{result['risk_level']}"
        )
        print()
        print("Behavior Features:")
        for feature, value in features.items():
            print(
                f"  {feature}: {value}"
            )
    print("=" * 70)
if __name__ == "__main__":
    main()