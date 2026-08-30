from datetime import datetime
def is_after_hours(timestamp):
    try:
        dt = datetime.fromisoformat(timestamp)
        hour = dt.hour
        if hour < 9 or hour >= 18:
            return 1
        return 0
    except Exception:
        return 0
def build_features(events):
    features = {
        "total_events": 0,
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
        features["total_events"] += 1
        event_type = str(
            event.get("event_type", "")
        ).lower()
        action = str(
            event.get("action", "")
        ).lower()
        resource = str(
            event.get("resource", "")
        ).lower()
        timestamp = event.get(
            "timestamp",
            ""
        )
        if event_type == "login":
            features["login_events"] += 1
            if (
                "fail" in action
                or "failed" in action
            ):
                features["failed_logins"] += 1
        if event_type == "file":
            features["file_access_count"] += 1
            if (
                "confidential" in resource
                or "sensitive" in resource
            ):
                features[
                    "confidential_file_access"
                ] += 1
        if event_type == "process":
            features["process_count"] += 1
        if event_type == "usb":
            if "connected" in action:
                features[
                    "usb_connections"
                ] += 1
            elif "disconnected" in action:
                features[
                    "usb_disconnections"
                ] += 1
        if event_type == "network":
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
            ] += is_after_hours(timestamp)
    features[
        "unique_network_destinations"
    ] = len(network_destinations)
    return features