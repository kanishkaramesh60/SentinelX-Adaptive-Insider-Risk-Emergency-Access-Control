import time
import requests
import win32evtlog

from config import SERVER_URL, DEVICE_ID, MONITOR_INTERVAL


SECURITY_LOG = "Security"

EVENT_TYPES = {
    4624: "login_success",
    4625: "login_failed",
    4634: "logout"
}


def send_event(username, action, timestamp):

    event = {
        "device_id": DEVICE_ID,
        "username": username,
        "event_type": "authentication",
        "action": action,
        "resource": "Windows Security Log",
        "source_ip": "N/A",
        "timestamp": timestamp,
        "risk_score": 0
    }

    try:

        response = requests.post(
            SERVER_URL,
            json=event,
            timeout=5
        )

        if response.status_code == 200:

            print(
                f"[SENT] {action} | "
                f"user={username}"
            )

        else:

            print(
                f"[SERVER ERROR] "
                f"{response.status_code}"
            )

    except requests.RequestException as error:

        print(
            f"[CONNECTION ERROR] {error}"
        )


def extract_username(event):

    inserts = event.StringInserts

    if not inserts:
        return "Unknown"

    # For Windows logon events, the account
    # name is commonly located around index 5.

    if len(inserts) > 5:

        username = inserts[5]

        if username and username != "-":
            return username

    return "Unknown"


def read_events():

    handle = win32evtlog.OpenEventLog(
        None,
        SECURITY_LOG
    )

    flags = (
        win32evtlog.EVENTLOG_BACKWARDS_READ
        | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    )

    try:

        events = win32evtlog.ReadEventLog(
            handle,
            flags,
            0
        )

        return events or []

    finally:

        win32evtlog.CloseEventLog(handle)


def monitor():

    print("=" * 60)
    print("SENTINELX - Windows Authentication Monitor")
    print("=" * 60)

    print(f"Device : {DEVICE_ID}")
    print(f"Server : {SERVER_URL}")
    print("Monitoring Windows Security events...")
    print("Press CTRL+C to stop.")
    print("=" * 60)

    processed = set()

    while True:

        try:

            events = read_events()

            for event in reversed(events[:50]):

                record_number = event.RecordNumber

                if record_number in processed:
                    continue

                processed.add(record_number)

                event_id = event.EventID & 0xFFFF

                if event_id not in EVENT_TYPES:
                    continue

                action = EVENT_TYPES[event_id]

                username = extract_username(event)

                timestamp = event.TimeGenerated.isoformat()

                print(
                    f"[DETECTED] "
                    f"EventID={event_id} "
                    f"Action={action} "
                    f"User={username}"
                )

                send_event(
                    username=username,
                    action=action,
                    timestamp=timestamp
                )

            if len(processed) > 500:

                processed = set(
                    list(processed)[-250:]
                )

            time.sleep(MONITOR_INTERVAL)

        except PermissionError:

            print(
                "[PERMISSION ERROR] "
                "Run this terminal as Administrator."
            )

            time.sleep(10)
        except Exception as error:
            print(
                f"[MONITOR ERROR] {error}"
            )
            time.sleep(10)
if __name__ == "__main__":
    try:
        monitor()
    except KeyboardInterrupt:
        print("\nSentinelX monitor stopped.")