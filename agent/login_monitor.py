import time
from datetime import datetime
import requests
import win32evtlog
from config import SERVER_URL, DEVICE_ID, MONITOR_INTERVAL 
SECURITY_LOG = "Security"
LOGIN_EVENTS = {
    4624: "login_success",
    4625: "login_failed",
    4634: "logout"
}
def send_event(
    event_type,
    action,
    username,
    timestamp
):
    event = {
        "device_id": DEVICE_ID,
        "username": username,
        "event_type": event_type,
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
                f"[ERROR] Server returned "
                f"{response.status_code}"
            )
    except requests.RequestException as error:
        print(
            f"[ERROR] Could not contact server: {error}"
        )
def get_username(event):
    inserts = event.StringInserts
    if not inserts:
        return "Unknown"
    if len(inserts) > 5:
        username = inserts[5]
        if username and username != "-":
            return username
    return "Unknown"
def read_security_events():
    handle = win32evtlog.OpenEventLog(
        None,
        SECURITY_LOG
    )
    flags = (
        win32evtlog.EVENTLOG_BACKWARDS_READ
        | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    )
    events = []
    try:
        records = win32evtlog.ReadEventLog(
            handle,
            flags,
            0
        )
        if records:
            events = records[:20]
    finally:
        win32evtlog.CloseEventLog(handle)
    return events
def monitor():
    print("=" * 60)
    print("Windows Authentication Monitor")
    print("=" * 60)
    print(f"Device ID : {DEVICE_ID}")
    print(f"Server    : {SERVER_URL}")
    print("Monitoring Windows Security events...")
    print("Press CTRL+C to stop.")
    print("=" * 60)
    processed_records = set()
    while True:
        try:
            events = read_security_events()
            for event in reversed(events):
                record_id = event.RecordNumber
                if record_id in processed_records:
                    continue
                processed_records.add(record_id)
                event_id = event.EventID & 0xFFFF
                if event_id not in LOGIN_EVENTS:
                    continue
                action = LOGIN_EVENTS[event_id]
                username = get_username(event)
                event_time = event.TimeGenerated
                timestamp = event_time.isoformat()
                print(
                    f"[DETECTED] "
                    f"EventID={event_id} "
                    f"Action={action} "
                    f"User={username}"
                )
                send_event(
                    event_type="authentication",
                    action=action,
                    username=username,
                    timestamp=timestamp
                )
            if len(processed_records) > 500:
                processed_records = set(
                    list(processed_records)[-250:]
                )
            time.sleep(MONITOR_INTERVAL)
        except PermissionError:
            print(
                "[ERROR] Permission denied while "
                "reading Windows Security Log."
            )
            print(
                "Run PowerShell as Administrator."
            )
            time.sleep(10)
        except Exception as error:
            print(
                f"[ERROR] Monitoring error: {error}"
            )
            time.sleep(10)
if __name__ == "__main__":
    try:
        monitor()
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")