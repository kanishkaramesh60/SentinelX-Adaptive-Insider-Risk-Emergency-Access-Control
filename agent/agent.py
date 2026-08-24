import time
import psutil
import requests
from datetime import datetime
from config import SERVER_URL, DEVICE_ID, USERNAME
MONITOR_INTERVAL = 2
def send_event(event):
    try:
        response = requests.post(
            SERVER_URL,
            json=event,
            timeout=5
        )
        if response.status_code in (200, 201):
            print(
                f"[SENT] {event['event_type']} | "
                f"{event.get('process_name', '')}"
            )
        else:
            print(
                f"[ERROR] Server returned "
                f"{response.status_code}: {response.text}"
            )
    except requests.exceptions.ConnectionError:
        print("[ERROR] Cannot connect to the server.")
    except requests.exceptions.Timeout:
        print("[ERROR] Request timed out.")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed: {e}")
def get_running_processes():
    processes = {}
    for process in psutil.process_iter(
        ["pid", "name"]
    ):
        try:
            processes[process.info["pid"]] = process.info
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue
    return processes
def create_process_event(process):
    return {
        "event_type": "PROCESS_EXECUTION",
        "device_id": DEVICE_ID,
        "username": USERNAME,
        "action": "EXECUTE",
        "resource": process["name"],
        "source_ip": "127.0.0.1",
        "process_name": process["name"],
        "pid": process["pid"],
        "timestamp": datetime.now().isoformat()
    }
def monitor_processes():
    print("=" * 60)
    print("       INSIDER THREAT MONITORING AGENT")
    print("=" * 60)
    print(f"Device  : {DEVICE_ID}")
    print(f"Username: {USERNAME}")
    print(f"Server  : {SERVER_URL}")
    print("Monitoring process execution...")
    print("Press CTRL+C to stop.")
    print("=" * 60)
    previous_processes = get_running_processes()
    while True:
        time.sleep(MONITOR_INTERVAL)
        current_processes = get_running_processes()
        previous_pids = set(previous_processes.keys())
        current_pids = set(current_processes.keys())
        new_pids = current_pids - previous_pids
        for pid in new_pids:
            process = current_processes[pid]
            event = create_process_event(process)
            print(
                f"[DETECTED] "
                f"{event['process_name']} "
                f"(PID={event['pid']})"
            )
            send_event(event)
        previous_processes = current_processes
if __name__ == "__main__":
    try:
        monitor_processes()
    except KeyboardInterrupt:
        print("\nAgent stopped.")