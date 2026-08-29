import os
import time
import requests
import psutil
from config import SERVER_URL, DEVICE_ID
SCAN_INTERVAL = 5
def send_event(process_name, pid):
    event = {
        "device_id": DEVICE_ID,
        "username": os.getlogin(),
        "event_type": "process",
        "action": "process_started",
        "resource": process_name,
        "source_ip": "127.0.0.1",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
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
                f"[SENT] PROCESS_STARTED | "
                f"{process_name} | PID={pid}"
            )
        else:
            print(
                f"[SERVER ERROR] HTTP "
                f"{response.status_code}"
            )
    except requests.RequestException as error:
        print(
            f"[CONNECTION ERROR] {error}"
        )
def get_running_processes():
    processes = {}
    for process in psutil.process_iter(
        ["pid", "name"]
    ):
        try:
            pid = process.info["pid"]
            name = process.info["name"]
            if name:
                processes[pid] = name
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied
        ):
            continue
    return processes
def main():
    print("=" * 65)
    print("SENTINELX - PROCESS ACTIVITY MONITOR")
    print("=" * 65)
    print(f"Device: {DEVICE_ID}")
    print(f"Scan interval: {SCAN_INTERVAL} seconds")
    print("Monitoring process creation...")
    print("Press CTRL+C to stop.")
    print("=" * 65)
    previous_processes = set(
        get_running_processes().keys()
    )
    try:
        while True:
            current_processes = get_running_processes()
            current_pids = set(
                current_processes.keys()
            )
            new_processes = (
                current_pids - previous_processes
            )
            for pid in new_processes:
                process_name = current_processes[pid]
                print(
                    f"[DETECTED] PROCESS_STARTED | "
                    f"{process_name} | PID={pid}"
                )
                send_event(
                    process_name,
                    pid
                )
            previous_processes = current_pids
            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        print(
            "\n[SENTINELX] Process monitor stopped."
        )
if __name__ == "__main__":
    main()