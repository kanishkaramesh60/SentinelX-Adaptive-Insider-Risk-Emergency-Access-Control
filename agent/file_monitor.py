import os
import time
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from config import SERVER_URL, DEVICE_ID
WATCH_DIRECTORY = r"D:\CyberProjects\insider-threat-system\test_data"
def get_file_sensitivity(path):
    path_lower = path.lower()
    if "\\confidential\\" in path_lower:
        return "confidential"
    if "\\internal\\" in path_lower:
        return "internal"
    if "\\public\\" in path_lower:
        return "public"
    return "unknown"
class FileActivityHandler(FileSystemEventHandler):
    def send_event(self, action, path):
        sensitivity = get_file_sensitivity(path)
        event = {
            "device_id": DEVICE_ID,
            "username": os.getlogin(),
            "event_type": "file",
            "action": action,
            "resource": path,
            "source_ip": "N/A",
            "timestamp": time.strftime(
                "%Y-%m-%dT%H:%M:%S"
            ),
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
                    f"[SENT] "
                    f"{action} | "
                    f"sensitivity={sensitivity} | "
                    f"{path}"
                )
            else:
                print(
                    f"[SERVER ERROR] "
                    f"HTTP {response.status_code}"
                )
        except requests.RequestException as error:
            print(
                f"[CONNECTION ERROR] {error}"
            )
    def on_created(self, event):
        if event.is_directory:
            return
        print(
            f"[DETECTED] FILE_CREATED | "
            f"{event.src_path}"
        )
        self.send_event(
            "file_created",
            event.src_path
        )
    def on_modified(self, event):
        if event.is_directory:
            return
        print(
            f"[DETECTED] FILE_MODIFIED | "
            f"{event.src_path}"
        )
        self.send_event(
            "file_modified",
            event.src_path
        )
    def on_deleted(self, event):
        if event.is_directory:
            return
        print(
            f"[DETECTED] FILE_DELETED | "
            f"{event.src_path}"
        )
        self.send_event(
            "file_deleted",
            event.src_path
        )
    def on_moved(self, event):
        if event.is_directory:
            return
        print(
            f"[DETECTED] FILE_MOVED | "
            f"{event.src_path}"
        )
        self.send_event(
            "file_moved",
            event.dest_path
        )
def main():
    print("=" * 65)
    print("SENTINELX - FILE ACTIVITY MONITOR")
    print("=" * 65)
    print(f"Device: {DEVICE_ID}")
    print(
        f"Monitoring: {WATCH_DIRECTORY}"
    )
    print("Press CTRL+C to stop.")
    print("=" * 65)
    if not os.path.exists(WATCH_DIRECTORY):
        print(
            "[ERROR] Monitoring directory does not exist."
        )
        return
    handler = FileActivityHandler()
    observer = Observer()
    observer.schedule(
        handler,
        WATCH_DIRECTORY,
        recursive=True
    )
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print(
            "\n[SENTINELX] File monitor stopped."
        )
    observer.join()
if __name__ == "__main__":
    main()