import os
import time
import requests
import win32com.client
from config import SERVER_URL, DEVICE_ID
CHECK_INTERVAL = 5
def get_usb_devices():
    devices = set()
    try:
        wmi = win32com.client.GetObject(
            "winmgmts:"
        )
        usb_devices = wmi.ExecQuery(
            "SELECT DeviceID, PNPDeviceID "
            "FROM Win32_DiskDrive "
            "WHERE InterfaceType='USB'"
        )
        for device in usb_devices:
            identifier = (
                getattr(device, "PNPDeviceID", None)
                or getattr(device, "DeviceID", None)
            )
            if identifier:
                devices.add(identifier)
    except Exception as error:
        print(
            f"[USB ERROR] {error}"
        )
    return devices
def send_event(action, device_id):
    event = {
        "device_id": DEVICE_ID,
        "username": os.getlogin(),
        "event_type": "usb",
        "action": action,
        "resource": device_id,
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
                f"[SENT] {action} | "
                f"{device_id}"
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
def main():
    print("=" * 65)
    print("SENTINELX - USB DEVICE MONITOR")
    print("=" * 65)
    print(f"Device: {DEVICE_ID}")
    print(
        f"Check interval: {CHECK_INTERVAL} seconds"
    )
    print(
        "Monitoring USB storage devices..."
    )
    print("Press CTRL+C to stop.")
    print("=" * 65)
    previous_devices = get_usb_devices()
    print(
        f"[INFO] Initial USB devices: "
        f"{len(previous_devices)}"
    )
    try:
        while True:
            current_devices = get_usb_devices()
            added_devices = (
                current_devices - previous_devices
            )
            removed_devices = (
                previous_devices - current_devices
            )
            for usb in added_devices:
                print(
                    f"[DETECTED] USB_CONNECTED | "
                    f"{usb}"
                )
                send_event(
                    "usb_connected",
                    usb
                )
            for usb in removed_devices:
                print(
                    f"[DETECTED] USB_DISCONNECTED | "
                    f"{usb}"
                )
                send_event(
                    "usb_disconnected",
                    usb
                )
            previous_devices = current_devices
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        print(
            "\n[SENTINELX] USB monitor stopped."
        )
if __name__ == "__main__":
    main()