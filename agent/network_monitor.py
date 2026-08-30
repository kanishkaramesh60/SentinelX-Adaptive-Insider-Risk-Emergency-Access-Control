import os
import time
import requests
import psutil
from config import SERVER_URL, DEVICE_ID
SCAN_INTERVAL = 5
def get_username():
    try:
        return os.getlogin()
    except OSError:
        return os.environ.get(
            "USERNAME",
            "unknown"
        )
def get_connections():
    connections = []
    try:
        for conn in psutil.net_connections(
            kind="inet"
        ):
            if conn.status != psutil.CONN_ESTABLISHED:
                continue
            if not conn.raddr:
                continue
            local_ip = conn.laddr.ip
            local_port = conn.laddr.port
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            pid = conn.pid
            process_name = "unknown"
            if pid:
                try:
                    process_name = (
                        psutil.Process(pid).name()
                    )
                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied
                ):
                    pass
            connections.append(
                {
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "pid": pid,
                    "process_name": process_name
                }
            )
    except Exception as error:
        print(
            f"[NETWORK ERROR] {error}"
        )
    return connections
def connection_key(connection):
    return (
        connection["local_ip"],
        connection["local_port"],
        connection["remote_ip"],
        connection["remote_port"],
        connection["pid"]
    )
def send_event(connection):
    remote_ip = connection["remote_ip"]
    remote_port = connection["remote_port"]
    process_name = connection["process_name"]
    event = {
        "device_id": DEVICE_ID,
        "username": get_username(),
        "event_type": "network",
        "action": "network_connection",
        "resource": (
            f"{remote_ip}:{remote_port}"
        ),
        "source_ip": connection["local_ip"],
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
                f"[SENT] NETWORK_CONNECTION | "
                f"{process_name} | "
                f"{remote_ip}:{remote_port}"
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
    print("=" * 70)
    print("SENTINELX - NETWORK ACTIVITY MONITOR")
    print("=" * 70)
    print(
        f"Device: {DEVICE_ID}"
    )
    print(
        f"Scan interval: {SCAN_INTERVAL} seconds"
    )
    print(
        "Monitoring established network connections..."
    )
    print(
        "Press CTRL+C to stop."
    )
    print("=" * 70)
    previous_connections = set()
    try:
        while True:
            connections = get_connections()
            current_connections = {
                connection_key(connection)
                for connection in connections
            }
            new_connections = (
                current_connections
                - previous_connections
            )
            for connection in connections:
                key = connection_key(connection)
                if key in new_connections:
                    print(
                        f"[DETECTED] NETWORK_CONNECTION | "
                        f"{connection['process_name']} | "
                        f"{connection['remote_ip']}:"
                        f"{connection['remote_port']}"
                    )
                    send_event(connection)
            previous_connections = (
                current_connections
            )
            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        print(
            "\n[SENTINELX] Network monitor stopped."
        )
if __name__ == "__main__":
    main()