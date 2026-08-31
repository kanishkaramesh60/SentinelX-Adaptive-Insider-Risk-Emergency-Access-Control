import json
import os
from datetime import datetime
from emergency.auth import (
    verify_password,
    generate_otp,
    verify_otp
)
BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)
AUDIT_FILE = os.path.join(
    BASE_DIR,
    "emergency",
    "emergency_audit.json"
)
def save_audit(record):
    records = []
    if os.path.exists(AUDIT_FILE):
        try:
            with open(
                AUDIT_FILE,
                "r",
                encoding="utf-8"
            ) as file:
                records = json.load(file)
        except Exception:
            records = []
    records.append(record)
    with open(
        AUDIT_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            records,
            file,
            indent=4
        )
def emergency_access(
    username,
    password,
    resource
):
    print()
    print("=" * 70)
    print("SENTINELX - EMERGENCY ACCESS")
    print("=" * 70)
    print(
        f"User     : {username}"
    )
    print(
        f"Resource : {resource}"
    )
    print()
    print(
        "[1/2] Verifying primary authentication..."
    )
    if not verify_password(
        username,
        password
    ):
        print(
            "[DENIED] Primary authentication failed."
        )
        save_audit({
            "timestamp":
                datetime.now().isoformat(),
            "username":
                username,
            "resource":
                resource,
            "result":
                "DENIED",
            "reason":
                "PRIMARY_AUTH_FAILED"
        })
        return False
    print(
        "[SUCCESS] Primary authentication passed."
    )
    print()
    print(
        "[2/2] Generating second-factor OTP..."
    )
    otp = generate_otp()
    print(
        f"[DEMO OTP] {otp}"
    )
    entered_otp = input(
        "Enter OTP: "
    ).strip()
    if not verify_otp(
        otp,
        entered_otp
    ):
        print(
            "[DENIED] Second authentication failed."
        )
        save_audit({
            "timestamp":
                datetime.now().isoformat(),
            "username":
                username,
            "resource":
                resource,
            "result":
                "DENIED",
            "reason":
                "SECOND_FACTOR_FAILED"
        })
        return False
    print(
        "[SUCCESS] Second authentication passed."
    )
    print()
    print(
        "[GRANTED] Emergency access approved."
    )
    print(
        "[MONITORING] Enhanced monitoring enabled."
    )
    save_audit({
        "timestamp":
            datetime.now().isoformat(),
        "username":
            username,
        "resource":
            resource,
        "result":
            "GRANTED",
        "reason":
            "EMERGENCY_ACCESS_APPROVED",
        "enhanced_monitoring":
            True
    })
    return True
if __name__ == "__main__":
    print("=" * 70)
    print("SENTINELX - EMERGENCY ACCESS TEST")
    print("=" * 70)
    username = input(
        "Username: "
    ).strip()
    password = input(
        "Password: "
    ).strip()
    resource = input(
        "Resource to access: "
    ).strip()
    emergency_access(
        username,
        password,
        resource
    )
    print("=" * 70)