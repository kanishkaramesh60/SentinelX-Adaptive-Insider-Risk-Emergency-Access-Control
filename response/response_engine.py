from datetime import datetime
import json
import os
BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)
LOG_FILE = os.path.join(
    BASE_DIR,
    "response",
    "response_log.json"
)
def get_response(risk_score):
    if risk_score < 25:
        return {
            "level": "LOW",
            "action": "MONITOR"
        }
    elif risk_score < 50:
        return {
            "level": "MEDIUM",
            "action": "LOG_AND_ALERT"
        }
    elif risk_score < 75:
        return {
            "level": "HIGH",
            "action": "ENHANCED_MONITORING"
        }
    else:
        return {
            "level": "CRITICAL",
            "action": "REQUIRE_SECURITY_REVIEW"
        }
def save_response(
    username,
    risk_score,
    risk_level,
    action
):
    record = {
        "timestamp": datetime.now().isoformat(),
        "username": username,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "action": action
    }
    records = []
    if os.path.exists(LOG_FILE):
        try:
            with open(
                LOG_FILE,
                "r",
                encoding="utf-8"
            ) as file:
                records = json.load(file)
        except Exception:
            records = []
    records.append(record)
    with open(
        LOG_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            records,
            file,
            indent=4
        )
def process_risk(
    username,
    risk_score
):
    response = get_response(
        risk_score
    )
    print("-" * 70)
    print(
        f"USER        : {username}"
    )
    print(
        f"RISK SCORE  : {risk_score}/100"
    )
    print(
        f"RISK LEVEL  : {response['level']}"
    )
    print(
        f"ACTION      : {response['action']}"
    )
    save_response(
        username,
        risk_score,
        response["level"],
        response["action"]
    )
    return response
if __name__ == "__main__":
    print("=" * 70)
    print("SENTINELX - RISK RESPONSE ENGINE")
    print("=" * 70)
    test_scores = [
        15,
        35,
        65,
        90
    ]
    for score in test_scores:
        process_risk(
            "employee_a",
            score
        )
    print("=" * 70)
    print("Response testing completed.")
    print("=" * 70)