import os
import joblib
import pandas as pd
BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)
MODEL_FILE = os.path.join(
    BASE_DIR,
    "ml",
    "models",
    "xgboost_risk_model.pkl"
)
FEATURES = [
    "total_events",
    "event_count",
    "login_events",
    "failed_logins",
    "file_access_count",
    "confidential_file_access",
    "process_count",
    "usb_connections",
    "usb_disconnections",
    "network_connections",
    "unique_network_destinations",
    "after_hours_events"
]
def load_model():
    if not os.path.exists(MODEL_FILE):
        raise FileNotFoundError(
            f"Model not found: {MODEL_FILE}"
        )
    return joblib.load(
        MODEL_FILE
    )
def calculate_risk_level(score):
    if score < 25:
        return "LOW"
    elif score < 50:
        return "MEDIUM"
    elif score < 75:
        return "HIGH"
    else:
        return "CRITICAL"
def predict_risk(features):
    model = load_model()
    data = {}
    for feature in FEATURES:
        data[feature] = [
            features.get(feature, 0)
        ]
    dataframe = pd.DataFrame(data)
    probability = model.predict_proba(
        dataframe
    )[0][1]
    risk_score = round(
        probability * 100,
        2
    )
    risk_level = calculate_risk_level(
        risk_score
    )
    return {
        "probability": round(
            float(probability),
            4
        ),
        "risk_score": risk_score,
        "risk_level": risk_level
    }
if __name__ == "__main__":
    print("=" * 70)
    print("SENTINELX - XGBOOST RISK PREDICTION TEST")
    print("=" * 70)
    test_behavior = {
        "total_events": 80,
        "event_count": 80,
        "login_events": 6,
        "failed_logins": 4,
        "file_access_count": 60,
        "confidential_file_access": 30,
        "process_count": 20,
        "usb_connections": 2,
        "usb_disconnections": 2,
        "network_connections": 50,
        "unique_network_destinations": 20,
        "after_hours_events": 25
    }
    result = predict_risk(
        test_behavior
    )
    print(
        f"Probability: "
        f"{result['probability']}"
    )
    print(
        f"Risk Score: "
        f"{result['risk_score']}/100"
    )
    print(
        f"Risk Level: "
        f"{result['risk_level']}"
    )
    print("=" * 70)