import os
import pandas as pd
import joblib
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)
BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)
DATASET = os.path.join(
    BASE_DIR,
    "ml",
    "data",
    "behavior_dataset.csv"
)
MODEL_DIR = os.path.join(
    BASE_DIR,
    "ml",
    "models"
)
MODEL_FILE = os.path.join(
    MODEL_DIR,
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
def main():
    print("=" * 70)
    print("SENTINELX - XGBOOST RISK MODEL TRAINING")
    print("=" * 70)
    if not os.path.exists(DATASET):
        print(
            f"[ERROR] Dataset not found:\n{DATASET}"
        )
        return
    df = pd.read_csv(DATASET)
    print(
        f"[INFO] Dataset samples: {len(df)}"
    )
    missing = [
        feature
        for feature in FEATURES
        if feature not in df.columns
    ]
    if "label" not in df.columns:
        print(
            "[ERROR] label column missing."
        )
        return
    if missing:
        print(
            "[ERROR] Missing features:"
        )
        for feature in missing:
            print(
                f"  - {feature}"
            )
        return
    print("\n[INFO] Class distribution:")
    print(
        df["label"].value_counts()
    )
    X = df[FEATURES]
    y = df["label"]
    X = X.apply(
        pd.to_numeric,
        errors="coerce"
    )
    X = X.fillna(0)
    if y.nunique() < 2:
        print(
            "\n[ERROR] Dataset contains only "
            "one class."
        )
        print(
            "We need both normal (0) and "
            "suspicious (1) samples."
        )
        return
    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=0.25,
            random_state=42,
            stratify=y
        )
    )
    print(
        f"\n[INFO] Training samples: "
        f"{len(X_train)}"
    )
    print(
        f"[INFO] Testing samples: "
        f"{len(X_test)}"
    )
    model = XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=2
    )
    print(
        "\n[INFO] Training XGBoost..."
    )
    model.fit(
        X_train,
        y_train
    )
    print(
        "[INFO] Training completed."
    )
    predictions = model.predict(
        X_test
    )
    probabilities = model.predict_proba(
        X_test
    )[:, 1]
    accuracy = accuracy_score(
        y_test,
        predictions
    )
    print("\n" + "=" * 70)
    print("MODEL EVALUATION")
    print("=" * 70)
    print(
        f"Accuracy: {accuracy:.4f}"
    )
    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0
        )
    )
    print("Confusion Matrix:")
    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )
    print("\nFeature Importance:")
    importance = pd.Series(
        model.feature_importances_,
        index=FEATURES
    ).sort_values(
        ascending=False
    )
    print(
        importance
    )
    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )
    joblib.dump(
        model,
        MODEL_FILE
    )
    print(
        "\n[INFO] Model saved:"
    )
    print(
        MODEL_FILE
    )
    print("=" * 70)
if __name__ == "__main__":
    main()