import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

MODEL_FILE = "threat_model.pkl"

# Global variable taaki model sirf ek baar memory me load ho (Optimized for performance)
_CACHED_MODEL = None


def create_training_dataset():
    """Generates synthetic dataset for the SOC AI model training phase."""
    data = {
        "failed_logins": [
            0, 1, 2, 3, 4,
            5, 6, 7, 8, 9,
            10, 15, 20, 25
        ],
        "ports_scanned": [
            0, 0, 1, 1, 2,
            5, 6, 7, 8, 10,
            15, 20, 25, 30
        ],
        "blacklisted_hits": [
            0, 0, 0, 0, 0,
            0, 1, 1, 1, 2,
            2, 3, 4, 5
        ],
        "suspicious_events": [
            0, 0, 0, 1, 1,
            1, 2, 2, 3, 3,
            4, 5, 6, 8
        ],
        "label": [
            "Normal",
            "Normal",
            "Normal",
            "Suspicious",
            "Suspicious",
            "Suspicious",
            "Malicious",
            "Malicious",
            "Malicious",
            "Malicious",
            "Critical",
            "Critical",
            "Critical",
            "Critical"
        ]
    }
    return pd.DataFrame(data)


def train_model():
    """Trains the RandomForest model and serializes it to disk."""
    global _CACHED_MODEL
    df = create_training_dataset()

    X = df[[
        "failed_logins",
        "ports_scanned",
        "blacklisted_hits",
        "suspicious_events"
    ]]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )
    
    model.fit(X_train, y_train)

    # Save to disk
    joblib.dump(model, MODEL_FILE)
    
    # Cache to memory immediately after training
    _CACHED_MODEL = model
    print("AI Threat Model trained and saved successfully.")


def load_model():
    """Loads the model from disk if not cached, trains it if missing."""
    global _CACHED_MODEL
    
    # Agar memory me already loaded hai, toh disk read skipped
    if _CACHED_MODEL is not None:
        return _CACHED_MODEL

    # Agar file disk par nahi hai, toh pehle train karein
    if not os.path.exists(MODEL_FILE):
        train_model()
        return _CACHED_MODEL

    # Disk se load karke cache me save karein
    _CACHED_MODEL = joblib.load(MODEL_FILE)
    return _CACHED_MODEL


def predict_threat(failed_logins, ports_scanned, blacklisted_hits, suspicious_events):
    """Predicts threat severity level based on log signatures."""
    model = load_model()

    # Feature names validation mismatch warning se bachne ke liye DataFrame use kiya
    features_df = pd.DataFrame([{
        "failed_logins": int(failed_logins),
        "ports_scanned": int(ports_scanned),
        "blacklisted_hits": int(blacklisted_hits),
        "suspicious_events": int(suspicious_events)
    }])

    prediction = model.predict(features_df)
    return prediction[0]


if __name__ == "__main__":
    # Script ko standalone run karne par automatic retrain karega
    print("Initializing AI Model Testing Block...")
    train_model()
    
    # Sample dry-run test prediction
    test_prediction = predict_threat(12, 15, 3, 4)
    print(f"Test Evaluation Run Output Level: {test_prediction}")