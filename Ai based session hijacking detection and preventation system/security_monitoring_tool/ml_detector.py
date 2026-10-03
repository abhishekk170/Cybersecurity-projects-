"""
NovaBank Security Monitoring Agent - ML Anomaly Detector

WHAT THIS DOES:
  Trains an Isolation Forest on the session dataset to learn what
  "normal" session behavior looks like. Any session that differs
  significantly from normal gets a high anomaly score.

  This does NOT decide the final risk level by itself - it produces
  one signal (0-100) that the Risk Engine (Step C) will combine with
  other rule-based signals.

Run directly to train + test on the current dataset:
  python monitoring/ml_detector.py
"""

import os
import sys

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# The features the model learns from. Order matters - must match
# every time we train AND every time we score a new session.
FEATURE_COLUMNS = [
    "session_duration_sec",
    "total_requests",
    "requests_per_minute",
    "failed_login_attempts",
    "number_of_pages_accessed",
    "unusual_page_access",
    "ip_changed",
]

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "dataset", "isolation_forest.joblib")

# Sessions that are clearly leftover testing noise, not real browsing:
# - failed-login bursts with no real session (session_key starts with "ip:")
# - unrealistic request rates from manual testing/curl (not human or demo.py traffic)
MAX_REALISTIC_RPM = 200


def load_clean_dataset():
    df = pd.read_csv(config.DATASET_PATH)
    before = len(df)
    df = df[~df["session_key"].astype(str).str.startswith("ip:")]
    df = df[df["requests_per_minute"] <= MAX_REALISTIC_RPM]
    after = len(df)
    print(f"[CLEAN] Kept {after}/{before} sessions after removing testing noise.")
    return df


def train_model():
    """Trains a fresh Isolation Forest on the current dataset and saves it to disk."""
    df = load_clean_dataset()

    if len(df) < 10:
        raise ValueError(f"Only {len(df)} sessions left after cleaning - need at least 10 to train.")

    X = df[FEATURE_COLUMNS]

    # contamination = the rough fraction of sessions we EXPECT to be
    # unusual. 0.1 = assume ~10% of current data is abnormal. This is
    # just a starting assumption for training, not a hardcoded output.
    model = IsolationForest(
        n_estimators=200,
        contamination=0.1,
        random_state=42,
    )
    model.fit(X)

    joblib.dump(model, MODEL_PATH)
    print(f"[TRAIN] Model trained on {len(df)} sessions and saved to {MODEL_PATH}")
    return model


def load_model():
    if not os.path.exists(MODEL_PATH):
        return train_model()
    return joblib.load(MODEL_PATH)


def score_session(feature_dict, model=None):
    """
    Takes one session's features as a dict, e.g.:
      {
        "session_duration_sec": 45.0,
        "total_requests": 80,
        "requests_per_minute": 106.7,
        "failed_login_attempts": 6,
        "number_of_pages_accessed": 2,
        "unusual_page_access": 1,
        "ip_changed": 1,
      }
    Returns an anomaly score from 0 (perfectly normal) to 100 (highly anomalous).
    """
    if model is None:
        model = load_model()

    row = pd.DataFrame([[feature_dict[col] for col in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)

    # decision_function: higher = more normal, lower/negative = more anomalous.
    # Typical range is roughly -0.5 to +0.5, so we rescale it to 0-100,
    # where 100 = most anomalous.
    raw_score = model.decision_function(row)[0]
    anomaly_score = round(max(0, min(100, (0.5 - raw_score) * 100)), 1)

    return anomaly_score


if __name__ == "__main__":
    model = train_model()

    df = load_clean_dataset()
    print("\n[TEST] Scoring every (clean) session currently in the dataset:\n")
    for _, row in df.iterrows():
        features = {col: row[col] for col in FEATURE_COLUMNS}
        score = score_session(features, model=model)
        flag = "ANOMALY" if score >= 60 else ""
        print(f"  session={str(row['session_key'])[:12]:<12} "
              f"failed_logins={row['failed_login_attempts']:<3.0f} "
              f"rpm={row['requests_per_minute']:<8.1f} "
              f"ip_changed={row['ip_changed']:<2.0f} "
              f"-> anomaly_score={score:<6} {flag}")