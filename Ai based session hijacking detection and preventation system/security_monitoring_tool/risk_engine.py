"""
NovaBank Security Monitoring Agent - Risk Engine

WHAT THIS DOES:
  Combines two kinds of evidence into ONE risk score (0-100):
    1. The ML anomaly score from ml_detector.py (up to 30 points)
    2. Simple rule-based red flags (failed logins, IP change, etc.)
  Then maps the score to LOW / MEDIUM / HIGH and lists the reasons.

Run directly to self-test and score the real dataset:
  python monitoring/risk_engine.py
(run from inside the security_monitoring_tool/ folder)
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
import ml_detector

# ---------------- Tunable settings (change these to tune the engine) ----------------

ML_NORMAL_CEILING = 45     # at or below this -> 0 points
ML_FULL_SCORE = 80         # at or above this -> full points
ML_MAX_POINTS = 30
ML_REASON_THRESHOLD = 60   # ML score at/above this adds the "ML anomaly" reason

FAILED_LOGIN_LOW = 1       # 1-2 attempts  -> +5
FAILED_LOGIN_MED = 3       # 3-4 attempts  -> +15
FAILED_LOGIN_HIGH = 5      # 5+ attempts   -> +25

RPM_MEDIUM = 40            # -> +10
RPM_HIGH = 80              # -> +20

IP_CHANGE_POINTS = 35
UNUSUAL_PAGE_POINTS = 10

SHORT_SESSION_SECONDS = 20
SHORT_SESSION_MIN_REQUESTS = 20
SHORT_SESSION_POINTS = 10

MEDIUM_MIN = 31
HIGH_MIN = 71


def ml_points_from_score(ml_score):
    """Turns the 0-100 ML anomaly score into 0-30 points."""
    span = ML_FULL_SCORE - ML_NORMAL_CEILING
    fraction = (ml_score - ML_NORMAL_CEILING) / span
    fraction = max(0.0, min(1.0, fraction))
    return fraction * ML_MAX_POINTS


def risk_level(score):
    if score >= HIGH_MIN:
        return "HIGH"
    if score >= MEDIUM_MIN:
        return "MEDIUM"
    return "LOW"


def evaluate_session(features, ml_score):
    """
    features: dict with the same keys as the dataset columns
    ml_score: anomaly score (0-100) from ml_detector.score_session()

    Returns a dict: {"risk_score", "risk_level", "reasons", "ml_score"}
    """
    points = 0.0
    reasons = []

    # 1) ML signal
    points += ml_points_from_score(ml_score)
    if ml_score >= ML_REASON_THRESHOLD:
        reasons.append("ML anomaly detected")

    # 2) Failed logins
    failed = float(features["failed_login_attempts"])
    if failed >= FAILED_LOGIN_HIGH:
        points += 25
        reasons.append("Multiple failed login attempts")
    elif failed >= FAILED_LOGIN_MED:
        points += 15
        reasons.append("Multiple failed login attempts")
    elif failed >= FAILED_LOGIN_LOW:
        points += 5
        reasons.append("Some failed login attempts")

    # 3) IP change
    if float(features["ip_changed"]) == 1:
        points += IP_CHANGE_POINTS
        reasons.append("IP change detected")

    # 4) Request rate
    rpm = float(features["requests_per_minute"])
    if rpm >= RPM_HIGH:
        points += 20
        reasons.append("Unusual request frequency")
    elif rpm >= RPM_MEDIUM:
        points += 10
        reasons.append("Elevated request frequency")

    # 5) Unusual pages / transactions
    if float(features["unusual_page_access"]) == 1:
        points += UNUSUAL_PAGE_POINTS
        reasons.append("Unusual page or transaction activity")

    # 6) Very short but busy session
    if (float(features["session_duration_sec"]) < SHORT_SESSION_SECONDS
            and float(features["total_requests"]) >= SHORT_SESSION_MIN_REQUESTS):
        points += SHORT_SESSION_POINTS
        reasons.append("Abnormally short, busy session")

    score = int(round(min(100, points)))
    return {
        "risk_score": score,
        "risk_level": risk_level(score),
        "reasons": reasons,
        "ml_score": ml_score,
    }


def format_report(result):
    lines = [
        f"Risk Score: {result['risk_score']}/100",
        f"Risk Level: {result['risk_level']}",
        "Reasons:",
    ]
    if result["reasons"]:
        lines += [f"  - {r}" for r in result["reasons"]]
    else:
        lines.append("  - None (normal behavior)")
    return "\n".join(lines)


# ---------------- Self-test ----------------

SAMPLE_SESSIONS = {
    "SAMPLE LOW": (
        {"session_duration_sec": 45, "total_requests": 10, "requests_per_minute": 13,
         "failed_login_attempts": 0, "number_of_pages_accessed": 2,
         "unusual_page_access": 0, "ip_changed": 0},
        40.0,
    ),
    "SAMPLE MEDIUM": (
        {"session_duration_sec": 45, "total_requests": 35, "requests_per_minute": 47,
         "failed_login_attempts": 3, "number_of_pages_accessed": 2,
         "unusual_page_access": 1, "ip_changed": 0},
        52.0,
    ),
    "SAMPLE HIGH": (
        {"session_duration_sec": 50, "total_requests": 88, "requests_per_minute": 105,
         "failed_login_attempts": 6, "number_of_pages_accessed": 2,
         "unusual_page_access": 1, "ip_changed": 1},
        71.4,
    ),
}

if __name__ == "__main__":
    print("=" * 50)
    print(" PART 1: Hand-made sample sessions")
    print("=" * 50)
    for name, (feats, ml) in SAMPLE_SESSIONS.items():
        print(f"\n--- {name} (ML score {ml}) ---")
        print(format_report(evaluate_session(feats, ml)))

    print("\n" + "=" * 50)
    print(" PART 2: Real sessions from your dataset")
    print("=" * 50)
    model = ml_detector.load_model()
    df = ml_detector.load_clean_dataset()
    for _, row in df.iterrows():
        feats = {col: row[col] for col in ml_detector.FEATURE_COLUMNS}
        ml = ml_detector.score_session(feats, model=model)
        res = evaluate_session(feats, ml)
        print(f"  session={str(row['session_key'])[:12]:<12} "
              f"ml={ml:<5} -> risk={res['risk_score']:<3} {res['risk_level']:<6} "
              f"{'; '.join(res['reasons'])}")