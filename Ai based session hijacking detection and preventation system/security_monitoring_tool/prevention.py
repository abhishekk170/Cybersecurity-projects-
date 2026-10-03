"""
NovaBank Security Monitoring Agent - Prevention

WHAT THIS DOES:
  Turns a risk level (from risk_engine.py) into an action:
    LOW    -> keep monitoring
    MEDIUM -> warn + flag (logged to dataset/incidents.csv)
    HIGH   -> invalidate the session via the bank API (forces re-login)
              + log the incident

  Each session is only acted on when its risk ESCALATES, so we never
  repeat the same action again and again.

Self-test (no network needed):
  python monitoring/prevention.py

Live test against a real session id (bank backend must be running):
  python monitoring/prevention.py --live <session_id>
"""

import csv
import os
import sys
from datetime import datetime

import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

INCIDENT_FIELDS = [
    "timestamp", "session_key", "user_id", "risk_score",
    "risk_level", "action", "reasons", "outcome",
]

LEVEL_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

ACTIONS = {
    "LOW": ("CONTINUE_MONITORING", "Session looks normal. Continue monitoring."),
    "MEDIUM": ("WARN_AND_FLAG", "Suspicious behavior. Session flagged and warning logged."),
    "HIGH": ("INVALIDATE_SESSION", "High risk. Session terminated - user must log in again."),
}

# session_key -> highest risk level already acted on
_handled = {}


def ensure_incident_file():
    os.makedirs(os.path.dirname(config.INCIDENT_LOG_PATH), exist_ok=True)
    if not os.path.exists(config.INCIDENT_LOG_PATH):
        with open(config.INCIDENT_LOG_PATH, "w", newline="") as f:
            csv.DictWriter(f, fieldnames=INCIDENT_FIELDS).writeheader()


def log_incident(session_key, user_id, result, action, outcome):
    ensure_incident_file()
    row = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "session_key": session_key,
        "user_id": user_id or "",
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "action": action,
        "reasons": "; ".join(result["reasons"]),
        "outcome": outcome,
    }
    with open(config.INCIDENT_LOG_PATH, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=INCIDENT_FIELDS).writerow(row)


def invalidate_session(session_key):
    """Asks the bank backend to kill the session. Returns a short outcome string."""
    if str(session_key).startswith("ip:"):
        return "skipped (no real session to invalidate)"
    try:
        resp = requests.post(
            f"{config.BANK_API_URL}/api/security/sessions/{session_key}/invalidate",
            timeout=5,
        )
        if resp.status_code == 200:
            return resp.json().get("message", "ok")
        if resp.status_code == 404:
            return "session not found"
        return f"unexpected status {resp.status_code}"
    except requests.RequestException:
        return "bank API unreachable"


def apply_prevention(session_key, user_id, result, dry_run=False):
    """
    Decide and perform the action for one session.
    Returns a dict describing what happened, or None if nothing new to do.
    dry_run=True prints the decision but sends no request and writes no CSV.
    """
    level = result["risk_level"]
    action, description = ACTIONS[level]

    already = _handled.get(session_key, -1)
    if LEVEL_RANK[level] <= already:
        return None  # already handled at this level or higher
    _handled[session_key] = LEVEL_RANK[level]

    if level == "LOW":
        return {"action": action, "outcome": "no action needed"}

    if level == "MEDIUM":
        outcome = "flagged"
    else:  # HIGH
        if dry_run:
            outcome = "dry-run (no request sent)"
        elif config.INVALIDATE_ON_HIGH:
            outcome = invalidate_session(session_key)
        else:
            outcome = "observe-only mode (not invalidated)"

    print(f"[PREVENTION] {level:<6} | session={str(session_key)[:12]} "
          f"| score={result['risk_score']} | action={action} | outcome={outcome}")
    print(f"             {description}")

    if not dry_run:
        log_incident(session_key, user_id, result, action, outcome)

    return {"action": action, "outcome": outcome}


# ---------------- Self-test ----------------

if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--live":
        sid = sys.argv[2]
        fake_result = {
            "risk_score": 95, "risk_level": "HIGH", "ml_score": 75.0,
            "reasons": ["Manual live test"],
        }
        print(f"[LIVE TEST] Invalidating session {sid} ...")
        apply_prevention(sid, None, fake_result)
        print(f"\nCheck {config.INCIDENT_LOG_PATH}")
    else:
        print("[SELF-TEST] Dry run - no requests sent, no files written\n")
        samples = {
            "sample-low": {"risk_score": 5, "risk_level": "LOW", "reasons": []},
            "sample-medium": {"risk_score": 46, "risk_level": "MEDIUM",
                              "reasons": ["Multiple failed login attempts"]},
            "sample-high": {"risk_score": 100, "risk_level": "HIGH",
                            "reasons": ["IP change detected"]},
        }
        for key, res in samples.items():
            apply_prevention(key, "1", res, dry_run=True)

        print("\n[SELF-TEST] Repeating the HIGH session (should do nothing):")
        again = apply_prevention("sample-high", "1", samples["sample-high"], dry_run=True)
        print(f"  result = {again}")