"""
NovaBank Security Monitoring Agent

WHAT THIS DOES:
  1. Every few seconds, asks the bank backend: "any new events since last time?"
  2. Writes every raw event to dataset/raw_logs.csv
  3. Groups events into sessions and tracks running stats per session
  4. LIVE: scores active sessions with the Risk Engine and applies prevention
  5. Saves a live snapshot (dataset/live_sessions.json) for the dashboard
  6. When a session goes quiet, writes one feature row to session_dataset.csv

Run with:  python monitoring/monitor.py
(run from inside the security_monitoring_tool/ folder)
"""

import csv
import json
import os
import sys
import time
from datetime import datetime, timezone

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
import requests
import ml_detector
import risk_engine
import prevention

RAW_FIELDS = [
    "id", "session_id", "user_id", "timestamp", "ip",
    "user_agent", "endpoint", "request_method", "event_type",
]

DATASET_FIELDS = [
    "session_key", "user_id", "start_time", "end_time",
    "session_duration_sec", "total_requests", "requests_per_minute",
    "failed_login_attempts", "number_of_pages_accessed",
    "unusual_page_access", "ip_changed",
]

MAX_RECENT_FINISHED = 15

sessions = {}

# user_id -> list of failed-login timestamps not yet attached to a session
failed_logins_by_user = {}

# summaries of sessions that already finished (shown on the dashboard)
recent_finished = []

_model = None


def ensure_files():
    os.makedirs(os.path.dirname(config.RAW_LOG_PATH), exist_ok=True)
    if not os.path.exists(config.RAW_LOG_PATH):
        with open(config.RAW_LOG_PATH, "w", newline="") as f:
            csv.DictWriter(f, fieldnames=RAW_FIELDS).writeheader()
    if not os.path.exists(config.DATASET_PATH):
        with open(config.DATASET_PATH, "w", newline="") as f:
            csv.DictWriter(f, fieldnames=DATASET_FIELDS).writeheader()


def append_raw(event):
    with open(config.RAW_LOG_PATH, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=RAW_FIELDS)
        writer.writerow({k: event.get(k, "") for k in RAW_FIELDS})


def group_key(event):
    """Events with a session_id are grouped by session.
    Failed logins have no session_id yet, so we group those by IP."""
    return event["session_id"] or f"ip:{event['ip']}"


def parse_ts(ts_str):
    return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")


def update_session(event):
    key = group_key(event)
    now = parse_ts(event["timestamp"])

    s = sessions.get(key)
    if s is None:
        s = {
            "user_id": event.get("user_id"),
            "start": now,
            "last_seen": now,
            "events": 0,
            "failed_logins": 0,
            "endpoints": set(),
            "ips": set(),
            "transactions": 0,
        }
        sessions[key] = s
        if event.get("user_id"):
            recent = [
                t for t in failed_logins_by_user.get(event["user_id"], [])
                if (now - t).total_seconds() <= config.FAILED_LOGIN_LOOKBACK_SECONDS
            ]
            s["failed_logins"] = len(recent)
            failed_logins_by_user[event["user_id"]] = []

    s["last_seen"] = now
    s["events"] += 1
    if event.get("user_id"):
        s["user_id"] = event["user_id"]
    if event.get("endpoint") and event.get("event_type") in ("page_access", "transaction"):
        s["endpoints"].add(event["endpoint"])
    if event.get("ip"):
        s["ips"].add(event["ip"])
    if event.get("event_type") == "failed_login":
        s["failed_logins"] += 1
        if event.get("user_id"):
            failed_logins_by_user.setdefault(event["user_id"], []).append(now)
    if event.get("event_type") == "transaction":
        s["transactions"] += 1


def write_feature_row(key, s):
    duration = max((s["last_seen"] - s["start"]).total_seconds(), 1)
    rpm = round(s["events"] / (duration / 60), 2)
    unusual = 1 if (
        len(s["endpoints"]) > config.UNUSUAL_ENDPOINT_THRESHOLD
        or s["transactions"] > config.UNUSUAL_TRANSACTION_THRESHOLD
    ) else 0
    ip_changed = 1 if len(s["ips"]) > 1 else 0

    row = {
        "session_key": key,
        "user_id": s["user_id"] or "",
        "start_time": s["start"].strftime("%Y-%m-%d %H:%M:%S"),
        "end_time": s["last_seen"].strftime("%Y-%m-%d %H:%M:%S"),
        "session_duration_sec": round(duration, 1),
        "total_requests": s["events"],
        "requests_per_minute": rpm,
        "failed_login_attempts": s["failed_logins"],
        "number_of_pages_accessed": len(s["endpoints"]),
        "unusual_page_access": unusual,
        "ip_changed": ip_changed,
    }

    with open(config.DATASET_PATH, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=DATASET_FIELDS).writerow(row)

    print(f"[DATASET] session={key} rpm={rpm} failed_logins={s['failed_logins']} "
          f"pages={len(s['endpoints'])} unusual={unusual} ip_changed={ip_changed}")


def check_live_risk():
    """Scores every active session and applies prevention if risk escalates."""
    global _model
    if _model is None:
        try:
            _model = ml_detector.load_model()
        except Exception as e:
            print(f"[WARN] ML model unavailable, live scoring skipped: {e}")
            return

    for key, s in list(sessions.items()):
        if str(key).startswith("ip:"):
            continue  # failed-login bursts have no real session to act on
        if s.get("terminated"):
            continue  # already killed, nothing more to do
        if s["events"] < 5:
            continue  # too little data to judge fairly

        duration = max((s["last_seen"] - s["start"]).total_seconds(), 1)
        features = {
            "session_duration_sec": round(duration, 1),
            "total_requests": s["events"],
            "requests_per_minute": round(s["events"] / (duration / 60), 2),
            "failed_login_attempts": s["failed_logins"],
            "number_of_pages_accessed": len(s["endpoints"]),
            "unusual_page_access": 1 if (
                len(s["endpoints"]) > config.UNUSUAL_ENDPOINT_THRESHOLD
                or s["transactions"] > config.UNUSUAL_TRANSACTION_THRESHOLD
            ) else 0,
            "ip_changed": 1 if len(s["ips"]) > 1 else 0,
        }

        ml_score = ml_detector.score_session(features, model=_model)
        result = risk_engine.evaluate_session(features, ml_score)
        s["last_result"] = result  # remembered for the dashboard

        outcome = prevention.apply_prevention(key, s["user_id"], result)
        if outcome and result["risk_level"] == "HIGH":
            s["terminated"] = True


def session_summary(key, s, status):
    """Small dict describing one session for the dashboard."""
    result = s.get("last_result")
    if not result:
        return None
    return {
        "session": str(key)[:12],
        "user_id": s.get("user_id") or "",
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "ml_score": float(result["ml_score"]),
        "reasons": result["reasons"],
        "action": prevention.ACTIONS[result["risk_level"]][0],
        "requests": s["events"],
        "failed_logins": s["failed_logins"],
        "ip_changed": 1 if len(s["ips"]) > 1 else 0,
        "status": status,
    }


def write_live_snapshot():
    """Saves active + recently finished sessions to live_sessions.json."""
    items = []
    for key, s in sessions.items():
        if str(key).startswith("ip:"):
            continue
        status = "terminated" if s.get("terminated") else "active"
        item = session_summary(key, s, status)
        if item:
            items.append(item)
    items.extend(reversed(recent_finished))  # newest finished first

    snapshot = {
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "sessions": items[:25],
    }

    tmp_path = config.LIVE_SNAPSHOT_PATH + ".tmp"
    try:
        with open(tmp_path, "w") as f:
            json.dump(snapshot, f, default=str)
        os.replace(tmp_path, config.LIVE_SNAPSHOT_PATH)
    except OSError:
        pass  # file busy for a moment - the next poll will write it again


def flush_idle_sessions():
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for key in list(sessions.keys()):
        s = sessions[key]
        if (now - s["last_seen"]).total_seconds() > config.SESSION_IDLE_SECONDS:
            write_feature_row(key, s)
            if not str(key).startswith("ip:"):
                status = "terminated" if s.get("terminated") else "ended"
                item = session_summary(key, s, status)
                if item:
                    recent_finished.append(item)
                    del recent_finished[:-MAX_RECENT_FINISHED]
            del sessions[key]


def last_raw_id():
    """Returns the highest event id already saved in raw_logs.csv (0 if none)."""
    last = 0
    if not os.path.exists(config.RAW_LOG_PATH):
        return last
    with open(config.RAW_LOG_PATH, newline="") as f:
        for row in csv.DictReader(f):
            try:
                last = max(last, int(row["id"]))
            except (ValueError, KeyError):
                pass
    return last


def poll_loop():
    ensure_files()
    since_id = last_raw_id()

    print("=" * 60)
    print(" NovaBank Monitoring Agent")
    print(f" Watching: {config.BANK_API_URL}")
    print(f" Raw log:  {config.RAW_LOG_PATH}")
    print(f" Dataset:  {config.DATASET_PATH}")
    print(f" Live file: {config.LIVE_SNAPSHOT_PATH}")
    print(f" Resuming from event id: {since_id}")
    print("=" * 60)

    while True:
        try:
            resp = requests.get(
                f"{config.BANK_API_URL}/api/security/events",
                params={"since_id": since_id, "limit": 200},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
            events = data.get("events", [])

            for event in events:
                append_raw(event)
                update_session(event)
                print(f"[EVENT] {event['event_type']:<20} "
                      f"session={(event['session_id'] or '-')[:10]:<10} "
                      f"ip={event['ip']} endpoint={event['endpoint'][:30]}")

            if events:
                since_id = data["last_id"]

            check_live_risk()
            flush_idle_sessions()
            write_live_snapshot()

        except requests.RequestException as e:
            print(f"[WARN] Could not reach bank API: {e}")

        time.sleep(config.POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        poll_loop()
    except KeyboardInterrupt:
        print("\n[STOPPED] Monitoring agent shut down.")
