"""
NovaBank Security Monitoring Agent

WHAT THIS DOES:
  1. Every few seconds, asks the bank backend: "any new events since last time?"
     (GET /api/security/events?since_id=...)
  2. Writes every raw event to dataset/raw_logs.csv  -> your audit trail
  3. Groups events into "sessions" and tracks running stats per session
  4. When a session goes quiet (no events for SESSION_IDLE_SECONDS), it
     computes ML-ready features and appends one row to
     dataset/session_dataset.csv

This process never talks to the bank's database directly. It only ever
calls the public GET /api/security/events endpoint. This keeps the two
parts of the project cleanly separated.

Run with:  python monitoring/monitor.py
(run this from inside the security-monitoring-tool/ folder)
"""

import csv
import os
import sys
import time
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
import requests

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

# In-memory tracker: one entry per "session" (or per IP, for failed
# logins that have no session yet). Cleared out once written to the
# dataset.
sessions = {}


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
    Failed logins have no session_id yet, so we group those by IP
    instead - good enough to see 'a burst of failed logins from X'."""
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

    s["last_seen"] = now
    s["events"] += 1
    if event.get("user_id"):
        s["user_id"] = event["user_id"]
    # Only count actual page browsing toward "distinct pages visited" -
    # login/logout/failed_login are session boundaries, not page visits,
    # and would otherwise inflate every session's endpoint count by 2.
    if event.get("endpoint") and event.get("event_type") in ("page_access", "transaction"):
        s["endpoints"].add(event["endpoint"])
    if event.get("ip"):
        s["ips"].add(event["ip"])
    if event.get("event_type") == "failed_login":
        s["failed_logins"] += 1
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


def flush_idle_sessions():
    now = datetime.utcnow()
    for key in list(sessions.keys()):
        s = sessions[key]
        if (now - s["last_seen"]).total_seconds() > config.SESSION_IDLE_SECONDS:
            write_feature_row(key, s)
            del sessions[key]


def poll_loop():
    ensure_files()
    since_id = 0

    print("=" * 60)
    print(" NovaBank Monitoring Agent")
    print(f" Watching: {config.BANK_API_URL}")
    print(f" Raw log:  {config.RAW_LOG_PATH}")
    print(f" Dataset:  {config.DATASET_PATH}")
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
                      f"session={event['session_id'] or '-':<10} "
                      f"ip={event['ip']} endpoint={event['endpoint']}")

            if events:
                since_id = data["last_id"]

            flush_idle_sessions()

        except requests.RequestException as e:
            print(f"[WARN] Could not reach bank API: {e}")

        time.sleep(config.POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        poll_loop()
    except KeyboardInterrupt:
        print("\n[STOPPED] Monitoring agent shut down.")