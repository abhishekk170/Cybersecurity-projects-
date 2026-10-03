"""
NovaBank Demo Simulator (run from YOUR laptop / terminal)

Generates CONTROLLED test traffic against the bank's own public API.
It never touches the database directly, never bypasses auth, and never
reads anyone else's real data - it registers its own throwaway demo user
and only calls the same endpoints a normal browser would.

Usage:
    python demo.py --scenario low
    python demo.py --scenario medium
    python demo.py --scenario high

By default it targets http://127.0.0.1:5000. During the real two-laptop
presentation, point it at your friend's machine:
    python demo.py --scenario high --url http://192.168.1.23:5000
"""

import argparse
import random
import string
import time
import sys

import requests

SCENARIOS = {
    "low": {
        "failed_logins": 0,
        "num_requests": 8,
        "duration_seconds": 45,
        "endpoints": ["/api/account", "/api/transactions"],
        "num_transactions": 0,
    },
    "medium": {
        "failed_logins": 3,
        "num_requests": 30,
        "duration_seconds": 45,
        "endpoints": ["/api/account", "/api/transactions"],
        "num_transactions": 3,
    },
    "high": {
        "failed_logins": 6,
        "num_requests": 80,
        "duration_seconds": 45,
        "endpoints": ["/api/account", "/api/transactions"],
        "num_transactions": 6,
    },
}


def random_username():
    return "demo_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


def register_demo_user(base_url):
    username = random_username()
    payload = {
        "name": "Demo Tester",
        "username": username,
        "password": "DemoPass123",
    }
    resp = requests.post(f"{base_url}/api/auth/register", json=payload, timeout=5)
    if resp.status_code != 201:
        print(f"[ERROR] Could not register demo user: {resp.status_code} {resp.text}")
        sys.exit(1)
    return username, "DemoPass123"


def do_failed_logins(base_url, username, count):
    if count == 0:
        return
    print(f"Generating {count} failed login event(s)...")
    for _ in range(count):
        requests.post(
            f"{base_url}/api/auth/login",
            json={"username": username, "password": "wrong-password"},
            timeout=5,
        )
        time.sleep(0.4)
    print("\u2713 Failed login events generated")


def do_real_login(base_url, username, password):
    session = requests.Session()
    resp = session.post(
        f"{base_url}/api/auth/login",
        json={"username": username, "password": password},
        timeout=5,
    )
    if resp.status_code != 200:
        print(f"[ERROR] Login failed: {resp.status_code} {resp.text}")
        sys.exit(1)
    return session


def do_transactions(session, base_url, count):
    if count == 0:
        return
    print(f"Generating {count} transaction event(s)...")
    for i in range(count):
        session.post(
            f"{base_url}/api/transactions",
            json={"type": "credit", "category": "Demo", "description": f"Demo transfer {i+1}", "amount": 10.00},
            timeout=5,
        )
        time.sleep(0.3)
    print("\u2713 Transaction events generated")


def do_browsing(session, base_url, endpoints, num_requests, duration_seconds):
    interval = max(duration_seconds / num_requests, 0.05)
    label = "High request frequency" if num_requests >= 60 else \
            "Moderate request frequency" if num_requests >= 20 else \
            "Normal request frequency"
    print(f"Generating {num_requests} page requests over ~{duration_seconds}s...")
    for _ in range(num_requests):
        endpoint = random.choice(endpoints)
        try:
            session.get(f"{base_url}{endpoint}", timeout=5)
        except requests.RequestException:
            pass
        time.sleep(interval)
    print(f"\u2713 {label} generated")


def run_scenario(name, base_url):
    cfg = SCENARIOS[name]

    print("[DEMO MODE]")
    print(f"Generating {name}-risk activity...\n")

    username, password = register_demo_user(base_url)

    do_failed_logins(base_url, username, cfg["failed_logins"])

    session = do_real_login(base_url, username, password)
    print("\u2713 Login successful, session started")

    do_browsing(session, base_url, cfg["endpoints"], cfg["num_requests"], cfg["duration_seconds"])

    do_transactions(session, base_url, cfg["num_transactions"])

    session.post(f"{base_url}/api/auth/logout", timeout=5)
    print("\u2713 Session ended (logout)")

    print("\nSending events to monitoring system...")
    print("\u2713 Events sent successfully")
    print(f"\nDone. Check the Monitoring Agent terminal and dataset/session_dataset.csv")
    print(f"in a few seconds (the agent finalizes a session after it goes quiet).")


def main():
    parser = argparse.ArgumentParser(description="NovaBank controlled activity simulator")
    parser.add_argument("--scenario", choices=SCENARIOS.keys(), required=True)
    parser.add_argument("--url", default="http://127.0.0.1:5000",
                         help="Bank API base URL (default: http://127.0.0.1:5000)")
    args = parser.parse_args()

    run_scenario(args.scenario, args.url)


if __name__ == "__main__":
    main()