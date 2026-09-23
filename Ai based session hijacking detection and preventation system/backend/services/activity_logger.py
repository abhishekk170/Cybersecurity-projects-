"""
NovaBank Demo Backend - Activity & Security Event Logger

Two related but distinct things are written here, on purpose:

1. activity_logs  -> general audit trail for the bank app itself
                      (login, logout, failed_login, page_access, transaction)

2. security_events -> a lightweight outbound queue specifically shaped for
                       the future Monitoring Agent (matches the JSON schema
                       given in the project spec). The bank backend never
                       computes a risk score here - it just records raw facts.

No passwords, cookies, or auth tokens are ever written to either table.
"""

import json
import requests
from flask import request, current_app

import models as models


def _client_info():
    return request.remote_addr, request.headers.get("User-Agent", "")


def _push_to_monitoring_agent(event_row):
    """Best-effort push to an external Monitoring Agent, if configured.
    Never raises - a monitoring agent being offline must not break banking."""
    webhook_url = current_app.config.get("MONITORING_AGENT_WEBHOOK_URL")
    if not webhook_url:
        return
    payload = {
        "session_id": event_row.get("session_id"),
        "user_id": event_row.get("user_id"),
        "timestamp": event_row.get("created_at"),
        "ip": event_row.get("ip_address"),
        "user_agent": event_row.get("user_agent"),
        "endpoint": event_row.get("endpoint"),
        "request_method": event_row.get("request_method"),
        "event_type": event_row.get("event_type"),
    }
    try:
        requests.post(webhook_url, json=payload, timeout=1.5)
    except requests.RequestException:
        pass  # monitoring agent may not be running yet - that's fine


def _record(session_id, user_id, event_type, endpoint=None, details=None):
    ip_address, user_agent = _client_info()
    method = request.method if request else None

    models.log_activity(
        session_id=session_id,
        user_id=user_id,
        event_type=event_type,
        endpoint=endpoint or (request.path if request else None),
        request_method=method,
        ip_address=ip_address,
        user_agent=user_agent,
        details=json.dumps(details) if details else None,
    )

    event_id = models.record_security_event(
        session_id=session_id,
        user_id=user_id,
        event_type=event_type,
        endpoint=endpoint or (request.path if request else None),
        request_method=method,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    # Fetch what we just wrote so the webhook payload has a real timestamp
    events = models.get_security_events(since_id=event_id - 1, limit=1, mark_delivered=False)
    if events:
        _push_to_monitoring_agent(dict(events[0]))


def log_login(session_id, user_id):
    _record(session_id, user_id, "login", endpoint="/api/auth/login")


def log_failed_login(username_attempted):
    _record(None, None, "failed_login", endpoint="/api/auth/login",
            details={"username_attempted": username_attempted})


def log_logout(session_id, user_id):
    _record(session_id, user_id, "logout", endpoint="/api/auth/logout")


def log_page_access(session_id, user_id):
    _record(session_id, user_id, "page_access")


def log_transaction(session_id, user_id, tx_id, tx_type, amount):
    _record(session_id, user_id, "transaction", endpoint="/api/transactions",
            details={"transaction_id": tx_id, "type": tx_type, "amount": amount})


def log_session_invalidated(session_id, user_id, invalidated_by="security_console"):
    _record(session_id, user_id, "session_invalidated",
            endpoint=f"/api/security/sessions/{session_id}/invalidate",
            details={"invalidated_by": invalidated_by})