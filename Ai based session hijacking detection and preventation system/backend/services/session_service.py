"""
NovaBank Demo Backend - Session Service

Manages a custom, database-backed session (separate from Flask's built-in
`session` cookie) so that:
  - each login gets an explicit session_id we can log, list, and expose
  - a future Security Console can invalidate one specific session
  - idle sessions expire automatically

The session_id is delivered to the browser as an HttpOnly cookie.
"""

import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import request, jsonify, current_app, g

import models as models


def generate_session_id():
    return secrets.token_hex(32)


def start_session(user_id):
    """Create a new session record and return the session_id."""
    session_id = generate_session_id()
    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")
    models.create_session(session_id, user_id, ip_address, user_agent)
    return session_id


def set_session_cookie(response, session_id):
    idle_minutes = current_app.config["SESSION_IDLE_TIMEOUT_MINUTES"]
    response.set_cookie(
        current_app.config["SESSION_COOKIE_NAME"],
        session_id,
        httponly=True,
        samesite="Lax",
        secure=False,  # set True when served over HTTPS in a real deployment
        max_age=idle_minutes * 60,
        path="/",
    )
    return response


def clear_session_cookie(response):
    response.delete_cookie(current_app.config["SESSION_COOKIE_NAME"], path="/")
    return response


def _is_expired(session_row):
    idle_minutes = current_app.config["SESSION_IDLE_TIMEOUT_MINUTES"]
    last_activity = datetime.strptime(session_row["last_activity"], "%Y-%m-%d %H:%M:%S")
    return datetime.utcnow() - last_activity > timedelta(minutes=idle_minutes)


def get_current_session():
    """Look up the session tied to this request's cookie, or None."""
    session_id = request.cookies.get(current_app.config["SESSION_COOKIE_NAME"])
    if not session_id:
        return None
    session_row = models.get_session(session_id)
    if not session_row:
        return None
    return session_row


def require_auth(view_func):
    """
    Decorator for protected routes.
    Validates the session cookie, checks status + idle expiry, refreshes
    last_activity, and stashes the session + user on flask.g for the view.
    Also records a 'page_access' activity + security event automatically.
    """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        session_row = get_current_session()

        if not session_row:
            return jsonify({"error": "Not authenticated. Please log in."}), 401

        if session_row["session_status"] == "invalidated":
            return jsonify({"error": "Session has been invalidated. Please log in again."}), 401

        if session_row["session_status"] != "active":
            return jsonify({"error": "Session is no longer active. Please log in again."}), 401

        if _is_expired(session_row):
            models.end_session(session_row["session_id"], status="expired")
            return jsonify({"error": "Session expired. Please log in again."}), 401

        models.touch_session(session_row["session_id"])

        g.session_id = session_row["session_id"]
        g.user_id = session_row["user_id"]

        # Log this authenticated API access for the security pipeline
        from services.activity_logger import log_page_access
        log_page_access(session_row["session_id"], session_row["user_id"])

        return view_func(*args, **kwargs)

    return wrapper