"""
NovaBank Demo Backend - Configuration

All values can be overridden with environment variables.
No secrets are hardcoded for production use; the defaults here
are ONLY suitable for local demo/development.
"""

import os
import secrets


class Config:
    # SQLite database file (created next to this file)
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_PATH = os.path.join(BASE_DIR, "novabank.db")

    # Flask secret key (used for signing, CSRF, etc.)
    # In real deployments, set FLASK_SECRET_KEY as an env var instead.
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

    # Frontend origin allowed to call this API with credentials (cookies)
    FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "http://127.0.0.1:5500")

    # Custom session cookie (separate from Flask's own session cookie)
    SESSION_COOKIE_NAME = "novabank_session_id"
    SESSION_IDLE_TIMEOUT_MINUTES = int(os.environ.get("SESSION_IDLE_TIMEOUT_MINUTES", 30))

    # Optional: if set, activity/security events are also pushed (POST) to
    # this URL, so a separate Monitoring Agent process can receive them
    # in real time instead of only polling GET /api/security/events.
    MONITORING_AGENT_WEBHOOK_URL = os.environ.get("MONITORING_AGENT_WEBHOOK_URL", "")

    # Demo account seed values
    DEMO_STARTING_BALANCE = 84520.00