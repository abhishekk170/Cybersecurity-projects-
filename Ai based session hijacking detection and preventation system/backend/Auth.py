"""
NovaBank Demo Backend - Auth routes
"""

import re
from flask import Blueprint, request, jsonify, g

import models as models
from config import Config
from services import session_service
from services.activity_logger import log_login, log_failed_login, log_logout

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@auth_bp.post("/register")
def register():
    data = request.get_json(silent=True) or {}

    name = (data.get("name") or "").strip()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    email = (data.get("email") or "").strip() or None

    # ---- Validation ----
    if not name or not username or not password:
        return jsonify({"error": "Name, username and password are required."}), 400

    if len(name) > 100:
        return jsonify({"error": "Name is too long."}), 400

    if not USERNAME_RE.match(username):
        return jsonify({
            "error": "Username must be 3-32 characters: letters, numbers, '_' or '.' only."
        }), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters."}), 400

    if email and not EMAIL_RE.match(email):
        return jsonify({"error": "Email address is not valid."}), 400

    if models.username_exists(username):
        return jsonify({"error": "That username is already taken."}), 409

    if email and models.email_exists(email):
        return jsonify({"error": "That email is already registered."}), 409

    # ---- Create user + demo account ----
    user_id = models.create_user(name, username, password, email)
    account_number = models.create_account_for_user(user_id, Config.DEMO_STARTING_BALANCE)

    # Seed a couple of demo transactions so the dashboard isn't empty
    models.create_transaction(user_id, "credit", "Deposit", "Welcome bonus", 5000.00)
    models.create_transaction(user_id, "debit", "Fees", "Account setup", 0.00)

    return jsonify({
        "message": "Account created successfully.",
        "username": username,
        "account_number": account_number,
    }), 201


@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    user = models.get_user_by_username(username)

    if not user or not models.verify_password(user, password):
        log_failed_login(username)
        return jsonify({"error": "Username or password is incorrect."}), 401

    session_id = session_service.start_session(user["id"])
    log_login(session_id, user["id"])

    account = models.get_account_by_user_id(user["id"])

    resp = jsonify({
        "message": "Login successful.",
        "user": {
            "name": user["name"],
            "username": user["username"],
        },
        "account": {
            "account_number": account["account_number"],
            "balance": account["balance"],
        } if account else None,
    })
    return session_service.set_session_cookie(resp, session_id)


@auth_bp.post("/logout")
def logout():
    session_row = session_service.get_current_session()

    if session_row and session_row["session_status"] == "active":
        models.end_session(session_row["session_id"], status="logged_out")
        log_logout(session_row["session_id"], session_row["user_id"])

    resp = jsonify({"message": "Logged out successfully."})
    return session_service.clear_session_cookie(resp)


@auth_bp.get("/session")
def check_session():
    """Lets the frontend ask 'am I still logged in?' on page load."""
    session_row = session_service.get_current_session()

    if not session_row or session_row["session_status"] != "active":
        return jsonify({"authenticated": False}), 200

    from datetime import datetime, timedelta
    from flask import current_app
    idle_minutes = current_app.config["SESSION_IDLE_TIMEOUT_MINUTES"]
    last_activity = datetime.strptime(session_row["last_activity"], "%Y-%m-%d %H:%M:%S")
    if datetime.utcnow() - last_activity > timedelta(minutes=idle_minutes):
        models.end_session(session_row["session_id"], status="expired")
        return jsonify({"authenticated": False}), 200

    user = models.get_user_by_id(session_row["user_id"])
    models.touch_session(session_row["session_id"])

    return jsonify({
        "authenticated": True,
        "user": {"name": user["name"], "username": user["username"]},
    })