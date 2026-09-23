"""
NovaBank Demo Backend - Database layer

Plain sqlite3 with parameterized queries (no string-built SQL anywhere).
Kept deliberately dependency-light so `python app.py` just works.
"""

import secrets
import sqlite3
from flask import g, current_app
from werkzeug.security import generate_password_hash, check_password_hash


def get_db():
    """Return a sqlite3 connection stored on Flask's application context `g`."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    username TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    account_number TEXT NOT NULL UNIQUE,
    balance REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    login_time TEXT NOT NULL DEFAULT (datetime('now')),
    last_activity TEXT NOT NULL DEFAULT (datetime('now')),
    ip_address TEXT,
    user_agent TEXT,
    session_status TEXT NOT NULL DEFAULT 'active', -- active | logged_out | invalidated | expired
    logout_time TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,             -- 'credit' | 'debit'
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    amount REAL NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    user_id INTEGER,
    event_type TEXT NOT NULL,       -- login | logout | failed_login | page_access | transaction | session_invalidated
    endpoint TEXT,
    request_method TEXT,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    user_id INTEGER,
    event_type TEXT NOT NULL,
    endpoint TEXT,
    request_method TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    delivered INTEGER NOT NULL DEFAULT 0  -- 0 = not yet pulled by monitoring agent, 1 = pulled
);
"""


def init_db(app):
    """Create tables if they do not already exist. Safe to call every startup."""
    with app.app_context():
        db = sqlite3.connect(app.config["DATABASE_PATH"])
        db.executescript(SCHEMA)
        db.commit()
        db.close()


# =========================
# USERS
# =========================

def username_exists(username):
    db = get_db()
    row = db.execute(
        "SELECT 1 FROM users WHERE username = ?", (username,)
    ).fetchone()
    return row is not None


def email_exists(email):
    db = get_db()
    row = db.execute(
        "SELECT 1 FROM users WHERE email = ?", (email,)
    ).fetchone()
    return row is not None


def create_user(name, username, password, email=None):
    db = get_db()
    password_hash = generate_password_hash(password)
    cursor = db.execute(
        "INSERT INTO users (name, username, email, password_hash) "
        "VALUES (?, ?, ?, ?)",
        (name, username, email, password_hash),
    )
    db.commit()
    return cursor.lastrowid


def get_user_by_username(username):
    db = get_db()
    return db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def get_user_by_id(user_id):
    db = get_db()
    return db.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def verify_password(user, password):
    return check_password_hash(user["password_hash"], password)


# =========================
# ACCOUNTS
# =========================

def _generate_account_number():
    return "NB" + secrets.token_hex(5).upper()


def create_account_for_user(user_id, starting_balance=0.0):
    db = get_db()
    account_number = _generate_account_number()
    db.execute(
        "INSERT INTO accounts (user_id, account_number, balance) "
        "VALUES (?, ?, ?)",
        (user_id, account_number, starting_balance),
    )
    db.commit()
    return account_number


def get_account_by_user_id(user_id):
    db = get_db()
    return db.execute(
        "SELECT * FROM accounts WHERE user_id = ?", (user_id,)
    ).fetchone()


def update_balance(user_id, new_balance):
    db = get_db()
    db.execute(
        "UPDATE accounts SET balance = ? WHERE user_id = ?",
        (new_balance, user_id),
    )
    db.commit()


# =========================
# TRANSACTIONS
# =========================

def create_transaction(user_id, tx_type, category, description, amount):
    db = get_db()
    cursor = db.execute(
        "INSERT INTO transactions (user_id, type, category, description, amount) "
        "VALUES (?, ?, ?, ?, ?)",
        (user_id, tx_type, category, description, amount),
    )
    db.commit()
    return cursor.lastrowid


def list_transactions(user_id, limit=20):
    db = get_db()
    return db.execute(
        "SELECT * FROM transactions WHERE user_id = ? "
        "ORDER BY created_at DESC, id DESC LIMIT ?",
        (user_id, limit),
    ).fetchall()


# =========================
# SESSIONS
# =========================

def create_session(session_id, user_id, ip_address, user_agent):
    db = get_db()
    db.execute(
        "INSERT INTO sessions (session_id, user_id, ip_address, user_agent) "
        "VALUES (?, ?, ?, ?)",
        (session_id, user_id, ip_address, user_agent),
    )
    db.commit()


def get_session(session_id):
    db = get_db()
    return db.execute(
        "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
    ).fetchone()


def touch_session(session_id):
    db = get_db()
    db.execute(
        "UPDATE sessions SET last_activity = datetime('now') "
        "WHERE session_id = ?",
        (session_id,),
    )
    db.commit()


def end_session(session_id, status="logged_out"):
    db = get_db()
    db.execute(
        "UPDATE sessions SET session_status = ?, logout_time = datetime('now') "
        "WHERE session_id = ?",
        (status, session_id),
    )
    db.commit()


# =========================
# ACTIVITY LOGS
# =========================

def log_activity(session_id=None, user_id=None, event_type=None, endpoint=None,
                  request_method=None, ip_address=None, user_agent=None, details=None):
    db = get_db()
    db.execute(
        "INSERT INTO activity_logs "
        "(session_id, user_id, event_type, endpoint, request_method, ip_address, user_agent, details) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (session_id, user_id, event_type, endpoint, request_method, ip_address, user_agent, details),
    )
    db.commit()


# =========================
# SECURITY EVENTS
# =========================

def log_security_event(session_id, user_id, event_type, endpoint=None,
                        request_method=None, ip_address=None, user_agent=None):
    db = get_db()
    cursor = db.execute(
        "INSERT INTO security_events "
        "(session_id, user_id, event_type, endpoint, request_method, ip_address, user_agent) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (session_id, user_id, event_type, endpoint, request_method, ip_address, user_agent),
    )
    db.commit()
    return cursor.lastrowid


# Alias matching the exact name activity_logger.py calls.
def record_security_event(session_id, user_id, event_type, endpoint=None,
                           request_method=None, ip_address=None, user_agent=None):
    return log_security_event(
        session_id, user_id, event_type,
        endpoint=endpoint, request_method=request_method,
        ip_address=ip_address, user_agent=user_agent,
    )


def get_security_events(since_id=0, limit=100, mark_delivered=True):
    db = get_db()
    rows = db.execute(
        "SELECT * FROM security_events WHERE id > ? ORDER BY id ASC LIMIT ?",
        (since_id, limit),
    ).fetchall()

    if mark_delivered and rows:
        ids = [r["id"] for r in rows]
        placeholders = ",".join("?" for _ in ids)
        db.execute(
            f"UPDATE security_events SET delivered = 1 WHERE id IN ({placeholders})",
            ids,
        )
        db.commit()

    return rows