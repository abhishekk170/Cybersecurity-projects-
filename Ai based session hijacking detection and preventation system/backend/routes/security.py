"""
NovaBank Demo Backend - Security integration routes

These endpoints are the seam between this bank backend and the separate
pieces you'll build later (Monitoring Agent, AI anomaly detection,
Security Console). This backend never scores risk - it only records
facts and lets a trusted caller invalidate a session.

NOTE ON AUTH FOR THIS BLUEPRINT:
In a real deployment these two endpoints should be called only by your
Monitoring Agent / Security Console backend-to-backend, protected by e.g.
a shared service token or mTLS/network isolation - not by end-user
sessions. For this local demo, no extra auth is enforced here so you can
test with curl/Postman immediately; add a token check before this touches
anything beyond localhost.
"""

from flask import Blueprint, request, jsonify

import models as models
from services.activity_logger import log_session_invalidated

security_bp = Blueprint("security", __name__, url_prefix="/api/security")


@security_bp.get("/events")
def get_events():
    """
    Polling interface for the Monitoring Agent.
    Query params:
      since_id (int, default 0): only return events with id > since_id
      limit    (int, default 100, max 500)
      mark_delivered (bool, default true): mark returned events as delivered
    """
    since_id = request.args.get("since_id", default=0, type=int)
    limit = request.args.get("limit", default=100, type=int)
    limit = max(1, min(limit, 500))
    mark_delivered = request.args.get("mark_delivered", default="true").lower() != "false"

    rows = models.get_security_events(since_id=since_id, limit=limit, mark_delivered=mark_delivered)

    events = [
        {
            "id": r["id"],
            "session_id": r["session_id"],
            "user_id": r["user_id"],
            "timestamp": r["created_at"],
            "ip": r["ip_address"],
            "user_agent": r["user_agent"],
            "endpoint": r["endpoint"],
            "request_method": r["request_method"],
            "event_type": r["event_type"],
        }
        for r in rows
    ]

    last_id = events[-1]["id"] if events else since_id

    return jsonify({"events": events, "last_id": last_id})


@security_bp.post("/sessions/<session_id>/invalidate")
def invalidate_session(session_id):
    """
    Lets a future Security Console forcibly kill a specific session.
    Any further authenticated request using this session_id cookie will
    now get 401 (see services/session_service.require_auth).
    """
    session_row = models.get_session(session_id)

    if not session_row:
        return jsonify({"error": "Session not found."}), 404

    if session_row["session_status"] != "active":
        return jsonify({
            "message": f"Session already {session_row['session_status']}.",
            "session_id": session_id,
        }), 200

    models.end_session(session_id, status="invalidated")
    log_session_invalidated(session_id, session_row["user_id"])

    return jsonify({
        "message": "Session invalidated successfully.",
        "session_id": session_id,
    })