"""
NovaBank Demo Backend - Transaction routes
"""

from flask import Blueprint, request, jsonify, g

import models as models
from services.session_service import require_auth
from services.activity_logger import log_transaction

transactions_bp = Blueprint("transactions", __name__, url_prefix="/api/transactions")

ALLOWED_TYPES = {"credit", "debit"}


@transactions_bp.get("")
@require_auth
def list_transactions():
    limit = request.args.get("limit", default=20, type=int)
    limit = max(1, min(limit, 100))

    rows = models.list_transactions(g.user_id, limit=limit)
    transactions = [
        {
            "id": r["id"],
            "type": r["type"],
            "category": r["category"],
            "description": r["description"],
            "amount": r["amount"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]
    return jsonify({"transactions": transactions})


@transactions_bp.post("")
@require_auth
def create_transaction():
    """Create a demo transaction (e.g. from a future 'Send Money' / 'Add Money' form)
    and update the account balance accordingly."""
    data = request.get_json(silent=True) or {}

    tx_type = (data.get("type") or "").strip().lower()
    category = (data.get("category") or "General").strip()
    description = (data.get("description") or "").strip()
    amount = data.get("amount")

    if tx_type not in ALLOWED_TYPES:
        return jsonify({"error": "Type must be 'credit' or 'debit'."}), 400

    if not description:
        return jsonify({"error": "Description is required."}), 400

    try:
        amount = float(amount)
    except (TypeError, ValueError):
        return jsonify({"error": "Amount must be a number."}), 400

    if amount <= 0:
        return jsonify({"error": "Amount must be greater than zero."}), 400

    account = models.get_account_by_user_id(g.user_id)
    if not account:
        return jsonify({"error": "No account found for this user."}), 404

    if tx_type == "debit" and amount > account["balance"]:
        return jsonify({"error": "Insufficient balance."}), 400

    new_balance = account["balance"] + amount if tx_type == "credit" else account["balance"] - amount
    models.update_balance(g.user_id, new_balance)

    tx_id = models.create_transaction(g.user_id, tx_type, category, description, amount)

    log_transaction(g.session_id, g.user_id, tx_id, tx_type, amount)

    return jsonify({
        "message": "Transaction recorded.",
        "transaction": {
            "id": tx_id,
            "type": tx_type,
            "category": category,
            "description": description,
            "amount": amount,
        },
        "new_balance": new_balance,
    }), 201