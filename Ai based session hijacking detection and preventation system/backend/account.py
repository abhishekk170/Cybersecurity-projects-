"""
NovaBank Demo Backend - Account routes
"""

from flask import Blueprint, jsonify, g

import backend.models as models
from services_session_ import require_auth

account_bp = Blueprint("account", __name__, url_prefix="/api/account")


@account_bp.get("")
@require_auth
def get_account():
    user = models.get_user_by_id(g.user_id)
    account = models.get_account_by_user_id(g.user_id)

    if not account:
        return jsonify({"error": "No account found for this user."}), 404

    return jsonify({
        "account_holder": user["name"],
        "username": user["username"],
        "account_number": account["account_number"],
        "balance": account["balance"],
    })