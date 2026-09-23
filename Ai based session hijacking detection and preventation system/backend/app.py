"""
NovaBank Demo Backend - Entry point

Run with:  python app.py
Serves at: http://127.0.0.1:5000
"""

from flask import Flask
from flask_cors import CORS

from config import Config
from database import init_db, close_db

from routes.auth import auth_bp
from routes.account import account_bp
from routes.transactions import transactions_bp
from routes.security import security_bp


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Allow the frontend origin to call this API WITH credentials (cookies).
    # Update FRONTEND_ORIGIN in config.py / env if you serve the frontend
    # from a different host/port (e.g. Live Server on 5500, or file://).
    CORS(
        app,
        supports_credentials=True,
        origins=[app.config["FRONTEND_ORIGIN"]],
    )

    app.teardown_appcontext(close_db)

    app.register_blueprint(auth_bp)
    app.register_blueprint(account_bp)
    app.register_blueprint(transactions_bp)
    app.register_blueprint(security_bp)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "service": "novabank-backend"}

    return app


app = create_app()

if __name__ == "__main__":
    init_db(app)
    app.run(host="127.0.0.1", port=5000, debug=True)