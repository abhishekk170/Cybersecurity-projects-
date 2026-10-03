"""
Monitoring Agent - Configuration

Everything the agent needs to know: where the bank API lives, how often
to poll it, and the simple thresholds used to derive features.
"""

import os

# Where the NovaBank backend is running.
# On the "friend's laptop" during the real demo, this stays 127.0.0.1.
# On YOUR laptop (the tester), set this to the friend's IP, e.g.:
#   set BANK_API_URL=http://192.168.1.23:5000   (Windows)
#   export BANK_API_URL=http://192.168.1.23:5000 (Mac/Linux)
BANK_API_URL = os.environ.get("BANK_API_URL", "http://127.0.0.1:5000")

# How often (seconds) the agent asks the bank for new events.
POLL_INTERVAL_SECONDS = 2

# If a session/IP has been silent this long, we consider it "finished"
# and write one summary row to session_dataset.csv.
SESSION_IDLE_SECONDS = 15

# Where raw + processed data get written.
RAW_LOG_PATH = os.path.join(os.path.dirname(__file__), "dataset", "raw_logs.csv")
DATASET_PATH = os.path.join(os.path.dirname(__file__), "dataset", "session_dataset.csv")

# A session is flagged "unusual_page_access" if it touches MORE than
# this many distinct endpoints. Simple, explainable rule.
# NOTE: this demo bank only has 2 endpoints protected by @require_auth
# (/api/account, /api/transactions), so distinct-endpoint count alone
# can never exceed 2. We combine it with a transaction-count rule below,
# which is more realistic for a bank anyway: many money-movements in one
# session is a stronger red flag than "visited an extra page".
UNUSUAL_ENDPOINT_THRESHOLD = 2

# A session is also flagged unusual if it performs MORE than this many
# transactions (deposits/withdrawals) in one sitting.
UNUSUAL_TRANSACTION_THRESHOLD = 2